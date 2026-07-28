package com.bulwark.tv

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.bulwark.deviceapi.AppPosture
import com.bulwark.deviceapi.AppRecord
import com.bulwark.deviceapi.CommandExecutor
import com.bulwark.deviceapi.DeviceApiClient
import com.bulwark.deviceapi.DeviceCrypto
import com.bulwark.deviceapi.DeviceIdentity

/**
 * Enrollment + one agent tick (heartbeat, poll/verify/execute, inventory sync).
 */
class DeviceAgentService(
    private val context: Context,
    private val store: IdentityStore = IdentityStore(context),
    private val packageManager: PackageManager = context.packageManager,
    private val blocklistStore: BlocklistStore = BlocklistStore(context),
) {
    private val seenNonces = linkedSetOf<String>()

    fun enroll(code: String, baseUrl: String, deviceName: String = Build.MODEL): Result<DeviceIdentity> {
        return runCatching {
            val normalized = normalizePairingCode(code)
            require(normalized.matches(Regex("^[A-F0-9]{4}-[A-F0-9]{4}$"))) {
                "Invalid pairing code"
            }
            val client = DeviceApiClient(baseUrl)
            val keys = DeviceCrypto.generateDeviceKeyPair()
            val enrolled = client.enroll(
                code = normalized,
                name = deviceName.ifBlank { "Android TV" },
                publicKeyPem = keys.publicKeyPem,
                os = "Android TV ${Build.VERSION.RELEASE} (${Build.MANUFACTURER} ${Build.MODEL})",
            )
            val serverKey = client.getServerKey()
            val identity = DeviceIdentity(
                deviceId = enrolled.deviceId,
                name = deviceName.ifBlank { "Android TV" },
                publicKeyPem = keys.publicKeyPem,
                privateKeyPem = keys.privateKeyPem,
                serverPublicKeyPem = serverKey,
                baseUrl = baseUrl.trimEnd('/'),
                enrolledAt = enrolled.enrolledAt,
            )
            store.save(identity)
            identity
        }
    }

    fun unenroll() {
        store.clear()
        seenNonces.clear()
    }

    fun tick(): Result<TickReport> {
        val identity = store.load() ?: return Result.failure(IllegalStateException("not enrolled"))
        return runCatching {
            val client = DeviceApiClient(identity.baseUrl)
            client.heartbeat(identity)
            // Pull remote policy every tick (versioned); apply before executing commands.
            runCatching {
                val policy = client.getPolicy(identity)
                blocklistStore.applyPolicy(policy)
                if (policy.dnsGuardRequired || policy.isolated) {
                    // Best-effort: UI/user may still need to approve VPN permission.
                    if (!DnsGuardVpnService.isRunning) {
                        DnsGuardVpnService.start(context)
                    }
                }
            }
            val commands = client.pollCommands(identity)
            var processed = 0
            var rejected = 0
            var lastType: String? = null
            for (cmd in commands) {
                val (ok, result) = CommandExecutor.process(
                    serverPublicKeyPem = identity.serverPublicKeyPem,
                    deviceId = identity.deviceId,
                    cmd = cmd,
                    seenNonces = seenNonces,
                    execute = ::executeCommand,
                )
                if (ok) {
                    if (cmd.type == "REQUEST_INVENTORY") {
                        val inventory = collectInventory()
                        client.submitInventory(identity, inventory)
                        @Suppress("UNCHECKED_CAST")
                        val findings = inventory["_findings"] as? List<Map<String, Any?>> ?: emptyList()
                        if (findings.isNotEmpty()) client.submitFindings(identity, findings)
                    }
                    if (cmd.type == "RUN_HEALTH_ASSESSMENT") {
                        @Suppress("UNCHECKED_CAST")
                        val findings = result["findings"] as? List<Map<String, Any?>>
                        if (!findings.isNullOrEmpty()) client.submitFindings(identity, findings)
                    }
                    processed++
                    lastType = cmd.type
                } else {
                    rejected++
                }
                client.postCommandResult(identity, cmd.commandId, result)
            }
            if (commands.isEmpty()) {
                val inventory = collectInventory()
                client.submitInventory(identity, inventory)
                @Suppress("UNCHECKED_CAST")
                val findings = inventory["_findings"] as? List<Map<String, Any?>> ?: emptyList()
                if (findings.isNotEmpty()) {
                    client.submitFindings(identity, findings)
                    for (f in findings.take(20)) {
                        AgentEvents.finding(
                            f["subjectName"] as? String ?: "unknown",
                            f["reason"] as? String ?: "",
                            f["level"] as? String ?: "unknown",
                        )
                    }
                }
            }
            // Flush queued DNS / isolation / finding events to the control plane.
            val drained = AgentEvents.batcher.drain()
            if (drained.isNotEmpty()) {
                client.submitNetworkEvents(identity, drained.map { it.toMap() })
            }
            TickReport(processed = processed, rejected = rejected, lastType = lastType)
        }
    }

    fun executeCommand(type: String, parameters: Map<String, Any?>): Map<String, Any?> {
        return when (type) {
            "REQUEST_INVENTORY" -> {
                val inventory = collectInventory()
                mapOf(
                    "ok" to true,
                    "type" to type,
                    "count" to inventory["count"],
                    "sideloadedCount" to inventory["sideloadedCount"],
                    "findingCount" to (inventory["_findings"] as? List<*>)?.size,
                )
            }
            "RUN_HEALTH_ASSESSMENT" -> AppPosture.healthAssessment(collectAppRecords())
            "BLOCK_DOMAIN" -> {
                val domain = parameters["domain"] as? String
                    ?: parameters["host"] as? String
                    ?: return mapOf("ok" to false, "error" to "domain required", "type" to type)
                val added = blocklistStore.add(domain)
                mapOf(
                    "ok" to true,
                    "type" to type,
                    "applied" to added,
                    "domain" to domain,
                    "blocklistSize" to blocklistStore.size(),
                    "dnsGuardRunning" to DnsGuardVpnService.isRunning,
                )
            }
            "UPDATE_THREAT_FEEDS" -> {
                @Suppress("UNCHECKED_CAST")
                val domains = (parameters["domains"] as? List<*>)?.mapNotNull { it as? String }
                    ?: BlocklistStore.STARTER
                val added = if (parameters["replace"] == true) {
                    blocklistStore.replaceAll(domains)
                    domains.size
                } else {
                    blocklistStore.addAll(domains)
                }
                mapOf(
                    "ok" to true,
                    "type" to type,
                    "updated" to true,
                    "added" to added,
                    "blocklistSize" to blocklistStore.size(),
                )
            }
            "ISOLATE_DEVICE" -> {
                val policy = (blocklistStore.loadPolicy() ?: com.bulwark.deviceapi.DevicePolicy()).copy(
                    isolated = true,
                    dnsGuardRequired = true,
                    version = (blocklistStore.loadPolicy()?.version ?: 0) + 1,
                )
                blocklistStore.applyPolicy(policy)
                if (!DnsGuardVpnService.isRunning) DnsGuardVpnService.start(context)
                AgentEvents.isolationChanged(true)
                mapOf(
                    "ok" to true,
                    "type" to type,
                    "applied" to true,
                    "isolated" to true,
                    "mode" to blocklistStore.mode().name,
                    "allowlistSize" to blocklistStore.size(),
                    "reason" to (parameters["reason"] ?: "command"),
                )
            }
            "CLEAR_ISOLATION" -> {
                val prev = blocklistStore.loadPolicy()
                val policy = (prev ?: com.bulwark.deviceapi.DevicePolicy()).copy(
                    isolated = false,
                    version = (prev?.version ?: 0) + 1,
                )
                blocklistStore.applyPolicy(policy)
                if (policy.blockedDomains.isEmpty()) {
                    blocklistStore.replaceAll(BlocklistStore.STARTER)
                }
                AgentEvents.isolationChanged(false)
                mapOf(
                    "ok" to true,
                    "type" to type,
                    "applied" to true,
                    "isolated" to false,
                    "mode" to blocklistStore.mode().name,
                )
            }
            "APPLY_POLICY" -> {
                val identity = store.load()
                if (identity == null) {
                    mapOf("ok" to false, "error" to "not enrolled", "type" to type)
                } else {
                    val policy = DeviceApiClient(identity.baseUrl).getPolicy(identity)
                    blocklistStore.applyPolicy(policy)
                    if (policy.dnsGuardRequired || policy.isolated) {
                        if (!DnsGuardVpnService.isRunning) DnsGuardVpnService.start(context)
                    }
                    mapOf(
                        "ok" to true,
                        "type" to type,
                        "applied" to true,
                        "version" to policy.version,
                        "isolated" to policy.isolated,
                        "mode" to blocklistStore.mode().name,
                    )
                }
            }
            "RUN_MALWARE_SCAN", "RUN_VULNERABILITY_SCAN" -> {
                val findings = AppPosture.analyze(collectAppRecords())
                mapOf(
                    "ok" to true,
                    "type" to type,
                    "threatsFound" to findings.count { it.level != "potential_match" },
                    "findings" to findings.size,
                    "details" to findings.take(25).map { it.toMap() },
                )
            }
            else -> CommandExecutor.defaultExecute(type, parameters)
        }
    }

    fun collectAppRecords(): List<AppRecord> {
        val packages = packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
        return packages.map { PackageInspector.inspect(packageManager, it) }
    }

    fun collectInventory(): Map<String, Any?> {
        val records = collectAppRecords()
        val apps = records.map { PackageInspector.toInventoryMap(it) }
        val findings = AppPosture.analyze(records).map { it.toMap() }
        val health = AppPosture.healthAssessment(records)
        return mapOf(
            "apps" to apps,
            "count" to apps.size,
            "sideloadedCount" to records.count { it.sideloaded && !it.system },
            "device" to mapOf(
                "manufacturer" to Build.MANUFACTURER,
                "model" to Build.MODEL,
                "release" to Build.VERSION.RELEASE,
                "sdk" to Build.VERSION.SDK_INT,
            ),
            "postureScore" to health["score"],
            "dnsGuard" to DnsGuardVpnService.trafficSummary() + mapOf(
                "blocklistSize" to blocklistStore.size(),
                "mode" to blocklistStore.mode().name,
                "isolated" to blocklistStore.isIsolated(),
                "policyVersion" to blocklistStore.loadPolicy()?.version,
            ),
            "_findings" to findings,
        )
    }

    companion object {
        fun normalizePairingCode(raw: String): String {
            val cleaned = raw.trim().uppercase().replace(Regex("[^A-F0-9]"), "")
            if (cleaned.length == 8) return "${cleaned.substring(0, 4)}-${cleaned.substring(4)}"
            return ""
        }
    }
}

data class TickReport(
    val processed: Int,
    val rejected: Int,
    val lastType: String?,
)
