package com.bulwark.tv

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Environment
import android.os.Handler
import android.os.Looper
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import com.bulwark.deviceapi.AppPosture
import com.bulwark.deviceapi.AppRecord
import com.bulwark.deviceapi.CommandExecutor
import com.bulwark.deviceapi.DeviceApiClient
import com.bulwark.deviceapi.DeviceCrypto
import com.bulwark.deviceapi.DeviceIdentity
import com.bulwark.deviceapi.DnsGuardEnforcement
import com.bulwark.deviceapi.FileQuarantine
import java.io.File

/**
 * Enrollment + one agent tick (heartbeat, poll/verify/execute, inventory sync).
 */
class DeviceAgentService(
    private val context: Context,
    private val store: IdentityStore = IdentityStore(context),
    private val packageManager: PackageManager = context.packageManager,
    private val blocklistStore: BlocklistStore = BlocklistStore(context),
    private val vpnConsent: VpnConsentStore = VpnConsentStore(context),
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
                if (DnsGuardEnforcement.needsDnsGuard(policy.isolated, policy.dnsGuardRequired)) {
                    ensureDnsGuard()
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
                val guard = ensureDnsGuard()
                mapOf(
                    "ok" to true,
                    "stub" to false,
                    "type" to type,
                    "applied" to (added && guard.running),
                    "domain" to domain,
                    "blocklistSize" to blocklistStore.size(),
                    "dnsGuardRunning" to guard.running,
                    "vpnConsentPending" to guard.needsConsent,
                    "reason" to when {
                        guard.running -> null
                        guard.needsConsent -> DnsGuardEnforcement.REASON_VPN_PERMISSION
                        else -> DnsGuardEnforcement.REASON_VPN_ESTABLISH
                    },
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
                val guard = ensureDnsGuard()
                AgentEvents.isolationChanged(true)
                DnsGuardEnforcement.enforcementResult(
                    type = type,
                    vpnRunning = guard.running,
                    needsConsent = guard.needsConsent,
                    extras = mapOf(
                        "isolated" to true,
                        "mode" to blocklistStore.mode().name,
                        "allowlistSize" to blocklistStore.size(),
                        "isolateReason" to (parameters["reason"] ?: "command"),
                    ),
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
                // Clearing isolation alone must not drop pending if dnsGuardRequired remains.
                val vpnRunning = DnsGuardVpnService.isRunning
                val clearPending = DnsGuardEnforcement.shouldClearVpnPending(
                    isolated = false,
                    dnsGuardRequired = policy.dnsGuardRequired,
                    vpnRunning = vpnRunning,
                )
                if (clearPending) {
                    vpnConsent.clearPending()
                } else if (!vpnRunning) {
                    vpnConsent.markNeedsConsent()
                }
                mapOf(
                    "ok" to true,
                    "stub" to false,
                    "type" to type,
                    "applied" to true,
                    "isolated" to false,
                    "mode" to blocklistStore.mode().name,
                    "dnsGuardRequired" to policy.dnsGuardRequired,
                    "dnsGuardRunning" to vpnRunning,
                    "vpnConsentPending" to (!clearPending && !vpnRunning),
                )
            }
            "APPLY_POLICY" -> {
                val identity = store.load()
                if (identity == null) {
                    mapOf("ok" to false, "error" to "not enrolled", "type" to type)
                } else {
                    val policy = DeviceApiClient(identity.baseUrl).getPolicy(identity)
                    blocklistStore.applyPolicy(policy)
                    val needs = DnsGuardEnforcement.needsDnsGuard(policy.isolated, policy.dnsGuardRequired)
                    if (!needs) {
                        vpnConsent.clearPending()
                        mapOf(
                            "ok" to true,
                            "stub" to false,
                            "type" to type,
                            "applied" to true,
                            "version" to policy.version,
                            "isolated" to policy.isolated,
                            "mode" to blocklistStore.mode().name,
                            "dnsGuardRequired" to policy.dnsGuardRequired,
                            "dnsGuardRunning" to DnsGuardVpnService.isRunning,
                            "vpnConsentPending" to false,
                        )
                    } else {
                        val guard = ensureDnsGuard()
                        DnsGuardEnforcement.enforcementResult(
                            type = type,
                            vpnRunning = guard.running,
                            needsConsent = guard.needsConsent,
                            extras = mapOf(
                                "version" to policy.version,
                                "isolated" to policy.isolated,
                                "mode" to blocklistStore.mode().name,
                                "dnsGuardRequired" to policy.dnsGuardRequired,
                            ),
                        )
                    }
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
            "QUARANTINE_FILE" -> {
                val paths = FileQuarantine.parsePaths(parameters)
                val allowRoots = buildList {
                    add(context.filesDir)
                    add(context.cacheDir)
                    context.getExternalFilesDir(null)?.let { add(it) }
                    val downloads = Environment.getExternalStoragePublicDirectory(
                        Environment.DIRECTORY_DOWNLOADS,
                    )
                    if (downloads.exists() && downloads.canRead()) add(downloads)
                }
                val quarantineDir = File(context.filesDir, "quarantine")
                FileQuarantine.quarantineFiles(paths, allowRoots, quarantineDir) + mapOf(
                    "parameters" to parameters,
                )
            }
            "RESTART_AGENT" -> {
                // Return immediately, then reschedule WorkManager after the result is posted.
                Handler(Looper.getMainLooper()).postDelayed({
                    val appCtx = context.applicationContext
                    val wm = WorkManager.getInstance(appCtx)
                    wm.cancelUniqueWork(AgentWorker.UNIQUE_NAME)
                    (appCtx as? BulwarkApp)?.scheduleAgentWork()
                    val oneShot = OneTimeWorkRequestBuilder<AgentWorker>().build()
                    wm.enqueueUniqueWork(
                        "bulwark-device-agent-now",
                        ExistingWorkPolicy.REPLACE,
                        oneShot,
                    )
                }, 1500L)
                mapOf(
                    "ok" to true,
                    "stub" to false,
                    "type" to type,
                    "scheduled" to true,
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
                "vpnConsentPending" to vpnConsent.isPending(),
                "vpnConsentGranted" to vpnConsent.isConsentGranted(),
            ),
            "_findings" to findings,
        )
    }

    /**
     * Start DNS Guard when possible. If VpnService.prepare() is required,
     * mark consent pending and emit a parent-visible event — never claim success.
     */
    private fun ensureDnsGuard(): DnsGuardVpnService.TryStartResult {
        val result = DnsGuardVpnService.tryStart(context)
        if (result.running) {
            vpnConsent.setConsentGranted(true)
            vpnConsent.clearPending()
        } else if (result.needsConsent) {
            vpnConsent.markNeedsConsent()
            AgentEvents.dnsGuardPending()
        } else {
            // Permission already granted but establish failed / still starting.
            vpnConsent.markNeedsConsent()
            AgentEvents.dnsGuardPending("DNS Guard failed to establish TUN")
        }
        return result
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
