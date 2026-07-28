package com.bulwark.deviceapi

import java.io.File

/**
 * Shared JVM command execution used by the agent demo and as a fallback when the
 * Android TV app does not override a type. Prefer [DeviceAgentService] on-device —
 * this path is fully live for inventory/scans/feeds/quarantine/DNS policy state,
 * but isolate/DNS Guard cannot raise a real VpnService without Android Context.
 */
object CommandExecutor {
    /** In-memory DNS/policy state for the JVM demo (no Android Context). */
    val demoBlocklist: DnsBlocklist = DnsBlocklist(
        initial = listOf("malware.example", "tracker.evil.test"),
    )
    @Volatile
    var demoPolicy: DevicePolicy = DevicePolicy()
    @Volatile
    private var restartScheduled: Boolean = false

    /** Sample apps for JVM demos / unit tests (sideload + clean). */
    fun demoApps(): List<AppRecord> = listOf(
        AppRecord(
            packageName = "com.example.clean",
            label = "Clean App",
            installer = "com.android.vending",
            sideloaded = false,
            system = false,
            versionName = "1.0.0",
            targetSdk = 34,
        ),
        AppRecord(
            packageName = "com.example.sketchy",
            label = "Sketchy Sideload",
            installer = null,
            sideloaded = true,
            system = false,
            debuggable = true,
            allowBackup = true,
            versionName = "0.1",
            targetSdk = 28,
            permissions = listOf(
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.READ_EXTERNAL_STORAGE",
            ),
            exportedActivities = 2,
            exportedServices = 1,
        ),
    )

    /** Reset demo state between unit tests. */
    fun resetDemoState() {
        demoBlocklist.replaceAll(listOf("malware.example", "tracker.evil.test"))
        demoBlocklist.mode = DnsFilterMode.BLOCKLIST
        demoPolicy = DevicePolicy()
        restartScheduled = false
    }

    fun defaultExecute(type: String, parameters: Map<String, Any?>): Map<String, Any?> {
        return when (type) {
            "REQUEST_INVENTORY" -> {
                val apps = demoApps()
                val findings = AppPosture.analyze(apps)
                mapOf(
                    "ok" to true,
                    "stub" to false,
                    "type" to type,
                    "count" to apps.size,
                    "sideloadedCount" to apps.count { it.sideloaded && !it.system },
                    "findingCount" to findings.size,
                    "apps" to apps.map { app ->
                        mapOf(
                            "packageName" to app.packageName,
                            "label" to app.label,
                            "versionName" to app.versionName,
                            "sideloaded" to app.sideloaded,
                        )
                    },
                    "_findings" to findings.map { it.toMap() },
                )
            }
            "RUN_HEALTH_ASSESSMENT" -> {
                AppPosture.healthAssessment(demoApps()) + mapOf("stub" to false)
            }
            "RUN_MALWARE_SCAN", "RUN_VULNERABILITY_SCAN" -> {
                val findings = AppPosture.analyze(demoApps())
                mapOf(
                    "ok" to true,
                    "stub" to false,
                    "type" to type,
                    "threatsFound" to findings.count { it.level != "potential_match" },
                    "findings" to findings.size,
                    "details" to findings.take(25).map { it.toMap() },
                )
            }
            "UPDATE_THREAT_FEEDS" -> {
                @Suppress("UNCHECKED_CAST")
                val domains = (parameters["domains"] as? List<*>)?.mapNotNull { it as? String }
                    ?: listOf("malware.example", "tracker.evil.test")
                val added = if (parameters["replace"] == true) {
                    demoBlocklist.replaceAll(domains)
                    domains.size
                } else {
                    demoBlocklist.addAll(domains)
                }
                mapOf(
                    "ok" to true,
                    "stub" to false,
                    "type" to type,
                    "updated" to true,
                    "added" to added,
                    "blocklistSize" to demoBlocklist.size(),
                )
            }
            "BLOCK_DOMAIN" -> {
                val domain = parameters["domain"] as? String
                    ?: parameters["host"] as? String
                    ?: return mapOf("ok" to false, "error" to "domain required", "type" to type, "stub" to false)
                val added = demoBlocklist.add(domain)
                mapOf(
                    "ok" to true,
                    "stub" to false,
                    "type" to type,
                    "applied" to added,
                    "domain" to DnsBlocklist.normalize(domain),
                    "blocklistSize" to demoBlocklist.size(),
                    // JVM has no VpnService — DNS filter state is updated; TUN not up.
                    "dnsGuardRunning" to false,
                    "vpnConsentPending" to true,
                    "reason" to DnsGuardEnforcement.REASON_VPN_PERMISSION,
                )
            }
            "QUARANTINE_FILE" -> {
                val paths = FileQuarantine.parsePaths(parameters)
                val root = File(System.getProperty("java.io.tmpdir"), "bulwark-jvm-quarantine-root")
                root.mkdirs()
                val quarantineDir = File(root, "quarantine")
                FileQuarantine.quarantineFiles(paths, listOf(root), quarantineDir) + mapOf(
                    "parameters" to parameters,
                )
            }
            "ISOLATE_DEVICE" -> {
                demoPolicy = demoPolicy.copy(
                    isolated = true,
                    dnsGuardRequired = true,
                    version = demoPolicy.version + 1,
                )
                applyPolicyToBlocklist(demoPolicy, demoBlocklist)
                DnsGuardEnforcement.enforcementResult(
                    type = type,
                    vpnRunning = false,
                    needsConsent = true,
                    extras = mapOf(
                        "isolated" to true,
                        "mode" to demoBlocklist.mode.name,
                        "allowlistSize" to demoBlocklist.size(),
                    ),
                )
            }
            "CLEAR_ISOLATION" -> {
                demoPolicy = demoPolicy.copy(isolated = false, version = demoPolicy.version + 1)
                applyPolicyToBlocklist(demoPolicy, demoBlocklist)
                mapOf(
                    "ok" to true,
                    "stub" to false,
                    "type" to type,
                    "applied" to true,
                    "isolated" to false,
                    "mode" to demoBlocklist.mode.name,
                    "dnsGuardRunning" to false,
                    "vpnConsentPending" to false,
                )
            }
            "APPLY_POLICY" -> {
                val next = DevicePolicy.fromMap(parameters)
                demoPolicy = next
                applyPolicyToBlocklist(next, demoBlocklist)
                val needs = DnsGuardEnforcement.needsDnsGuard(next.isolated, next.dnsGuardRequired)
                if (!needs) {
                    mapOf(
                        "ok" to true,
                        "stub" to false,
                        "type" to type,
                        "applied" to true,
                        "version" to next.version,
                        "isolated" to next.isolated,
                        "mode" to demoBlocklist.mode.name,
                        "dnsGuardRequired" to next.dnsGuardRequired,
                        "dnsGuardRunning" to false,
                        "vpnConsentPending" to false,
                    )
                } else {
                    DnsGuardEnforcement.enforcementResult(
                        type = type,
                        vpnRunning = false,
                        needsConsent = true,
                        extras = mapOf(
                            "version" to next.version,
                            "isolated" to next.isolated,
                            "mode" to demoBlocklist.mode.name,
                            "dnsGuardRequired" to next.dnsGuardRequired,
                        ),
                    )
                }
            }
            "RESTART_AGENT" -> {
                // JVM demo cannot relaunch WorkManager; mark scheduled for parity.
                val already = restartScheduled
                restartScheduled = true
                mapOf(
                    "ok" to true,
                    "stub" to false,
                    "type" to type,
                    "scheduled" to true,
                    "reason" to if (already) "already_scheduled" else "jvm_demo_flag_only",
                )
            }
            else -> mapOf("ok" to false, "error" to "unhandled command type", "type" to type)
        }
    }

    fun process(
        serverPublicKeyPem: String,
        deviceId: String,
        cmd: CommandEnvelope,
        seenNonces: MutableSet<String>,
        nowMs: Long = System.currentTimeMillis(),
        execute: (String, Map<String, Any?>) -> Map<String, Any?> = ::defaultExecute,
    ): Pair<Boolean, Map<String, Any?>> {
        when (val v = verifyCommandEnvelope(serverPublicKeyPem, cmd, nowMs, deviceId, seenNonces)) {
            is CommandVerifyResult.Rejected ->
                return false to mapOf("ok" to false, "rejected" to true, "reason" to v.reason)
            CommandVerifyResult.Ok -> Unit
        }
        seenNonces += cmd.nonce
        val result = execute(cmd.type, cmd.parameters).toMutableMap()
        result["commandId"] = cmd.commandId
        result["type"] = cmd.type
        return true to result
    }
}
