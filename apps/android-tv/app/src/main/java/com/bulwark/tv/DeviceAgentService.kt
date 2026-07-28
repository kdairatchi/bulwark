package com.bulwark.tv

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import com.bulwark.deviceapi.CommandExecutor
import com.bulwark.deviceapi.DeviceApiClient
import com.bulwark.deviceapi.DeviceCrypto
import com.bulwark.deviceapi.DeviceIdentity

/**
 * Enrollment + one agent tick (heartbeat, poll/verify/execute, inventory sync).
 */
class DeviceAgentService(
    private val store: IdentityStore,
    private val packageManager: PackageManager,
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
                )
                if (ok) {
                    if (cmd.type == "REQUEST_INVENTORY") {
                        client.submitInventory(identity, collectInventory())
                    }
                    processed++
                    lastType = cmd.type
                } else {
                    rejected++
                }
                client.postCommandResult(identity, cmd.commandId, result)
            }
            // Periodic inventory even without a command.
            if (commands.isEmpty()) {
                client.submitInventory(identity, collectInventory())
            }
            TickReport(processed = processed, rejected = rejected, lastType = lastType)
        }
    }

    fun collectInventory(): Map<String, Any?> {
        val apps = mutableListOf<Map<String, Any?>>()
        val packages = packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
        for (app in packages) {
            val installer = installerFor(app.packageName)
            val sideloaded = isSideloaded(installer, app)
            apps += mapOf(
                "packageName" to app.packageName,
                "label" to (app.loadLabel(packageManager)?.toString() ?: app.packageName),
                "installer" to (installer ?: "unknown"),
                "sideloaded" to sideloaded,
                "system" to ((app.flags and ApplicationInfo.FLAG_SYSTEM) != 0),
            )
        }
        val findings = apps.filter { it["sideloaded"] == true }.map {
            mapOf(
                "level" to "likely_affected",
                "subjectName" to (it["packageName"] as String),
                "reason" to "Sideloaded app (installer=${it["installer"]})",
            )
        }
        return mapOf(
            "apps" to apps,
            "count" to apps.size,
            "sideloadedCount" to findings.size,
            "device" to mapOf(
                "manufacturer" to Build.MANUFACTURER,
                "model" to Build.MODEL,
                "release" to Build.VERSION.RELEASE,
                "sdk" to Build.VERSION.SDK_INT,
            ),
            // Findings are submitted separately by the worker when present.
            "_findings" to findings,
        )
    }

    private fun installerFor(packageName: String): String? {
        return try {
            if (Build.VERSION.SDK_INT >= 30) {
                packageManager.getInstallSourceInfo(packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                packageManager.getInstallerPackageName(packageName)
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun isSideloaded(installer: String?, app: ApplicationInfo): Boolean {
        if ((app.flags and ApplicationInfo.FLAG_SYSTEM) != 0) return false
        val trusted = setOf(
            "com.android.vending",
            "com.google.android.packageinstaller",
            "com.amazon.venezia",
            "com.sec.android.app.samsungapps",
        )
        return installer == null || installer !in trusted
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
