package com.bulwark.tv

import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import com.bulwark.deviceapi.AppRecord
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest

/**
 * Collects APK SHA-256, signing-cert SHA-256, and requested permissions for posture.
 */
object PackageInspector {
    fun inspect(packageManager: PackageManager, app: ApplicationInfo): AppRecord {
        val installer = installerFor(packageManager, app.packageName)
        val sideloaded = isSideloaded(installer, app)
        val pkgInfo = packageInfo(packageManager, app.packageName)
        val permissions = pkgInfo?.requestedPermissions?.toList() ?: emptyList()
        val apkPath = app.sourceDir
        return AppRecord(
            packageName = app.packageName,
            label = app.loadLabel(packageManager).toString(),
            installer = installer,
            sideloaded = sideloaded,
            system = (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
            apkSha256 = apkPath?.let { sha256File(it) },
            certSha256 = pkgInfo?.let { certSha256(it) },
            permissions = permissions,
        )
    }

    fun toInventoryMap(record: AppRecord): Map<String, Any?> = mapOf(
        "packageName" to record.packageName,
        "label" to record.label,
        "installer" to (record.installer ?: "unknown"),
        "sideloaded" to record.sideloaded,
        "system" to record.system,
        "apkSha256" to record.apkSha256,
        "certSha256" to record.certSha256,
        "permissions" to record.permissions,
        "dangerousPermissions" to com.bulwark.deviceapi.AppPosture.dangerousPermissions(record.permissions),
        "permissionRiskScore" to com.bulwark.deviceapi.AppPosture.permissionRiskScore(record.permissions),
    )

    private fun packageInfo(pm: PackageManager, packageName: String): PackageInfo? {
        return try {
            if (Build.VERSION.SDK_INT >= 28) {
                pm.getPackageInfo(
                    packageName,
                    PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES,
                )
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(
                    packageName,
                    PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNATURES,
                )
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun certSha256(info: PackageInfo): String? {
        return try {
            val bytes: ByteArray? = if (Build.VERSION.SDK_INT >= 28) {
                val signers = info.signingInfo?.apkContentsSigners
                signers?.firstOrNull()?.toByteArray()
            } else {
                @Suppress("DEPRECATION")
                info.signatures?.firstOrNull()?.toByteArray()
            }
            bytes?.let { sha256Bytes(it) }
        } catch (_: Exception) {
            null
        }
    }

    private fun sha256File(path: String): String? {
        return try {
            val md = MessageDigest.getInstance("SHA-256")
            FileInputStream(File(path)).use { input ->
                val buf = ByteArray(64 * 1024)
                while (true) {
                    val n = input.read(buf)
                    if (n <= 0) break
                    md.update(buf, 0, n)
                }
            }
            md.digest().joinToString("") { "%02x".format(it) }
        } catch (_: Exception) {
            null
        }
    }

    private fun sha256Bytes(data: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(data).joinToString("") { "%02x".format(it) }
    }

    private fun installerFor(pm: PackageManager, packageName: String): String? {
        return try {
            if (Build.VERSION.SDK_INT >= 30) {
                pm.getInstallSourceInfo(packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(packageName)
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
}
