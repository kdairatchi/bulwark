package com.bulwark.deviceapi

/**
 * TV/device posture helpers — pure functions over inventory records so they are
 * unit-testable on the JVM (Android PackageManager fills the records).
 */

/** Android dangerous permission names we flag on TV boxes. */
val DANGEROUS_PERMISSIONS = setOf(
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.PACKAGE_USAGE_STATS",
)

data class AppRecord(
    val packageName: String,
    val label: String = packageName,
    val installer: String? = null,
    val sideloaded: Boolean = false,
    val system: Boolean = false,
    val apkSha256: String? = null,
    val certSha256: String? = null,
    val permissions: List<String> = emptyList(),
    val versionName: String? = null,
    val versionCode: Long? = null,
    val targetSdk: Int? = null,
    val minSdk: Int? = null,
    val debuggable: Boolean = false,
    val allowBackup: Boolean = false,
    val exportedActivities: Int = 0,
    val exportedServices: Int = 0,
    val exportedReceivers: Int = 0,
    val exportedProviders: Int = 0,
)

data class Finding(
    val level: String,
    val subjectName: String,
    val reason: String,
    val category: String = "general",
) {
    fun toMap(): Map<String, Any?> = mapOf(
        "level" to level,
        "subjectName" to subjectName,
        "reason" to reason,
        "category" to category,
    )
}

object AppPosture {
    const val MODERN_TARGET_SDK = 33

    fun dangerousPermissions(permissions: List<String>): List<String> =
        permissions.filter { it in DANGEROUS_PERMISSIONS }.distinct().sorted()

    fun permissionRiskScore(permissions: List<String>): Int {
        val flagged = dangerousPermissions(permissions)
        return minOf(100, flagged.size * 15)
    }

    fun exportedComponentCount(app: AppRecord): Int =
        app.exportedActivities + app.exportedServices + app.exportedReceivers + app.exportedProviders

    fun analyze(apps: List<AppRecord>): List<Finding> {
        val findings = mutableListOf<Finding>()
        for (app in apps) {
            if (app.system) continue
            if (app.sideloaded) {
                findings += Finding(
                    level = "likely_affected",
                    subjectName = app.packageName,
                    reason = "Sideloaded app (installer=${app.installer ?: "unknown"})",
                    category = "sideload",
                )
            }
            val dangerous = dangerousPermissions(app.permissions)
            if (dangerous.isNotEmpty()) {
                val level = when {
                    dangerous.size >= 4 -> "confirmed_affected"
                    dangerous.size >= 2 -> "likely_affected"
                    else -> "potential_match"
                }
                findings += Finding(
                    level = level,
                    subjectName = app.packageName,
                    reason = "Dangerous permissions: ${dangerous.joinToString(", ")}",
                    category = "permissions",
                )
            }
            if (app.sideloaded && app.certSha256 == null) {
                findings += Finding(
                    level = "potential_match",
                    subjectName = app.packageName,
                    reason = "Sideloaded app without readable signing certificate",
                    category = "integrity",
                )
            }
            if (app.debuggable) {
                findings += Finding(
                    level = if (app.sideloaded) "confirmed_affected" else "likely_affected",
                    subjectName = app.packageName,
                    reason = "Application is debuggable (android:debuggable)",
                    category = "hardening",
                )
            }
            if (app.allowBackup && app.sideloaded) {
                findings += Finding(
                    level = "potential_match",
                    subjectName = app.packageName,
                    reason = "Sideloaded app allows backup (android:allowBackup)",
                    category = "hardening",
                )
            }
            val exported = exportedComponentCount(app)
            if (app.sideloaded && exported >= 3) {
                findings += Finding(
                    level = "likely_affected",
                    subjectName = app.packageName,
                    reason = "Sideloaded app exposes $exported exported components " +
                        "(activities=${app.exportedActivities}, services=${app.exportedServices}, " +
                        "receivers=${app.exportedReceivers}, providers=${app.exportedProviders})",
                    category = "attack_surface",
                )
            }
            val target = app.targetSdk
            if (target != null && target < MODERN_TARGET_SDK && (app.sideloaded || !app.system)) {
                findings += Finding(
                    level = if (target < 28) "likely_affected" else "potential_match",
                    subjectName = app.packageName,
                    reason = "Outdated targetSdk=$target (expected >= $MODERN_TARGET_SDK)",
                    category = "outdated",
                )
            }
        }
        return findings
    }

    fun healthAssessment(apps: List<AppRecord>): Map<String, Any?> {
        val findings = analyze(apps)
        val sideloaded = apps.count { it.sideloaded && !it.system }
        val highRisk = findings.count { it.level == "confirmed_affected" || it.level == "likely_affected" }
        val debuggable = apps.count { it.debuggable && !it.system }
        val score = (100 - sideloaded * 8 - highRisk * 8 - debuggable * 12).coerceIn(0, 100)
        return mapOf(
            "ok" to true,
            "type" to "RUN_HEALTH_ASSESSMENT",
            "score" to score,
            "appCount" to apps.size,
            "sideloadedCount" to sideloaded,
            "debuggableCount" to debuggable,
            "findingCount" to findings.size,
            "highRiskFindingCount" to highRisk,
            "findings" to findings.map { it.toMap() },
        )
    }
}
