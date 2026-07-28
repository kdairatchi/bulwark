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
)

data class Finding(
    val level: String,
    val subjectName: String,
    val reason: String,
) {
    fun toMap(): Map<String, Any?> = mapOf(
        "level" to level,
        "subjectName" to subjectName,
        "reason" to reason,
    )
}

object AppPosture {
    fun dangerousPermissions(permissions: List<String>): List<String> =
        permissions.filter { it in DANGEROUS_PERMISSIONS }.distinct().sorted()

    fun permissionRiskScore(permissions: List<String>): Int {
        val flagged = dangerousPermissions(permissions)
        // Cap so a single app cannot dominate the fleet score.
        return minOf(100, flagged.size * 15)
    }

    fun analyze(apps: List<AppRecord>): List<Finding> {
        val findings = mutableListOf<Finding>()
        for (app in apps) {
            if (app.system) continue
            if (app.sideloaded) {
                findings += Finding(
                    level = "likely_affected",
                    subjectName = app.packageName,
                    reason = "Sideloaded app (installer=${app.installer ?: "unknown"})",
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
                )
            }
            if (app.sideloaded && app.certSha256 == null) {
                findings += Finding(
                    level = "potential_match",
                    subjectName = app.packageName,
                    reason = "Sideloaded app without readable signing certificate",
                )
            }
        }
        return findings
    }

    fun healthAssessment(apps: List<AppRecord>): Map<String, Any?> {
        val findings = analyze(apps)
        val sideloaded = apps.count { it.sideloaded && !it.system }
        val highRisk = findings.count { it.level == "confirmed_affected" || it.level == "likely_affected" }
        val score = (100 - sideloaded * 8 - highRisk * 10).coerceIn(0, 100)
        return mapOf(
            "ok" to true,
            "type" to "RUN_HEALTH_ASSESSMENT",
            "score" to score,
            "appCount" to apps.size,
            "sideloadedCount" to sideloaded,
            "findingCount" to findings.size,
            "highRiskFindingCount" to highRisk,
            "findings" to findings.map { it.toMap() },
        )
    }
}
