package com.bulwark.deviceapi

/**
 * Pure helpers for honest DNS Guard / isolate command results.
 * Used by the Android TV app and JVM tests (no Android VpnService deps).
 */
object DnsGuardEnforcement {
    const val REASON_VPN_PERMISSION = "vpn_permission_required"
    const val REASON_VPN_ESTABLISH = "vpn_establish_failed"
    const val EVENT_DNS_GUARD_PENDING = "dns_guard_pending"

    fun needsDnsGuard(isolated: Boolean, dnsGuardRequired: Boolean): Boolean =
        isolated || dnsGuardRequired

    /**
     * Build a command result that never claims DNS filtering was applied
     * when the local guard is not actually running.
     */
    fun enforcementResult(
        type: String,
        vpnRunning: Boolean,
        needsConsent: Boolean,
        extras: Map<String, Any?> = emptyMap(),
    ): Map<String, Any?> {
        val applied = vpnRunning
        val reason = when {
            applied -> null
            needsConsent -> REASON_VPN_PERMISSION
            else -> REASON_VPN_ESTABLISH
        }
        return buildMap {
            put("ok", true)
            put("stub", false)
            put("type", type)
            put("applied", applied)
            put("dnsGuardRunning", vpnRunning)
            put("vpnConsentPending", needsConsent || !vpnRunning)
            if (reason != null) put("reason", reason)
            putAll(extras)
        }
    }
}
