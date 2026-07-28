package com.bulwark.tv

import android.content.Context

/**
 * Tracks whether the user has granted VpnService permission and whether
 * remote policy currently needs DNS Guard that is not yet running.
 */
class VpnConsentStore(context: Context) {
    private val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun isConsentGranted(): Boolean = prefs.getBoolean(KEY_GRANTED, false)

    fun setConsentGranted(granted: Boolean) {
        prefs.edit().putBoolean(KEY_GRANTED, granted).apply()
        if (granted) setPending(false)
    }

    fun isPending(): Boolean = prefs.getBoolean(KEY_PENDING, false)

    fun setPending(pending: Boolean) {
        prefs.edit().putBoolean(KEY_PENDING, pending).apply()
    }

    /** Mark that isolate / dnsGuardRequired needs on-device VPN approval. */
    fun markNeedsConsent() {
        setPending(true)
    }

    fun clearPending() {
        setPending(false)
    }

    companion object {
        private const val PREFS = "bulwark_vpn_consent"
        private const val KEY_GRANTED = "granted"
        private const val KEY_PENDING = "pending"
    }
}
