package com.bulwark.deviceapi

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DnsGuardEnforcementTest {
    @Test
    fun needsDnsGuardWhenIsolatedOrRequired() {
        assertTrue(DnsGuardEnforcement.needsDnsGuard(isolated = true, dnsGuardRequired = false))
        assertTrue(DnsGuardEnforcement.needsDnsGuard(isolated = false, dnsGuardRequired = true))
        assertFalse(DnsGuardEnforcement.needsDnsGuard(isolated = false, dnsGuardRequired = false))
    }

    @Test
    fun isolateResultIsHonestWhenVpnNotRunning() {
        val r = DnsGuardEnforcement.enforcementResult(
            type = "ISOLATE_DEVICE",
            vpnRunning = false,
            needsConsent = true,
            extras = mapOf("isolated" to true),
        )
        assertEquals(true, r["ok"])
        assertEquals(false, r["applied"])
        assertEquals(true, r["vpnConsentPending"])
        assertEquals(DnsGuardEnforcement.REASON_VPN_PERMISSION, r["reason"])
        assertEquals(true, r["isolated"])
    }

    @Test
    fun isolateResultAppliedWhenVpnRunning() {
        val r = DnsGuardEnforcement.enforcementResult(
            type = "ISOLATE_DEVICE",
            vpnRunning = true,
            needsConsent = false,
            extras = mapOf("isolated" to true),
        )
        assertEquals(true, r["applied"])
        assertEquals(false, r["vpnConsentPending"])
        assertEquals(null, r["reason"])
    }

    @Test
    fun clearPendingOnlyWhenGuardNoLongerNeededOrVpnRunning() {
        assertTrue(
            DnsGuardEnforcement.shouldClearVpnPending(
                isolated = false,
                dnsGuardRequired = false,
                vpnRunning = false,
            ),
        )
        assertFalse(
            DnsGuardEnforcement.shouldClearVpnPending(
                isolated = false,
                dnsGuardRequired = true,
                vpnRunning = false,
            ),
        )
        assertTrue(
            DnsGuardEnforcement.shouldClearVpnPending(
                isolated = false,
                dnsGuardRequired = true,
                vpnRunning = true,
            ),
        )
    }
}
