package com.bulwark.deviceapi

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class AppPostureTest {
    @Test
    fun flagsSideloadAndDangerousPermissions() {
        val apps = listOf(
            AppRecord(
                packageName = "com.example.sideload",
                sideloaded = true,
                permissions = listOf(
                    "android.permission.RECORD_AUDIO",
                    "android.permission.REQUEST_INSTALL_PACKAGES",
                    "android.permission.INTERNET",
                ),
                debuggable = true,
                targetSdk = 26,
                exportedActivities = 2,
                exportedServices = 2,
            ),
            AppRecord(
                packageName = "com.netflix.ninja",
                sideloaded = false,
                system = false,
                permissions = listOf("android.permission.INTERNET"),
                targetSdk = 34,
            ),
        )
        val findings = AppPosture.analyze(apps)
        assertTrue(findings.any { it.subjectName == "com.example.sideload" && it.reason.contains("Sideloaded") })
        assertTrue(findings.any { it.reason.contains("Dangerous permissions") })
        assertTrue(findings.any { it.category == "hardening" && it.reason.contains("debuggable") })
        assertTrue(findings.any { it.category == "attack_surface" })
        assertTrue(findings.any { it.category == "outdated" })
        val health = AppPosture.healthAssessment(apps)
        assertEquals(true, health["ok"])
        assertTrue((health["score"] as Int) < 100)
        assertEquals(2, AppPosture.dangerousPermissions(apps[0].permissions).size)
    }
}

class DnsBlocklistTest {
    @Test
    fun matchesExactAndSubdomains() {
        val bl = DnsBlocklist(listOf("tracker.malware.test", "ads.example.invalid"))
        assertTrue(bl.isBlocked("tracker.malware.test"))
        assertTrue(bl.isBlocked("evil.tracker.malware.test"))
        assertFalse(bl.isBlocked("malware.test"))
        assertFalse(bl.isBlocked("example.com"))
        assertTrue(bl.add("new.bad.invalid"))
        assertEquals(3, bl.size())
    }

    @Test
    fun isolationAllowlistBlocksEverythingElse() {
        val bl = DnsBlocklist(listOf("googleapis.com", "android.com"), mode = DnsFilterMode.ALLOWLIST)
        assertFalse(bl.isBlocked("googleapis.com"))
        assertFalse(bl.isBlocked("foo.googleapis.com"))
        assertTrue(bl.isBlocked("tracker.malware.test"))
        assertTrue(bl.isBlocked("netflix.com"))
    }

    @Test
    fun applyPolicySwitchesModes() {
        val bl = DnsBlocklist(listOf("ads.example.invalid"))
        applyPolicyToBlocklist(
            DevicePolicy(isolated = true, isolationAllowlist = listOf("android.com")),
            bl,
        )
        assertEquals(DnsFilterMode.ALLOWLIST, bl.mode)
        assertTrue(bl.isBlocked("evil.test"))
        assertFalse(bl.isBlocked("android.com"))
        applyPolicyToBlocklist(
            DevicePolicy(isolated = false, blockedDomains = listOf("tracker.malware.test")),
            bl,
        )
        assertEquals(DnsFilterMode.BLOCKLIST, bl.mode)
        assertTrue(bl.isBlocked("tracker.malware.test"))
        assertFalse(bl.isBlocked("android.com"))
    }
}

class DnsPacketTest {
    @Test
    fun parsesQueryAndBuildsNxDomain() {
        // Minimal DNS query for "a.b" type A
        val qname = byteArrayOf(
            1, 'a'.code.toByte(),
            1, 'b'.code.toByte(),
            0,
            0, 1, // type A
            0, 1, // class IN
        )
        val header = byteArrayOf(
            0x12, 0x34, // id
            0x01, 0x00, // RD
            0x00, 0x01, // QDCOUNT
            0, 0, 0, 0, 0, 0,
        )
        val packet = header + qname
        val query = DnsPacket.parseQuery(packet)
        assertNotNull(query)
        assertEquals(0x1234, query.id)
        assertEquals("a.b", query.qname)
        assertEquals(1, query.qtype)

        val nx = DnsPacket.buildNxDomain(packet, query)
        assertEquals((0x80 or 0x01).toByte(), nx[2]) // QR|RD
        assertEquals(0x03.toByte(), nx[3]) // NXDOMAIN
        assertEquals(packet.size, nx.size)
    }
}

class EventBatcherTest {
    @Test
    fun drainsQueuedEvents() {
        val b = EventBatcher(capacity = 3)
        b.add(DeviceEvent.dnsBlocked("a.test"))
        b.add(DeviceEvent.isolationChanged(true))
        b.add(DeviceEvent.findingRaised("pkg", "reason", "likely_affected"))
        b.add(DeviceEvent.dnsBlocked("b.test")) // drops oldest when over capacity
        assertEquals(3, b.size())
        val drained = b.drain()
        assertEquals(3, drained.size)
        assertEquals(0, b.size())
        assertTrue(drained.any { it.type == "isolation_enabled" })
    }
}
