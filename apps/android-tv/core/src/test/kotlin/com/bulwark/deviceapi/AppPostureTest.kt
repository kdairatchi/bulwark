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
            ),
            AppRecord(
                packageName = "com.netflix.ninja",
                sideloaded = false,
                system = false,
                permissions = listOf("android.permission.INTERNET"),
            ),
        )
        val findings = AppPosture.analyze(apps)
        assertTrue(findings.any { it.subjectName == "com.example.sideload" && it.reason.contains("Sideloaded") })
        assertTrue(findings.any { it.reason.contains("Dangerous permissions") })
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
