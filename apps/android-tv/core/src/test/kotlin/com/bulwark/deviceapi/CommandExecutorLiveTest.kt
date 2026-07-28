package com.bulwark.deviceapi

import java.io.File
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CommandExecutorLiveTest {
    @BeforeTest
    fun reset() {
        CommandExecutor.resetDemoState()
    }

    @Test
    fun inventoryIsLiveNotStub() {
        val r = CommandExecutor.defaultExecute("REQUEST_INVENTORY", emptyMap())
        assertEquals(true, r["ok"])
        assertEquals(false, r["stub"])
        assertTrue((r["count"] as Int) >= 2)
        assertTrue((r["findingCount"] as Int) >= 1)
    }

    @Test
    fun malwareScanUsesAppPosture() {
        val r = CommandExecutor.defaultExecute("RUN_MALWARE_SCAN", mapOf("scope" to "quick"))
        assertEquals(false, r["stub"])
        assertTrue((r["findings"] as Int) >= 1)
        assertTrue((r["threatsFound"] as Int) >= 1)
    }

    @Test
    fun blockDomainUpdatesDemoBlocklist() {
        val r = CommandExecutor.defaultExecute("BLOCK_DOMAIN", mapOf("domain" to "evil.test"))
        assertEquals(false, r["stub"])
        assertEquals(true, r["applied"])
        assertTrue(CommandExecutor.demoBlocklist.isBlocked("evil.test"))
        // Honest: no VPN on JVM
        assertEquals(false, r["dnsGuardRunning"])
        assertEquals(DnsGuardEnforcement.REASON_VPN_PERMISSION, r["reason"])
    }

    @Test
    fun isolateIsHonestWithoutVpn() {
        val r = CommandExecutor.defaultExecute("ISOLATE_DEVICE", emptyMap())
        assertEquals(false, r["stub"])
        assertEquals(false, r["applied"])
        assertEquals(true, r["isolated"])
        assertEquals(DnsFilterMode.ALLOWLIST, CommandExecutor.demoBlocklist.mode)
    }

    @Test
    fun clearIsolationApplies() {
        CommandExecutor.defaultExecute("ISOLATE_DEVICE", emptyMap())
        val r = CommandExecutor.defaultExecute("CLEAR_ISOLATION", emptyMap())
        assertEquals(false, r["stub"])
        assertEquals(true, r["applied"])
        assertEquals(false, r["isolated"])
    }

    @Test
    fun quarantineMovesFileUnderTmpRoot() {
        val root = File(System.getProperty("java.io.tmpdir"), "bulwark-jvm-quarantine-root")
        root.mkdirs()
        val sample = File(root, "sample-${System.nanoTime()}.bin").also { it.writeText("malware") }
        try {
            val r = CommandExecutor.defaultExecute("QUARANTINE_FILE", mapOf("path" to sample.absolutePath))
            assertEquals(false, r["stub"])
            assertEquals(true, r["applied"])
            assertFalse(sample.exists())
        } finally {
            File(root, "quarantine").deleteRecursively()
            sample.delete()
        }
    }

    @Test
    fun restartAgentSchedulesWithoutStub() {
        val r = CommandExecutor.defaultExecute("RESTART_AGENT", emptyMap())
        assertEquals(false, r["stub"])
        assertEquals(true, r["scheduled"])
    }
}
