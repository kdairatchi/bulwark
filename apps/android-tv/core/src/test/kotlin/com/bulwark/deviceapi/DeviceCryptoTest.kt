package com.bulwark.deviceapi

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class DeviceCryptoTest {
    @Test
    fun roundTripSignVerify() {
        val keys = DeviceCrypto.generateDeviceKeyPair()
        assertTrue(keys.publicKeyPem.contains("BEGIN PUBLIC KEY"))
        assertTrue(keys.privateKeyPem.contains("BEGIN PRIVATE KEY"))
        val sig = DeviceCrypto.signMessage(keys.privateKeyPem, "hello")
        assertTrue(DeviceCrypto.verifyMessage(keys.publicKeyPem, "hello", sig))
        assertFalse(DeviceCrypto.verifyMessage(keys.publicKeyPem, "hello!", sig))
    }

    @Test
    fun sha256MatchesKnownVector() {
        // echo -n "abc" | sha256sum
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            DeviceCrypto.sha256Hex("abc"),
        )
    }
}

class CommandsTest {
    private val server = DeviceCrypto.generateDeviceKeyPair()

    private fun sign(cmd: CommandEnvelope): CommandEnvelope {
        val sig = DeviceCrypto.signMessage(server.privateKeyPem, canonicalCommand(cmd))
        return cmd.copy(signature = sig)
    }

    @Test
    fun acceptsValidAllowlistedCommand() {
        val cmd = sign(
            CommandEnvelope(
                commandId = "cmd_1",
                deviceId = "dev_1",
                type = "RUN_MALWARE_SCAN",
                parameters = mapOf("scope" to "quick"),
                issuedAt = java.time.Instant.now().toString(),
                expiresAt = java.time.Instant.now().plusSeconds(60).toString(),
                nonce = "n1",
                signature = "",
            ),
        )
        val result = verifyCommandEnvelope(
            server.publicKeyPem, cmd, System.currentTimeMillis(), "dev_1", emptySet(),
        )
        assertIs<CommandVerifyResult.Ok>(result)
    }

    @Test
    fun rejectsShellAndExpiredAndReplay() {
        val base = CommandEnvelope(
            commandId = "cmd_2",
            deviceId = "dev_1",
            type = "RUN_SHELL",
            parameters = emptyMap(),
            issuedAt = java.time.Instant.now().toString(),
            expiresAt = java.time.Instant.now().plusSeconds(60).toString(),
            nonce = "n2",
            signature = "x",
        )
        assertIs<CommandVerifyResult.Rejected>(
            verifyCommandEnvelope(server.publicKeyPem, base, System.currentTimeMillis(), "dev_1", emptySet()),
        )

        val expired = sign(
            base.copy(
                type = "RUN_MALWARE_SCAN",
                expiresAt = java.time.Instant.now().minusSeconds(5).toString(),
                nonce = "n3",
                signature = "",
            ),
        )
        val r2 = verifyCommandEnvelope(server.publicKeyPem, expired, System.currentTimeMillis(), "dev_1", emptySet())
        assertEquals("command expired", (r2 as CommandVerifyResult.Rejected).reason)

        val good = sign(
            base.copy(type = "RUN_MALWARE_SCAN", nonce = "n4", signature = ""),
        )
        val replay = verifyCommandEnvelope(
            server.publicKeyPem, good, System.currentTimeMillis(), "dev_1", setOf("n4"),
        )
        assertEquals("nonce replay", (replay as CommandVerifyResult.Rejected).reason)
    }

    @Test
    fun jsonLiteRoundTripEmptyAndNested() {
        assertEquals("{}", JsonLite.stringifyObject(emptyMap()))
        assertEquals("""{"scope":"quick"}""", JsonLite.stringifyObject(mapOf("scope" to "quick")))
        val parsed = JsonLite.parseObject("""{"a":1,"b":"x","c":true,"d":null}""")
        assertEquals(1L, parsed["a"])
        assertEquals("x", parsed["b"])
        assertEquals(true, parsed["c"])
        assertEquals(null, parsed["d"])
    }
}
