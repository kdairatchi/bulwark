package com.bulwark.deviceapi

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class FileQuarantineTest {
    @Test
    fun rejectsEmptyPaths() {
        val tmp = createTempDir()
        try {
            val r = FileQuarantine.quarantineFiles(emptyList(), listOf(tmp), File(tmp, "q"))
            assertEquals(false, r["ok"])
            assertEquals(false, r["stub"])
            assertEquals("QUARANTINE_FILE", r["type"])
            assertEquals(false, r["applied"])
            assertEquals("missing path or paths", r["reason"])
        } finally {
            tmp.deleteRecursively()
        }
    }

    @Test
    fun rejectsPathTooLong() {
        val tmp = createTempDir()
        try {
            val longPath = "a".repeat(501)
            val r = FileQuarantine.quarantineFiles(listOf(longPath), listOf(tmp), File(tmp, "q"))
            assertEquals(false, r["ok"])
            assertEquals("path too long", r["reason"])
        } finally {
            tmp.deleteRecursively()
        }
    }

    @Test
    fun rejectsPathOutsideAllowRoots() {
        val allow = createTempDir()
        val outside = createTempDir()
        try {
            val evil = File(outside, "evil.bin").also { it.writeText("x") }
            val r = FileQuarantine.quarantineFiles(
                listOf(evil.absolutePath),
                listOf(allow),
                File(allow, "quarantine"),
            )
            assertEquals(false, r["ok"])
            assertEquals(false, r["applied"])
            assertEquals("path outside allowed directories", r["reason"])
            @Suppress("UNCHECKED_CAST")
            val denied = r["denied"] as List<*>
            assertTrue(denied.isNotEmpty())
            assertTrue(evil.exists())
        } finally {
            allow.deleteRecursively()
            outside.deleteRecursively()
        }
    }

    @Test
    fun rejectsDotDotEscape() {
        val allow = createTempDir()
        val sibling = File(allow.parentFile, "sibling-${System.nanoTime()}").also { it.mkdirs() }
        try {
            val target = File(sibling, "secret.bin").also { it.writeText("secret") }
            val escaped = File(allow, "../${sibling.name}/secret.bin").path
            val r = FileQuarantine.quarantineFiles(
                listOf(escaped),
                listOf(allow),
                File(allow, "quarantine"),
            )
            assertEquals(false, r["ok"])
            assertEquals("path outside allowed directories", r["reason"])
            assertTrue(target.exists())
        } finally {
            allow.deleteRecursively()
            sibling.deleteRecursively()
        }
    }

    @Test
    fun quarantinesAllowedFileAndWritesManifest() {
        val root = createTempDir()
        try {
            val src = File(root, "malware.bin").also { it.writeText("payload") }
            val qDir = File(root, "quarantine")
            val r = FileQuarantine.quarantineFiles(listOf(src.absolutePath), listOf(root), qDir)

            assertEquals(true, r["ok"])
            assertEquals(false, r["stub"])
            assertEquals("QUARANTINE_FILE", r["type"])
            assertEquals(true, r["applied"])
            assertEquals(1, r["succeeded"])
            assertEquals(0, r["failed"])
            assertFalse(src.exists())

            val quarantined = qDir.listFiles { f -> f.name.endsWith(".quarantined") }
            assertEquals(1, quarantined?.size)

            val manifest = File(qDir, FileQuarantine.MANIFEST_NAME)
            assertTrue(manifest.exists())
            val parsed = JsonLite.parseValue(manifest.readText()) as List<*>
            assertEquals(1, parsed.size)
            @Suppress("UNCHECKED_CAST")
            val entry = parsed[0] as Map<String, Any?>
            assertEquals(src.absolutePath, entry["originalPath"])
            assertTrue((entry["name"] as String).endsWith(".quarantined"))
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun reportsMissingFileHonestly() {
        val root = createTempDir()
        try {
            val missing = File(root, "gone.bin").absolutePath
            val r = FileQuarantine.quarantineFiles(listOf(missing), listOf(root), File(root, "q"))
            assertEquals(false, r["ok"])
            assertEquals(true, r["applied"] == false || r["succeeded"] == 0)
            assertEquals(0, r["succeeded"])
            assertEquals(1, r["failed"])
            @Suppress("UNCHECKED_CAST")
            val errors = r["errors"] as List<Map<String, String>>
            assertEquals("file not found", errors[0]["reason"])
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun rejectsSymlinks() {
        val root = createTempDir()
        try {
            // Keep the symlink target inside the allow root so the batch allowlist
            // check passes; act-time must still reject the symlink itself.
            val target = File(root, "real.bin").also { it.writeText("payload") }
            val link = File(root, "link.bin")
            java.nio.file.Files.createSymbolicLink(link.toPath(), target.toPath())
            val r = FileQuarantine.quarantineFiles(
                listOf(link.absolutePath),
                listOf(root),
                File(root, "quarantine"),
            )
            assertEquals(false, r["ok"])
            assertEquals(false, r["applied"])
            @Suppress("UNCHECKED_CAST")
            val errors = r["errors"] as? List<Map<String, String>>
            assertTrue(errors != null && errors.isNotEmpty())
            assertEquals("symlinks are not allowed", errors!![0]["reason"])
            assertTrue(target.exists())
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun parsePathsFromPathOrPaths() {
        assertEquals(listOf("/a"), FileQuarantine.parsePaths(mapOf("path" to "/a")))
        assertEquals(
            listOf("/a", "/b"),
            FileQuarantine.parsePaths(mapOf("paths" to listOf("/a", "/b", ""))),
        )
        assertEquals(emptyList(), FileQuarantine.parsePaths(emptyMap()))
    }

    private fun createTempDir(): File =
        File.createTempFile("fq-", "-test").also {
            it.delete()
            it.mkdirs()
        }
}
