package com.bulwark.deviceapi

import java.io.File

/**
 * Pure JVM helper for QUARANTINE_FILE — mirrors desktop parse/allowlist semantics
 * without Android framework deps (testable on the JVM).
 */
object FileQuarantine {
    const val MAX_PATHS = 100
    const val MAX_PATH_LENGTH = 500
    const val MANIFEST_NAME = "quarantine-manifest.json"

    /**
     * Quarantine [paths] into [quarantineDir] when each canonical path is under
     * one of [allowRoots]. Rejects `..` escapes via canonical resolution.
     */
    fun quarantineFiles(
        paths: List<String>,
        allowRoots: List<File>,
        quarantineDir: File,
    ): Map<String, Any?> {
        if (paths.isEmpty()) {
            return mapOf(
                "ok" to false,
                "stub" to false,
                "type" to "QUARANTINE_FILE",
                "applied" to false,
                "reason" to "missing path or paths",
            )
        }
        if (paths.any { it.length > MAX_PATH_LENGTH }) {
            return mapOf(
                "ok" to false,
                "stub" to false,
                "type" to "QUARANTINE_FILE",
                "applied" to false,
                "reason" to "path too long",
            )
        }

        val roots = allowRoots.mapNotNull { runCatching { it.canonicalFile }.getOrNull() }
        val denied = paths.filter { !isUnderAllowRoots(it, roots) }
        if (denied.isNotEmpty()) {
            return mapOf(
                "ok" to false,
                "stub" to false,
                "type" to "QUARANTINE_FILE",
                "applied" to false,
                "reason" to "path outside allowed directories",
                "denied" to denied.take(5),
            )
        }

        return try {
            if (!quarantineDir.exists() && !quarantineDir.mkdirs()) {
                return mapOf(
                    "ok" to false,
                    "stub" to false,
                    "type" to "QUARANTINE_FILE",
                    "applied" to false,
                    "reason" to "cannot create quarantine directory",
                )
            }

            val manifest = readManifest(quarantineDir).toMutableList()
            var succeeded = 0
            var failed = 0
            val errors = mutableListOf<Map<String, String>>()

            for (path in paths.take(MAX_PATHS)) {
                val src = File(path)
                try {
                    // Re-check allowlist at act-time (closes TOCTOU / symlink races).
                    if (!isUnderAllowRoots(src.path, roots)) {
                        failed++
                        errors += mapOf("path" to path, "reason" to "path outside allowed directories")
                        continue
                    }
                    val srcPath = src.toPath()
                    if (java.nio.file.Files.isSymbolicLink(srcPath)) {
                        failed++
                        errors += mapOf("path" to path, "reason" to "symlinks are not allowed")
                        continue
                    }
                    if (!java.nio.file.Files.isRegularFile(
                            srcPath,
                            java.nio.file.LinkOption.NOFOLLOW_LINKS,
                        )
                    ) {
                        failed++
                        errors += mapOf(
                            "path" to path,
                            "reason" to if (!src.exists()) "file not found" else "not a regular file",
                        )
                        continue
                    }
                    if (!src.canRead()) {
                        failed++
                        errors += mapOf("path" to path, "reason" to "permission denied")
                        continue
                    }

                    val epoch = System.currentTimeMillis()
                    val safeBase = sanitizeBaseName(src.name)
                    val quarantinedName = "${epoch}_${safeBase}.quarantined"
                    val dest = File(quarantineDir, quarantinedName)
                    val renamed = src.renameTo(dest)
                    if (!renamed) {
                        // Cross-filesystem fallback: copy bytes without following links.
                        java.nio.file.Files.copy(
                            srcPath,
                            dest.toPath(),
                            java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                            java.nio.file.LinkOption.NOFOLLOW_LINKS,
                        )
                        if (!src.delete()) {
                            dest.delete()
                            failed++
                            errors += mapOf("path" to path, "reason" to "failed to move file")
                            continue
                        }
                    }
                    manifest += mapOf(
                        "name" to quarantinedName,
                        "originalPath" to path,
                        "quarantinedAt" to epoch,
                    )
                    succeeded++
                } catch (err: Exception) {
                    failed++
                    val reason = (err.message ?: "Failed to quarantine").take(200)
                    errors += mapOf("path" to path, "reason" to reason)
                }
            }

            writeManifest(quarantineDir, manifest)

            mapOf(
                "ok" to (failed == 0 && succeeded > 0),
                "stub" to false,
                "type" to "QUARANTINE_FILE",
                "applied" to (succeeded > 0),
                "succeeded" to succeeded,
                "failed" to failed,
                "errors" to errors,
            )
        } catch (err: Exception) {
            mapOf(
                "ok" to false,
                "stub" to false,
                "type" to "QUARANTINE_FILE",
                "applied" to false,
                "reason" to (err.message ?: err.toString()),
            )
        }
    }

    /** Extract `path` / `paths[]` from command parameters (max [MAX_PATHS]). */
    fun parsePaths(parameters: Map<String, Any?>): List<String> {
        val single = parameters["path"] as? String
        if (!single.isNullOrBlank()) return listOf(single.trim())
        val list = parameters["paths"] as? List<*> ?: return emptyList()
        return list
            .mapNotNull { (it as? String)?.trim()?.takeIf { s -> s.isNotEmpty() } }
            .take(MAX_PATHS)
    }

    fun isUnderAllowRoots(path: String, allowRoots: List<File>): Boolean {
        val canonical = runCatching { File(path).canonicalFile }.getOrNull() ?: return false
        return allowRoots.any { root ->
            val rootCanon = runCatching { root.canonicalFile }.getOrNull() ?: return@any false
            canonical == rootCanon || canonical.path.startsWith(rootCanon.path + File.separator)
        }
    }

    internal fun sanitizeBaseName(name: String): String {
        val base = name.replace(Regex("[\\\\/]+"), "_").replace(Regex("[^A-Za-z0-9._-]"), "_")
        return base.take(120).ifBlank { "file" }
    }

    @Suppress("UNCHECKED_CAST")
    private fun readManifest(quarantineDir: File): List<Map<String, Any?>> {
        val file = File(quarantineDir, MANIFEST_NAME)
        if (!file.exists()) return emptyList()
        return runCatching {
            val parsed = JsonLite.parseValue(file.readText())
            when (parsed) {
                is List<*> -> parsed.mapNotNull { entry ->
                    (entry as? Map<*, *>)?.entries
                        ?.associate { (k, v) -> k.toString() to v }
                }
                else -> emptyList()
            }
        }.getOrDefault(emptyList())
    }

    private fun writeManifest(quarantineDir: File, entries: List<Map<String, Any?>>) {
        val file = File(quarantineDir, MANIFEST_NAME)
        file.writeText(JsonLite.stringifyValue(entries))
    }
}
