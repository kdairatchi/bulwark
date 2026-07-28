package com.bulwark.deviceapi

/**
 * Secure remote-command model matching `src/cloud/device-api/commands.ts`.
 * Commands are server-signed, allowlisted, expiring, and nonce-protected.
 */

val ALLOWED_COMMANDS = setOf(
    "REQUEST_INVENTORY",
    "RUN_MALWARE_SCAN",
    "RUN_VULNERABILITY_SCAN",
    "RUN_HEALTH_ASSESSMENT",
    "UPDATE_THREAT_FEEDS",
    "QUARANTINE_FILE",
    "BLOCK_DOMAIN",
    "RESTART_AGENT",
    "ISOLATE_DEVICE",
    "CLEAR_ISOLATION",
    "APPLY_POLICY",
)

data class CommandEnvelope(
    val commandId: String,
    val deviceId: String,
    val type: String,
    val parameters: Map<String, Any?>,
    val issuedAt: String,
    val expiresAt: String,
    val nonce: String,
    val signature: String,
)

fun isAllowedCommand(type: String): Boolean = type in ALLOWED_COMMANDS

fun canonicalCommand(cmd: CommandEnvelope): String {
    val paramsJson = JsonLite.stringifyObject(cmd.parameters)
    return listOf(
        cmd.commandId,
        cmd.deviceId,
        cmd.type,
        paramsJson,
        cmd.issuedAt,
        cmd.expiresAt,
        cmd.nonce,
    ).joinToString("\n")
}

sealed class CommandVerifyResult {
    data object Ok : CommandVerifyResult()
    data class Rejected(val reason: String) : CommandVerifyResult()
}

fun verifyCommandEnvelope(
    serverPublicKeyPem: String,
    cmd: CommandEnvelope,
    nowMs: Long,
    deviceId: String,
    seenNonces: Set<String>,
): CommandVerifyResult {
    if (!isAllowedCommand(cmd.type)) return CommandVerifyResult.Rejected("command type not allowlisted")
    if (cmd.deviceId != deviceId) return CommandVerifyResult.Rejected("device id mismatch")
    val exp = runCatching { java.time.Instant.parse(cmd.expiresAt).toEpochMilli() }.getOrNull()
        ?: return CommandVerifyResult.Rejected("command expired")
    if (nowMs > exp) return CommandVerifyResult.Rejected("command expired")
    if (cmd.nonce in seenNonces) return CommandVerifyResult.Rejected("nonce replay")
    if (!DeviceCrypto.verifyMessage(serverPublicKeyPem, canonicalCommand(cmd), cmd.signature)) {
        return CommandVerifyResult.Rejected("invalid server signature")
    }
    return CommandVerifyResult.Ok
}

/**
 * Minimal JSON helpers so the core module stays dependency-light and matches
 * Node's `JSON.stringify` for plain string/number/boolean/null object maps.
 */
object JsonLite {
    fun stringifyObject(map: Map<String, Any?>): String {
        if (map.isEmpty()) return "{}"
        val parts = map.entries.joinToString(",") { (k, v) ->
            "\"${escape(k)}\":${stringifyValue(v)}"
        }
        return "{$parts}"
    }

    fun stringifyValue(v: Any?): String = when (v) {
        null -> "null"
        is Boolean -> v.toString()
        is Number -> v.toString()
        is String -> "\"${escape(v)}\""
        is Map<*, *> -> {
            @Suppress("UNCHECKED_CAST")
            stringifyObject(v as Map<String, Any?>)
        }
        is List<*> -> "[" + v.joinToString(",") { stringifyValue(it) } + "]"
        else -> "\"${escape(v.toString())}\""
    }

    private fun escape(s: String): String = buildString {
        for (c in s) {
            when (c) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> append(c)
            }
        }
    }

    fun parseObject(json: String): Map<String, Any?> {
        val trimmed = json.trim()
        require(trimmed.startsWith("{") && trimmed.endsWith("}")) { "expected object" }
        return parseValue(trimmed) as Map<String, Any?>
    }

    fun parseValue(json: String): Any? {
        val s = json.trim()
        return when {
            s == "null" -> null
            s == "true" -> true
            s == "false" -> false
            s.startsWith("\"") -> parseString(s).first
            s.startsWith("{") -> parseObj(s)
            s.startsWith("[") -> parseArr(s)
            else -> s.toDoubleOrNull() ?: s
        }
    }

    private fun parseString(s: String): Pair<String, Int> {
        require(s.startsWith("\""))
        val out = StringBuilder()
        var i = 1
        while (i < s.length) {
            val c = s[i]
            if (c == '"') return out.toString() to (i + 1)
            if (c == '\\' && i + 1 < s.length) {
                when (val n = s[i + 1]) {
                    '"', '\\', '/' -> { out.append(n); i += 2 }
                    'n' -> { out.append('\n'); i += 2 }
                    'r' -> { out.append('\r'); i += 2 }
                    't' -> { out.append('\t'); i += 2 }
                    else -> { out.append(n); i += 2 }
                }
            } else {
                out.append(c); i++
            }
        }
        error("unterminated string")
    }

    private fun parseObj(s: String): Map<String, Any?> {
        val map = linkedMapOf<String, Any?>()
        var i = 1
        skipWs(s, i).also { i = it }
        if (s[i] == '}') return map
        while (i < s.length) {
            skipWs(s, i).also { i = it }
            val (key, next) = parseString(s.substring(i))
            i += next
            i = skipWs(s, i)
            require(s[i] == ':')
            i++
            i = skipWs(s, i)
            val (value, consumed) = parseValueWithLength(s.substring(i))
            map[key] = value
            i += consumed
            i = skipWs(s, i)
            if (s[i] == '}') return map
            require(s[i] == ',')
            i++
        }
        error("unterminated object")
    }

    private fun parseArr(s: String): List<Any?> {
        val list = mutableListOf<Any?>()
        var i = 1
        i = skipWs(s, i)
        if (s[i] == ']') return list
        while (i < s.length) {
            i = skipWs(s, i)
            val (value, consumed) = parseValueWithLength(s.substring(i))
            list += value
            i += consumed
            i = skipWs(s, i)
            if (s[i] == ']') return list
            require(s[i] == ',')
            i++
        }
        error("unterminated array")
    }

    private fun parseValueWithLength(s: String): Pair<Any?, Int> {
        val trimmedStart = skipWs(s, 0)
        val body = s.substring(trimmedStart)
        when {
            body.startsWith("\"") -> {
                val (value, consumed) = parseString(body)
                return value to (trimmedStart + consumed)
            }
            body.startsWith("{") -> {
                val consumed = balanced(body, '{', '}')
                return parseObj(body.substring(0, consumed)) to (trimmedStart + consumed)
            }
            body.startsWith("[") -> {
                val consumed = balanced(body, '[', ']')
                return parseArr(body.substring(0, consumed)) to (trimmedStart + consumed)
            }
            body.startsWith("null") -> return null to (trimmedStart + 4)
            body.startsWith("true") -> return true to (trimmedStart + 4)
            body.startsWith("false") -> return false to (trimmedStart + 5)
            else -> {
                var n = 0
                while (n < body.length && (body[n].isDigit() || body[n] in "+-.eE")) n++
                val numStr = body.substring(0, n)
                val value: Any = numStr.toLongOrNull() ?: numStr.toDoubleOrNull() ?: numStr
                return value to (trimmedStart + n)
            }
        }
    }

    private fun balanced(s: String, open: Char, close: Char): Int {
        var depth = 0
        var inStr = false
        var esc = false
        for (i in s.indices) {
            val c = s[i]
            if (inStr) {
                if (esc) esc = false
                else if (c == '\\') esc = true
                else if (c == '"') inStr = false
                continue
            }
            when (c) {
                '"' -> inStr = true
                open -> depth++
                close -> {
                    depth--
                    if (depth == 0) return i + 1
                }
            }
        }
        error("unbalanced")
    }

    private fun skipWs(s: String, start: Int): Int {
        var i = start
        while (i < s.length && s[i].isWhitespace()) i++
        return i
    }
}
