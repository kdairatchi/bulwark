package com.bulwark.deviceapi

/**
 * Shared command execution used by the JVM demo and the Android TV agent.
 * Pass [execute] to override stubs with real inventory / DNS / posture handlers.
 */
object CommandExecutor {
    fun defaultExecute(type: String, parameters: Map<String, Any?>): Map<String, Any?> {
        return when (type) {
            "REQUEST_INVENTORY" -> mapOf(
                "ok" to true,
                "stub" to true,
                "type" to type,
                "parameters" to parameters,
            )
            "RUN_MALWARE_SCAN", "RUN_VULNERABILITY_SCAN", "RUN_HEALTH_ASSESSMENT" -> mapOf(
                "ok" to true,
                "stub" to true,
                "type" to type,
                "threatsFound" to 0,
                "findings" to 0,
                "parameters" to parameters,
            )
            "UPDATE_THREAT_FEEDS" -> mapOf("ok" to true, "stub" to true, "type" to type, "updated" to false)
            "QUARANTINE_FILE", "BLOCK_DOMAIN" -> mapOf(
                "ok" to true,
                "stub" to true,
                "type" to type,
                "applied" to false,
                "reason" to "stub — awaiting enforcement wiring",
            )
            "RESTART_AGENT" -> mapOf("ok" to true, "stub" to true, "type" to type, "scheduled" to false)
            else -> mapOf("ok" to false, "error" to "unhandled command type", "type" to type)
        }
    }

    fun process(
        serverPublicKeyPem: String,
        deviceId: String,
        cmd: CommandEnvelope,
        seenNonces: MutableSet<String>,
        nowMs: Long = System.currentTimeMillis(),
        execute: (String, Map<String, Any?>) -> Map<String, Any?> = ::defaultExecute,
    ): Pair<Boolean, Map<String, Any?>> {
        when (val v = verifyCommandEnvelope(serverPublicKeyPem, cmd, nowMs, deviceId, seenNonces)) {
            is CommandVerifyResult.Rejected ->
                return false to mapOf("ok" to false, "rejected" to true, "reason" to v.reason)
            CommandVerifyResult.Ok -> Unit
        }
        seenNonces += cmd.nonce
        val result = execute(cmd.type, cmd.parameters).toMutableMap()
        result["commandId"] = cmd.commandId
        result["type"] = cmd.type
        return true to result
    }
}
