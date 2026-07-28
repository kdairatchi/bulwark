package com.bulwark.deviceapi

import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.time.Instant

class DeviceApiException(val status: Int, val body: String) :
    RuntimeException("Device API HTTP $status: $body")

data class EnrollResult(val deviceId: String, val enrolledAt: String)

data class DeviceIdentity(
    val deviceId: String,
    val name: String,
    val publicKeyPem: String,
    val privateKeyPem: String,
    val serverPublicKeyPem: String,
    val baseUrl: String,
    val enrolledAt: String,
)

/**
 * Thin HTTP client for the Bulwark device API.
 * Uses HttpURLConnection so the same code runs on JVM demos and Android TV.
 */
class DeviceApiClient(
    baseUrl: String,
    private var dashboardToken: String? = System.getenv("DASHBOARD_TOKEN"),
) {
    private val base = baseUrl.trimEnd('/')

    fun setDashboardToken(token: String) {
        dashboardToken = token.trim()
    }

    /** Local/dev only — GET /v1/dashboard-bootstrap when the server auto-generated a token. */
    fun bootstrapDashboardToken(): String {
        val (status, body) = request("GET", "/v1/dashboard-bootstrap")
        if (status !in 200..299) throw DeviceApiException(status, body)
        val token = JsonLite.parseObject(body)["token"] as? String
            ?: throw DeviceApiException(status, "missing token")
        dashboardToken = token
        return token
    }

    fun ensureDashboardToken(): String {
        val existing = dashboardToken?.trim().orEmpty()
        if (existing.isNotEmpty()) return existing
        return bootstrapDashboardToken()
    }

    fun createPairingCode(): Pair<String, String> {
        val (status, body) = dashboardRequest("POST", "/v1/pairing-codes", "{}")
        if (status !in 200..299) throw DeviceApiException(status, body)
        val obj = JsonLite.parseObject(body)
        return (obj["code"] as String) to (obj["expiresAt"] as String)
    }

    fun issueCommand(deviceId: String, type: String, parameters: Map<String, Any?> = emptyMap()): Map<String, Any?> {
        val payload = JsonLite.stringifyObject(mapOf("type" to type, "parameters" to parameters))
        val (status, body) = dashboardRequest("POST", "/v1/devices/$deviceId/commands", payload)
        if (status !in 200..299) throw DeviceApiException(status, body)
        return JsonLite.parseObject(body)
    }

    fun isolateDevice(deviceId: String, reason: String = "agent-demo"): Map<String, Any?> {
        val payload = JsonLite.stringifyObject(mapOf("reason" to reason))
        val (status, body) = dashboardRequest("POST", "/v1/devices/$deviceId/isolate", payload)
        if (status !in 200..299) throw DeviceApiException(status, body)
        return JsonLite.parseObject(body)
    }

    fun enroll(code: String, name: String, publicKeyPem: String, os: String): EnrollResult {
        val payload = JsonLite.stringifyObject(
            mapOf(
                "code" to code,
                "name" to name,
                "publicKeyPem" to publicKeyPem,
                "os" to os,
            ),
        )
        val (status, body) = request("POST", "/v1/devices/enroll", payload)
        if (status !in 200..299) throw DeviceApiException(status, body)
        val obj = JsonLite.parseObject(body)
        return EnrollResult(obj["deviceId"] as String, obj["enrolledAt"] as? String ?: Instant.now().toString())
    }

    fun getServerKey(): String {
        val (status, body) = request("GET", "/v1/server-key")
        if (status !in 200..299) throw DeviceApiException(status, body)
        return JsonLite.parseObject(body)["publicKeyPem"] as String
    }

    fun heartbeat(identity: DeviceIdentity) {
        signed(identity, "POST", "/v1/devices/${identity.deviceId}/heartbeat", "{}")
    }

    fun pollCommands(identity: DeviceIdentity): List<CommandEnvelope> {
        val body = signed(identity, "GET", "/v1/devices/${identity.deviceId}/commands")
        val obj = JsonLite.parseObject(body)
        val commands = obj["commands"] as? List<*> ?: return emptyList()
        return commands.mapNotNull { parseCommand(it) }
    }

    fun postCommandResult(identity: DeviceIdentity, commandId: String, result: Map<String, Any?>) {
        val path = "/v1/devices/${identity.deviceId}/commands/$commandId/result"
        signed(identity, "POST", path, JsonLite.stringifyObject(result))
    }

    fun submitInventory(identity: DeviceIdentity, inventory: Map<String, Any?>) {
        signed(
            identity,
            "POST",
            "/v1/devices/${identity.deviceId}/inventory",
            JsonLite.stringifyObject(inventory),
        )
    }

    fun submitFindings(identity: DeviceIdentity, findings: List<Map<String, Any?>>) {
        val payload = JsonLite.stringifyObject(mapOf("findings" to findings))
        signed(identity, "POST", "/v1/devices/${identity.deviceId}/findings", payload)
    }

    fun getPolicy(identity: DeviceIdentity): DevicePolicy {
        val body = signed(identity, "GET", "/v1/devices/${identity.deviceId}/policy")
        val obj = JsonLite.parseObject(body)
        @Suppress("UNCHECKED_CAST")
        val policy = obj["policy"] as? Map<String, Any?> ?: emptyMap()
        return DevicePolicy.fromMap(policy)
    }

    fun submitNetworkEvents(identity: DeviceIdentity, events: List<Map<String, Any?>>) {
        if (events.isEmpty()) return
        signed(
            identity,
            "POST",
            "/v1/devices/${identity.deviceId}/network-events",
            JsonLite.stringifyObject(mapOf("events" to events)),
        )
    }

    private fun parseCommand(raw: Any?): CommandEnvelope? {
        val o = raw as? Map<*, *> ?: return null
        fun str(key: String): String? = o[key] as? String
        @Suppress("UNCHECKED_CAST")
        val params = (o["parameters"] as? Map<String, Any?>) ?: emptyMap()
        return CommandEnvelope(
            commandId = str("commandId") ?: return null,
            deviceId = str("deviceId") ?: return null,
            type = str("type") ?: return null,
            parameters = params,
            issuedAt = str("issuedAt") ?: return null,
            expiresAt = str("expiresAt") ?: return null,
            nonce = str("nonce") ?: return null,
            signature = str("signature") ?: return null,
        )
    }

    private fun signed(identity: DeviceIdentity, method: String, path: String, rawBody: String = ""): String {
        val timestamp = Instant.now().toString()
        val message = DeviceCrypto.canonicalRequest(
            method, path, timestamp, DeviceCrypto.sha256Hex(rawBody),
        )
        val signature = DeviceCrypto.signMessage(identity.privateKeyPem, message)
        val headers = mapOf(
            "Content-Type" to "application/json",
            "X-Device-Id" to identity.deviceId,
            "X-Timestamp" to timestamp,
            "X-Signature" to signature,
        )
        val (status, body) = request(method, path, if (method == "GET") null else rawBody, headers)
        if (status !in 200..299) throw DeviceApiException(status, body)
        return body
    }

    private fun dashboardRequest(method: String, path: String, rawBody: String? = null): Pair<Int, String> {
        val token = ensureDashboardToken()
        val headers = mapOf(
            "Content-Type" to "application/json",
            "Authorization" to "Bearer $token",
        )
        return request(method, path, rawBody, headers)
    }

    private fun request(
        method: String,
        path: String,
        rawBody: String? = null,
        headers: Map<String, String> = mapOf("Content-Type" to "application/json"),
    ): Pair<Int, String> {
        val conn = (URL(base + path).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = 10_000
            readTimeout = 30_000
            doInput = true
            headers.forEach { (k, v) -> setRequestProperty(k, v) }
            if (rawBody != null && method != "GET") {
                doOutput = true
                OutputStreamWriter(outputStream, Charsets.UTF_8).use { it.write(rawBody) }
            }
        }
        val status = conn.responseCode
        val stream = if (status >= 400) conn.errorStream ?: conn.inputStream else conn.inputStream
        val body = stream?.let { BufferedReader(InputStreamReader(it, Charsets.UTF_8)).readText() } ?: ""
        conn.disconnect()
        return status to body
    }
}
