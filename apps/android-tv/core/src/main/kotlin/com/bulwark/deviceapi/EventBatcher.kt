package com.bulwark.deviceapi

/**
 * Lightweight device event batch — DNS blocks, posture alerts, etc.
 * Matches POST /v1/devices/{id}/network-events on the control plane.
 */
data class DeviceEvent(
    val type: String,
    val at: String,
    val subject: String? = null,
    val detail: String? = null,
    val metadata: Map<String, Any?> = emptyMap(),
) {
    fun toMap(): Map<String, Any?> = mapOf(
        "type" to type,
        "at" to at,
        "subject" to subject,
        "detail" to detail,
        "metadata" to metadata,
    )

    companion object {
        fun dnsBlocked(host: String, at: String = java.time.Instant.now().toString()) = DeviceEvent(
            type = "dns_blocked",
            at = at,
            subject = host,
            detail = "DNS query blocked by local guard",
        )

        fun isolationChanged(isolated: Boolean, at: String = java.time.Instant.now().toString()) = DeviceEvent(
            type = if (isolated) "isolation_enabled" else "isolation_cleared",
            at = at,
            subject = "device",
            detail = if (isolated) "Emergency isolation enabled" else "Isolation cleared",
        )

        fun findingRaised(subject: String, reason: String, level: String) = DeviceEvent(
            type = "finding",
            at = java.time.Instant.now().toString(),
            subject = subject,
            detail = reason,
            metadata = mapOf("level" to level),
        )

        fun dnsGuardPending(detail: String = "VPN permission required for DNS Guard") = DeviceEvent(
            type = DnsGuardEnforcement.EVENT_DNS_GUARD_PENDING,
            at = java.time.Instant.now().toString(),
            subject = "device",
            detail = detail,
        )
    }
}

/** In-memory ring buffer used by the TV agent before flush to the cloud. */
class EventBatcher(private val capacity: Int = 200) {
    private val events = ArrayDeque<DeviceEvent>()

    @Synchronized
    fun add(event: DeviceEvent) {
        if (events.size >= capacity) events.removeFirst()
        events.addLast(event)
    }

    @Synchronized
    fun size(): Int = events.size

    @Synchronized
    fun drain(): List<DeviceEvent> {
        val out = events.toList()
        events.clear()
        return out
    }

    @Synchronized
    fun snapshot(): List<DeviceEvent> = events.toList()
}
