package com.bulwark.deviceapi

/**
 * Local DNS threat blocklist — exact host + parent-domain matching.
 * Modes:
 *  - BLOCKLIST (default): listed domains are blocked
 *  - ALLOWLIST (isolation): only listed domains resolve; everything else NXDOMAIN
 */
enum class DnsFilterMode {
    BLOCKLIST,
    ALLOWLIST,
}

class DnsBlocklist(
    initial: Collection<String> = emptyList(),
    var mode: DnsFilterMode = DnsFilterMode.BLOCKLIST,
) {
    private val domains = linkedSetOf<String>()

    init {
        addAll(initial)
    }

    fun add(domain: String): Boolean {
        val n = normalize(domain) ?: return false
        return domains.add(n)
    }

    fun addAll(items: Collection<String>): Int = items.count { add(it) }

    fun remove(domain: String): Boolean {
        val n = normalize(domain) ?: return false
        return domains.remove(n)
    }

    fun clear() = domains.clear()

    fun replaceAll(items: Collection<String>) {
        clear()
        addAll(items)
    }

    fun size(): Int = domains.size

    fun snapshot(): Set<String> = domains.toSet()

    fun isBlocked(hostname: String): Boolean {
        val host = normalize(hostname) ?: return mode == DnsFilterMode.ALLOWLIST
        return when (mode) {
            DnsFilterMode.BLOCKLIST -> matchesListed(host)
            DnsFilterMode.ALLOWLIST -> !matchesListed(host)
        }
    }

    private fun matchesListed(host: String): Boolean {
        if (host in domains) return true
        var idx = host.indexOf('.')
        while (idx >= 0 && idx < host.lastIndex) {
            val parent = host.substring(idx + 1)
            if (parent in domains) return true
            idx = host.indexOf('.', idx + 1)
        }
        return false
    }

    companion object {
        fun normalize(raw: String): String? {
            val d = raw.trim().lowercase().trim('.')
            if (d.isEmpty() || d.length > 253) return null
            if (!d.matches(Regex("^[a-z0-9._-]+$"))) return null
            return d
        }
    }
}

data class DevicePolicy(
    val version: Int = 1,
    val updatedAt: String = "",
    val isolated: Boolean = false,
    val dnsGuardRequired: Boolean = false,
    val blockedDomains: List<String> = emptyList(),
    val isolationAllowlist: List<String> = listOf(
        "googleapis.com",
        "gvt1.com",
        "android.com",
        "google.com",
        "cloudflare.com",
    ),
    val allowInstallUnknown: Boolean = false,
) {
    companion object {
        fun fromMap(map: Map<String, Any?>): DevicePolicy {
            fun strList(key: String): List<String> =
                (map[key] as? List<*>)?.mapNotNull { it as? String } ?: emptyList()
            return DevicePolicy(
                version = (map["version"] as? Number)?.toInt() ?: 1,
                updatedAt = map["updatedAt"] as? String ?: "",
                isolated = map["isolated"] as? Boolean ?: false,
                dnsGuardRequired = map["dnsGuardRequired"] as? Boolean ?: false,
                blockedDomains = strList("blockedDomains"),
                isolationAllowlist = strList("isolationAllowlist").ifEmpty {
                    DevicePolicy().isolationAllowlist
                },
                allowInstallUnknown = map["allowInstallUnknown"] as? Boolean ?: false,
            )
        }
    }
}

/** Apply a remote policy onto a mutable DNS blocklist (shared by TV VpnService). */
fun applyPolicyToBlocklist(policy: DevicePolicy, blocklist: DnsBlocklist) {
    if (policy.isolated) {
        blocklist.mode = DnsFilterMode.ALLOWLIST
        blocklist.replaceAll(policy.isolationAllowlist)
    } else {
        blocklist.mode = DnsFilterMode.BLOCKLIST
        if (policy.blockedDomains.isNotEmpty()) {
            blocklist.replaceAll(policy.blockedDomains)
        }
    }
}
