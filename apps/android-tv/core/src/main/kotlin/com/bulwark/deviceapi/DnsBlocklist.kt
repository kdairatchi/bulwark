package com.bulwark.deviceapi

/**
 * Local DNS threat blocklist — exact host + parent-domain matching.
 * Fed by UPDATE_THREAT_FEEDS / BLOCK_DOMAIN commands and used by the TV VpnService.
 */
class DnsBlocklist(
    initial: Collection<String> = emptyList(),
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

    fun size(): Int = domains.size

    fun snapshot(): Set<String> = domains.toSet()

    fun isBlocked(hostname: String): Boolean {
        val host = normalize(hostname) ?: return false
        if (host in domains) return true
        // Block subdomains of listed parents: evil.tracker.example matches tracker.example
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
