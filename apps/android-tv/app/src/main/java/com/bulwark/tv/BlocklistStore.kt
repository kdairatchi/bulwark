package com.bulwark.tv

import android.content.Context
import com.bulwark.deviceapi.DnsBlocklist
import org.json.JSONArray

/**
 * Persists the local DNS blocklist used by [DnsGuardVpnService].
 */
class BlocklistStore(context: Context) {
    private val prefs = context.getSharedPreferences("bulwark_dns_blocklist", Context.MODE_PRIVATE)
    private val list = DnsBlocklist(load())

    @Synchronized
    fun blocklist(): DnsBlocklist = list

    @Synchronized
    fun add(domain: String): Boolean {
        val ok = list.add(domain)
        if (ok) persist()
        return ok
    }

    @Synchronized
    fun addAll(domains: Collection<String>): Int {
        val n = list.addAll(domains)
        if (n > 0) persist()
        return n
    }

    @Synchronized
    fun replaceAll(domains: Collection<String>) {
        list.clear()
        list.addAll(domains)
        persist()
    }

    @Synchronized
    fun size(): Int = list.size()

    @Synchronized
    fun snapshot(): Set<String> = list.snapshot()

    private fun load(): List<String> {
        val raw = prefs.getString(KEY, "[]") ?: "[]"
        return try {
            val arr = JSONArray(raw)
            (0 until arr.length()).mapNotNull { arr.optString(it, null) }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun persist() {
        val arr = JSONArray()
        list.snapshot().forEach { arr.put(it) }
        prefs.edit().putString(KEY, arr.toString()).apply()
    }

    companion object {
        private const val KEY = "domains"

        /** Starter TV-oriented demo blocklist (ad/tracker style hosts). */
        val STARTER = listOf(
            "ads.example.invalid",
            "tracker.malware.test",
            "telemetry.evil.invalid",
        )
    }
}
