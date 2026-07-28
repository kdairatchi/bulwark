package com.bulwark.tv

import android.content.Context
import com.bulwark.deviceapi.DevicePolicy
import com.bulwark.deviceapi.DnsBlocklist
import com.bulwark.deviceapi.DnsFilterMode
import com.bulwark.deviceapi.applyPolicyToBlocklist
import org.json.JSONArray
import org.json.JSONObject

/**
 * Persists DNS blocklist + last applied remote policy for the TV agent.
 */
class BlocklistStore(context: Context) {
    private val prefs = context.getSharedPreferences("bulwark_dns_blocklist", Context.MODE_PRIVATE)
    private val list = DnsBlocklist(loadDomains())

    init {
        val modeName = prefs.getString(KEY_MODE, DnsFilterMode.BLOCKLIST.name)
        list.mode = runCatching { DnsFilterMode.valueOf(modeName!!) }.getOrDefault(DnsFilterMode.BLOCKLIST)
    }

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
        list.replaceAll(domains)
        persist()
    }

    @Synchronized
    fun applyPolicy(policy: DevicePolicy) {
        applyPolicyToBlocklist(policy, list)
        prefs.edit()
            .putString(KEY_POLICY, policyToJson(policy).toString())
            .apply()
        persist()
    }

    @Synchronized
    fun loadPolicy(): DevicePolicy? {
        val raw = prefs.getString(KEY_POLICY, null) ?: return null
        return try {
            DevicePolicy.fromMap(jsonToMap(JSONObject(raw)))
        } catch (_: Exception) {
            null
        }
    }

    @Synchronized
    fun isIsolated(): Boolean = list.mode == DnsFilterMode.ALLOWLIST || loadPolicy()?.isolated == true

    @Synchronized
    fun size(): Int = list.size()

    @Synchronized
    fun snapshot(): Set<String> = list.snapshot()

    @Synchronized
    fun mode(): DnsFilterMode = list.mode

    private fun loadDomains(): List<String> {
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
        prefs.edit()
            .putString(KEY, arr.toString())
            .putString(KEY_MODE, list.mode.name)
            .apply()
    }

    private fun policyToJson(p: DevicePolicy): JSONObject = JSONObject()
        .put("version", p.version)
        .put("updatedAt", p.updatedAt)
        .put("isolated", p.isolated)
        .put("dnsGuardRequired", p.dnsGuardRequired)
        .put("allowInstallUnknown", p.allowInstallUnknown)
        .put("blockedDomains", JSONArray(p.blockedDomains))
        .put("isolationAllowlist", JSONArray(p.isolationAllowlist))

    private fun jsonToMap(obj: JSONObject): Map<String, Any?> {
        val map = linkedMapOf<String, Any?>()
        val keys = obj.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            val v = obj.get(k)
            map[k] = when (v) {
                is JSONArray -> (0 until v.length()).map { v.get(it) }
                JSONObject.NULL -> null
                else -> v
            }
        }
        return map
    }

    companion object {
        private const val KEY = "domains"
        private const val KEY_MODE = "mode"
        private const val KEY_POLICY = "policy"

        val STARTER = listOf(
            "ads.example.invalid",
            "tracker.malware.test",
            "telemetry.evil.invalid",
        )
    }
}
