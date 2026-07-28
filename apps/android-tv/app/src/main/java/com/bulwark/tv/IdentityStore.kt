package com.bulwark.tv

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.bulwark.deviceapi.DeviceIdentity

/**
 * Persists the device-API identity. Private key stays in EncryptedSharedPreferences
 * (Android Keystore-backed master key).
 */
class IdentityStore(context: Context) {
    private val prefs = try {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            "bulwark_device_identity",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    } catch (_: Exception) {
        // Emulators / odd keystore setups — fall back to private prefs.
        context.getSharedPreferences("bulwark_device_identity_fallback", Context.MODE_PRIVATE)
    }

    fun load(): DeviceIdentity? {
        val deviceId = prefs.getString(KEY_DEVICE_ID, null) ?: return null
        val privateKey = prefs.getString(KEY_PRIVATE, null) ?: return null
        val publicKey = prefs.getString(KEY_PUBLIC, null) ?: return null
        val serverKey = prefs.getString(KEY_SERVER, null) ?: return null
        val baseUrl = prefs.getString(KEY_BASE, null) ?: return null
        return DeviceIdentity(
            deviceId = deviceId,
            name = prefs.getString(KEY_NAME, "Android TV") ?: "Android TV",
            publicKeyPem = publicKey,
            privateKeyPem = privateKey,
            serverPublicKeyPem = serverKey,
            baseUrl = baseUrl,
            enrolledAt = prefs.getString(KEY_ENROLLED_AT, "") ?: "",
        )
    }

    fun save(identity: DeviceIdentity) {
        prefs.edit()
            .putString(KEY_DEVICE_ID, identity.deviceId)
            .putString(KEY_NAME, identity.name)
            .putString(KEY_PUBLIC, identity.publicKeyPem)
            .putString(KEY_PRIVATE, identity.privateKeyPem)
            .putString(KEY_SERVER, identity.serverPublicKeyPem)
            .putString(KEY_BASE, identity.baseUrl)
            .putString(KEY_ENROLLED_AT, identity.enrolledAt)
            .apply()
    }

    fun clear() {
        prefs.edit().clear().apply()
    }

    companion object {
        private const val KEY_DEVICE_ID = "deviceId"
        private const val KEY_NAME = "name"
        private const val KEY_PUBLIC = "publicKeyPem"
        private const val KEY_PRIVATE = "privateKeyPem"
        private const val KEY_SERVER = "serverPublicKeyPem"
        private const val KEY_BASE = "baseUrl"
        private const val KEY_ENROLLED_AT = "enrolledAt"
    }
}
