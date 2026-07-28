package com.bulwark.deviceapi

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.util.io.pem.PemObject
import java.io.StringReader
import java.io.StringWriter
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * Per-device Ed25519 crypto matching `src/cloud/device-api/crypto.ts`
 * (SPKI / PKCS8 PEM, Node-compatible signatures).
 */
data class DeviceKeyPair(
    val publicKeyPem: String,
    val privateKeyPem: String,
)

object DeviceCrypto {
    init {
        // Ensure BouncyCastle is available for Ed25519 KeyPairGenerator on older JDKs.
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(org.bouncycastle.jce.provider.BouncyCastleProvider())
        }
    }

    fun generateDeviceKeyPair(): DeviceKeyPair {
        // Prefer JDK Ed25519 when available (OpenJDK 15+); fall back to BC.
        val kpg = try {
            KeyPairGenerator.getInstance("Ed25519")
        } catch (_: Exception) {
            KeyPairGenerator.getInstance("Ed25519", "BC")
        }
        val kp = kpg.generateKeyPair()
        return DeviceKeyPair(
            publicKeyPem = toPem("PUBLIC KEY", kp.public.encoded),
            privateKeyPem = toPem("PRIVATE KEY", kp.private.encoded),
        )
    }

    fun sha256Hex(data: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(data.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }

    fun canonicalRequest(method: String, path: String, timestamp: String, bodyHash: String): String =
        "${method.uppercase()}\n$path\n$timestamp\n$bodyHash"

    fun signMessage(privateKeyPem: String, message: String): String {
        val privateKey = parsePrivateKey(privateKeyPem)
        val signer = Ed25519Signer()
        signer.init(true, privateKey)
        val msg = message.toByteArray(Charsets.UTF_8)
        signer.update(msg, 0, msg.size)
        return Base64.getEncoder().encodeToString(signer.generateSignature())
    }

    fun verifyMessage(publicKeyPem: String, message: String, signatureB64: String): Boolean {
        return try {
            val publicKey = parsePublicKey(publicKeyPem)
            val signer = Ed25519Signer()
            signer.init(false, publicKey)
            val msg = message.toByteArray(Charsets.UTF_8)
            signer.update(msg, 0, msg.size)
            signer.verifySignature(Base64.getDecoder().decode(signatureB64))
        } catch (_: Exception) {
            false
        }
    }

    private fun toPem(type: String, der: ByteArray): String {
        val sw = StringWriter()
        JcaPEMWriter(sw).use { it.writeObject(PemObject(type, der)) }
        return sw.toString()
    }

    private fun parsePrivateKey(pem: String): Ed25519PrivateKeyParameters {
        PEMParser(StringReader(pem)).use { parser ->
            when (val obj = parser.readObject()) {
                is PrivateKeyInfo -> {
                    val key = JcaPEMKeyConverter().setProvider("BC").getPrivateKey(obj)
                    // Extract raw 32-byte seed from PKCS8
                    val encoded = key.encoded
                    // PKCS8 Ed25519 private key ends with the 32-byte seed
                    val seed = encoded.copyOfRange(encoded.size - 32, encoded.size)
                    return Ed25519PrivateKeyParameters(seed, 0)
                }
                else -> error("unsupported private key PEM")
            }
        }
    }

    private fun parsePublicKey(pem: String): Ed25519PublicKeyParameters {
        PEMParser(StringReader(pem)).use { parser ->
            when (val obj = parser.readObject()) {
                is SubjectPublicKeyInfo -> {
                    val key = JcaPEMKeyConverter().setProvider("BC").getPublicKey(obj)
                    val encoded = key.encoded
                    // SPKI Ed25519 public key ends with the 32-byte point
                    val point = encoded.copyOfRange(encoded.size - 32, encoded.size)
                    return Ed25519PublicKeyParameters(point, 0)
                }
                else -> error("unsupported public key PEM")
            }
        }
    }
}
