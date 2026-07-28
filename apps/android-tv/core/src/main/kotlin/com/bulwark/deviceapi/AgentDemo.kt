package com.bulwark.deviceapi

/**
 * JVM hello-world for the Android TV agent core against a running control plane:
 *   npm run cloud:dev
 *   ./gradlew :core:runAgentDemo
 *
 * Flow: create pairing code → enroll Ed25519 device → issue is done by this demo
 * as "dashboard" → poll → verify → execute stub → post result.
 */
fun main(args: Array<String>) {
    val base = args.firstOrNull()
        ?: System.getenv("DEVICE_API_URL")
        ?: "http://127.0.0.1:8787"
    val client = DeviceApiClient(base)

    val (code, _) = client.createPairingCode()
    println("1. pairing code: $code")

    val keys = DeviceCrypto.generateDeviceKeyPair()
    val enrolled = client.enroll(
        code = code,
        name = "Living Room TV",
        publicKeyPem = keys.publicKeyPem,
        os = "Android TV 14 (agent-demo)",
    )
    println("2. enrolled: ${enrolled.deviceId}")

    val serverKey = client.getServerKey()
    println("3. cached server public key (pem length ${serverKey.length})")

    val identity = DeviceIdentity(
        deviceId = enrolled.deviceId,
        name = "Living Room TV",
        publicKeyPem = keys.publicKeyPem,
        privateKeyPem = keys.privateKeyPem,
        serverPublicKeyPem = serverKey,
        baseUrl = base,
        enrolledAt = enrolled.enrolledAt,
    )

    // Dashboard-side enqueue via unsigned POST (same as command-demo.mjs)
    val issueConn = (java.net.URL("$base/v1/devices/${identity.deviceId}/commands").openConnection() as java.net.HttpURLConnection).apply {
        requestMethod = "POST"
        doOutput = true
        setRequestProperty("Content-Type", "application/json")
        outputStream.write("""{"type":"RUN_MALWARE_SCAN","parameters":{"scope":"quick"}}""".toByteArray())
    }
    val issueStatus = issueConn.responseCode
    issueConn.disconnect()
    println("4. dashboard issued status=$issueStatus")

    client.heartbeat(identity)
    println("5. heartbeat ok")

    val commands = client.pollCommands(identity)
    println("6. polled ${commands.size} command(s)")
    require(commands.isNotEmpty()) { "expected a pending command" }

    val seen = mutableSetOf<String>()
    val cmd = commands.first()
    val (accepted, result) = CommandExecutor.process(
        serverPublicKeyPem = identity.serverPublicKeyPem,
        deviceId = identity.deviceId,
        cmd = cmd,
        seenNonces = seen,
    )
    println("7. verified+executed accepted=$accepted type=${cmd.type}")
    require(accepted) { "command rejected: $result" }

    client.postCommandResult(identity, cmd.commandId, result)
    println("8. result posted: $result")

    // Inventory sample (sideload-shaped) — same shape as device-client-demo.
    client.submitInventory(
        identity,
        mapOf(
            "apps" to listOf(
                mapOf(
                    "packageName" to "com.example.sideload",
                    "label" to "Mystery APK",
                    "installer" to "com.android.packageinstaller",
                    "sideloaded" to true,
                ),
                mapOf(
                    "packageName" to "com.netflix.ninja",
                    "label" to "Netflix",
                    "installer" to "com.android.vending",
                    "sideloaded" to false,
                ),
            ),
            "count" to 2,
        ),
    )
    client.submitFindings(
        identity,
        listOf(
            mapOf(
                "level" to "likely_affected",
                "subjectName" to "com.example.sideload",
                "reason" to "Sideloaded app (installer is not a trusted store)",
            ),
        ),
    )
    println("9. inventory + findings submitted")

    // Posture + DNS blocklist (core library — same logic the TV app uses)
    val apps = listOf(
        AppRecord(
            packageName = "com.example.sideload",
            sideloaded = true,
            permissions = listOf("android.permission.RECORD_AUDIO", "android.permission.REQUEST_INSTALL_PACKAGES"),
            apkSha256 = "deadbeef",
            certSha256 = "cafebabe",
        ),
    )
    val health = AppPosture.healthAssessment(apps)
    println("10. posture score=${health["score"]} findings=${health["findingCount"]}")
    val bl = DnsBlocklist(listOf("tracker.malware.test"))
    println("11. dns blocklist blocks tracker.malware.test=${bl.isBlocked("sub.tracker.malware.test")}")
    println("DONE")
}
