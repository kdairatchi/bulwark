package com.bulwark.tv

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import com.bulwark.deviceapi.DnsPacket
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
/**
 * Local DNS filter via VpnService. Only DNS (UDP/53) is routed into the TUN;
 * blocked names get NXDOMAIN, others are forwarded to the upstream resolver.
 *
 * Traffic alerts are counted in-process for the TV UI (and can be synced later).
 */
class DnsGuardVpnService : VpnService() {
    private var tun: ParcelFileDescriptor? = null
    private var worker: Thread? = null
    private val running = AtomicBoolean(false)
    private lateinit var blocklistStore: BlocklistStore

    override fun onCreate() {
        super.onCreate()
        blocklistStore = BlocklistStore(this)
        if (blocklistStore.size() == 0) {
            blocklistStore.addAll(BlocklistStore.STARTER)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopGuard()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> startGuard()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopGuard()
        super.onDestroy()
    }

    private fun startGuard() {
        if (running.get()) return
        // Advertise ourselves as the device DNS resolver; only that address is routed
        // into the TUN so non-DNS traffic stays on the physical network.
        val builder = Builder()
            .setSession("Bulwark DNS Guard")
            .addAddress("10.111.111.2", 32)
            .addDnsServer(LOCAL_DNS)
            .addRoute(LOCAL_DNS, 32)
            .setMtu(1500)
        tun = builder.establish() ?: return
        running.set(true)
        isRunning = true
        worker = thread(name = "bulwark-dns-guard", isDaemon = true) {
            val fd = tun ?: return@thread
            val input = FileInputStream(fd.fileDescriptor)
            val output = FileOutputStream(fd.fileDescriptor)
            val buf = ByteArray(32767)
            val upstream = InetAddress.getByName(UPSTREAM)
            while (running.get()) {
                val n = try {
                    input.read(buf)
                } catch (_: Exception) {
                    break
                }
                if (n <= 0) continue
                handleIpPacket(buf, n, output, upstream)
            }
        }
    }

    private fun stopGuard() {
        running.set(false)
        isRunning = false
        try {
            worker?.interrupt()
        } catch (_: Exception) { }
        worker = null
        try {
            tun?.close()
        } catch (_: Exception) { }
        tun = null
    }

    private fun handleIpPacket(buf: ByteArray, length: Int, output: FileOutputStream, upstream: InetAddress) {
        if (length < 28) return // IPv4 + UDP minimum
        val version = (buf[0].toInt() ushr 4) and 0x0f
        if (version != 4) return
        val ihl = (buf[0].toInt() and 0x0f) * 4
        if (length < ihl + 8) return
        val protocol = buf[9].toInt() and 0xff
        if (protocol != 17) return // UDP only
        val destPort = ((buf[ihl + 2].toInt() and 0xff) shl 8) or (buf[ihl + 3].toInt() and 0xff)
        if (destPort != 53) return

        val dnsOffset = ihl + 8
        val dnsLen = length - dnsOffset
        if (dnsLen < 12) return
        val dns = buf.copyOfRange(dnsOffset, length)
        val query = DnsPacket.parseQuery(dns, dnsLen) ?: return
        queries.incrementAndGet()

        val blocked = blocklistStore.blocklist().isBlocked(query.qname)
        val responseDns: ByteArray = if (blocked) {
            blocks.incrementAndGet()
            lastBlockedHost = query.qname
            AgentEvents.dnsBlocked(query.qname)
            DnsPacket.buildNxDomain(dns, query)
        } else {
            forwardDns(dns, dnsLen, upstream) ?: return
        }

        val reply = buildUdpIpv4Reply(buf, ihl, responseDns) ?: return
        try {
            output.write(reply)
        } catch (_: Exception) { }
    }

    private fun forwardDns(dns: ByteArray, dnsLen: Int, upstream: InetAddress): ByteArray? {
        return try {
            DatagramSocket().use { socket ->
                protect(socket)
                socket.soTimeout = 2_500
                val req = DatagramPacket(dns, dnsLen, upstream, 53)
                socket.send(req)
                val respBuf = ByteArray(4096)
                val resp = DatagramPacket(respBuf, respBuf.size)
                socket.receive(resp)
                respBuf.copyOf(resp.length)
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun buildUdpIpv4Reply(request: ByteArray, ihl: Int, dnsPayload: ByteArray): ByteArray? {
        val totalLen = ihl + 8 + dnsPayload.size
        if (totalLen > 32767) return null
        val out = ByteArray(totalLen)
        // Copy IP header then swap src/dst
        System.arraycopy(request, 0, out, 0, ihl)
        // total length
        out[2] = ((totalLen ushr 8) and 0xff).toByte()
        out[3] = (totalLen and 0xff).toByte()
        // swap addresses (bytes 12-15 <-> 16-19)
        for (i in 0 until 4) {
            val a = out[12 + i]
            out[12 + i] = out[16 + i]
            out[16 + i] = a
        }
        // TTL
        out[8] = 64
        // clear checksum then recompute
        out[10] = 0
        out[11] = 0
        val ipChecksum = checksum(out, 0, ihl)
        out[10] = ((ipChecksum ushr 8) and 0xff).toByte()
        out[11] = (ipChecksum and 0xff).toByte()

        // UDP header: swap ports
        val srcPort0 = request[ihl]
        val srcPort1 = request[ihl + 1]
        out[ihl] = request[ihl + 2]
        out[ihl + 1] = request[ihl + 3]
        out[ihl + 2] = srcPort0
        out[ihl + 3] = srcPort1
        val udpLen = 8 + dnsPayload.size
        out[ihl + 4] = ((udpLen ushr 8) and 0xff).toByte()
        out[ihl + 5] = (udpLen and 0xff).toByte()
        out[ihl + 6] = 0
        out[ihl + 7] = 0
        System.arraycopy(dnsPayload, 0, out, ihl + 8, dnsPayload.size)
        // Optional UDP checksum left 0 (allowed for IPv4)
        return out
    }

    private fun checksum(buf: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        while (i < offset + length - 1) {
            sum += ((buf[i].toInt() and 0xff) shl 8) or (buf[i + 1].toInt() and 0xff)
            i += 2
        }
        if (length % 2 != 0) {
            sum += (buf[offset + length - 1].toInt() and 0xff) shl 8
        }
        while (sum ushr 16 != 0) {
            sum = (sum and 0xffff) + (sum ushr 16)
        }
        return sum.inv() and 0xffff
    }

    companion object {
        const val ACTION_STOP = "com.bulwark.tv.DNS_GUARD_STOP"
        const val UPSTREAM = "1.1.1.1"
        const val LOCAL_DNS = "10.111.111.3"

        @Volatile var isRunning: Boolean = false
            private set
        val queries = AtomicInteger(0)
        val blocks = AtomicInteger(0)
        @Volatile var lastBlockedHost: String? = null

        fun prepareIntent(context: android.content.Context): Intent? = prepare(context)

        fun start(context: android.content.Context) {
            context.startService(Intent(context, DnsGuardVpnService::class.java))
        }

        fun stop(context: android.content.Context) {
            context.startService(
                Intent(context, DnsGuardVpnService::class.java).setAction(ACTION_STOP),
            )
        }

        fun trafficSummary(): Map<String, Any?> = mapOf(
            "running" to isRunning,
            "queries" to queries.get(),
            "blocks" to blocks.get(),
            "lastBlockedHost" to lastBlockedHost,
        )
    }
}
