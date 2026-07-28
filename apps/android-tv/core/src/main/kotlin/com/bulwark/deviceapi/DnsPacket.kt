package com.bulwark.deviceapi

/**
 * Minimal DNS message helpers for the local VpnService filter.
 * Parses QNAME from a standard UDP DNS query and builds an NXDOMAIN reply.
 */
object DnsPacket {
    data class Query(
        val id: Int,
        val qname: String,
        val qtype: Int,
        val qclass: Int,
        /** Offset where the question section ends (start of answers). */
        val questionEnd: Int,
    )

    fun parseQuery(packet: ByteArray, length: Int = packet.size): Query? {
        if (length < 12) return null
        val id = ((packet[0].toInt() and 0xff) shl 8) or (packet[1].toInt() and 0xff)
        val flags = ((packet[2].toInt() and 0xff) shl 8) or (packet[3].toInt() and 0xff)
        // QR bit must be 0 (query)
        if ((flags and 0x8000) != 0) return null
        val qdCount = ((packet[4].toInt() and 0xff) shl 8) or (packet[5].toInt() and 0xff)
        if (qdCount < 1) return null

        var i = 12
        val labels = mutableListOf<String>()
        while (i < length) {
            val len = packet[i].toInt() and 0xff
            if (len == 0) {
                i++
                break
            }
            // Compression pointers are unusual in questions from stub resolvers; reject for safety.
            if ((len and 0xc0) == 0xc0) return null
            if (i + 1 + len > length) return null
            labels += String(packet, i + 1, len, Charsets.US_ASCII)
            i += 1 + len
        }
        if (i + 4 > length) return null
        val qtype = ((packet[i].toInt() and 0xff) shl 8) or (packet[i + 1].toInt() and 0xff)
        val qclass = ((packet[i + 2].toInt() and 0xff) shl 8) or (packet[i + 3].toInt() and 0xff)
        return Query(
            id = id,
            qname = labels.joinToString(".").lowercase(),
            qtype = qtype,
            qclass = qclass,
            questionEnd = i + 4,
        )
    }

    /** Build a response that copies the question and sets RCODE=NXDOMAIN (3). */
    fun buildNxDomain(queryPacket: ByteArray, query: Query): ByteArray {
        val out = queryPacket.copyOf(query.questionEnd)
        // Flags: QR=1, Opcode copy, AA=0, RD copy, RA=0, RCODE=3
        val rd = queryPacket[2].toInt() and 0x01
        out[2] = (0x80 or rd).toByte() // QR + RD
        out[3] = 0x03 // RCODE NXDOMAIN
        // ANCOUNT/NSCOUNT/ARCOUNT = 0
        out[6] = 0; out[7] = 0
        out[8] = 0; out[9] = 0
        out[10] = 0; out[11] = 0
        return out
    }
}
