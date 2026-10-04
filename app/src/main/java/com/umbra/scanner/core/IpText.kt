package com.umbra.scanner.core

import java.net.Inet6Address
import java.net.InetAddress

object IpText {

    fun isIpv6(text: String): Boolean = text.contains(':')

    /** Parses a literal IPv4/IPv6 address to raw bytes. Never performs DNS. */
    fun literalToBytes(text: String): ByteArray? {
        val t = text.trim()
        if (t.isEmpty()) return null
        return if (t.contains(':')) {
            // A string containing ':' is always an IPv6 literal, never DNS.
            try {
                val a = InetAddress.getByName(t)
                if (a is Inet6Address) a.address else null
            } catch (e: Exception) {
                null
            }
        } else {
            val parts = t.split('.')
            if (parts.size != 4) return null
            val out = ByteArray(4)
            for (i in 0..3) {
                val p = parts[i]
                if (p.isEmpty() || p.length > 3 || (p.length > 1 && p[0] == '0')) return null
                val v = p.toIntOrNull() ?: return null
                if (v < 0 || v > 255) return null
                out[i] = v.toByte()
            }
            out
        }
    }

    /** Compact RFC-5952-ish rendering of raw address bytes. */
    fun format(bytes: ByteArray): String = when (bytes.size) {
        4 -> bytes.joinToString(".") { (it.toInt() and 0xFF).toString() }
        16 -> formatIpv6(bytes)
        else -> "?"
    }

    fun formatIpv6(b: ByteArray): String {
        val hextets = IntArray(8)
        for (i in 0 until 8) {
            hextets[i] = ((b[i * 2].toInt() and 0xFF) shl 8) or (b[i * 2 + 1].toInt() and 0xFF)
        }
        // longest zero run (>=2 hextets)
        var bestStart = -1
        var bestLen = 0
        var i = 0
        while (i < 8) {
            if (hextets[i] == 0) {
                var j = i
                while (j < 8 && hextets[j] == 0) j++
                val len = j - i
                if (len > bestLen) {
                    bestLen = len
                    bestStart = i
                }
                i = j
            } else i++
        }
        val sb = StringBuilder()
        var k = 0
        while (k < 8) {
            if (bestStart >= 0 && k == bestStart && bestLen >= 2) {
                sb.append("::")
                k += bestLen
                if (k >= 8) break
                continue
            }
            if (k > 0 && sb.isNotEmpty() && sb[sb.length - 1] != ':') sb.append(':')
            sb.append(hextets[k].toString(16))
            k++
        }
        if (sb.isEmpty()) sb.append("::")
        return sb.toString()
    }

    /** Renders an IP for URLs / configs — IPv6 gets square brackets. */
    fun forUrl(ip: String): String =
        if (isIpv6(ip) && !ip.startsWith("[")) "[$ip]" else ip

    fun familyOf(bytes: ByteArray): IpProtocol =
        if (bytes.size == 4) IpProtocol.IPv4 else IpProtocol.IPv6
}
