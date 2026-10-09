package com.umbra.scanner.net

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runInterruptible
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException

/**
 * v3.6.2 — independent UDP-egress evidence for negative WARP verdicts.
 *
 * A gate that reports "warp unreachable" with zero handshake replies is
 * honest but incomplete: the user cannot tell whether (a) ALL udp is
 * blocked on this network, (b) udp works generally but Cloudflare's
 * network is filtered, or (c) udp reaches Cloudflare fine and only WARP's
 * ranges/ports are selectively dropped. Those three worlds have three
 * different remedies (switch network / EDGE mode / IPv6), so the verdict
 * must carry the distinction.
 *
 * NTP (:123) is the ideal witness protocol:
 *  - trivial 48-byte fixed request, any reply proves a real round-trip
 *  - almost never filtered by consumer ISPs (unlike VPN-looking traffic)
 *  - 162.159.200.1 (time.cloudflare.com) sits in Cloudflare's network,
 *    adjacent to the WARP ranges — a reply there plus WG silence pins the
 *    filtering to WARP's specific ranges/ports
 *  - 216.239.35.0 (Google NTP) is a non-Cloudflare control witness
 *
 * Both literals verified live 2026-10-10. Probes run only when the gate is
 * about to publish a negative verdict — never on healthy scans.
 */
object UdpEvidence {

    /** time.cloudflare.com — Cloudflare-network NTP witness. */
    internal val CF_NTP: ByteArray =
        byteArrayOf(162.toByte(), 159.toByte(), 200.toByte(), 1)

    /** Google NTP — non-Cloudflare control witness. */
    internal val OTHER_NTP: ByteArray =
        byteArrayOf(216.toByte(), 239.toByte(), 35.toByte(), 0)

    data class Evidence(
        /** UDP round-trip INSIDE Cloudflare's network succeeded. */
        val cloudflareNtp: Boolean,
        /** UDP round-trip to a non-Cloudflare host succeeded. */
        val otherNtp: Boolean,
    )

    /** Test seam — injects outcomes without sockets. */
    internal var ntpProber: suspend (ip: ByteArray, timeoutMs: Int) -> Boolean =
        { ip, timeoutMs -> ntpProbe(ip, timeoutMs) }

    /** Probes both witnesses in parallel; never throws. */
    suspend fun gather(timeoutMs: Int = 1500): Evidence = coroutineScope {
        val cf = async(Dispatchers.IO) {
            runCatching { ntpProber(CF_NTP, timeoutMs) }.getOrDefault(false)
        }
        val other = async(Dispatchers.IO) {
            runCatching { ntpProber(OTHER_NTP, timeoutMs) }.getOrDefault(false)
        }
        Evidence(cf.await(), other.await())
    }

    /** One NTP request/reply exchange. False on timeout/any error. */
    internal suspend fun ntpProbe(ip: ByteArray, timeoutMs: Int): Boolean =
        runInterruptible(Dispatchers.IO) {
            runCatching {
                val socket = DatagramSocket()
                try {
                    socket.soTimeout = timeoutMs.coerceIn(300, 5000)
                    socket.connect(InetSocketAddress(InetAddress.getByAddress(ip), 123))
                    // NTPv3 client packet: LI=0, VN=3, Mode=3 (client)
                    val req = ByteArray(48).also { it[0] = 0x1B }
                    socket.send(DatagramPacket(req, req.size))
                    val buf = ByteArray(64)
                    val resp = DatagramPacket(buf, buf.size)
                    socket.receive(resp)
                    resp.length >= 48
                } catch (e: SocketTimeoutException) {
                    false
                } catch (e: kotlinx.coroutines.CancellationException) {
                    throw e
                } catch (e: Exception) {
                    false
                } finally {
                    runCatching { socket.close() }
                }
            }.getOrDefault(false)
        }

    /**
     * Human-readable diagnosis for a scan that saw zero WG replies.
     * Only called by the gate on the way to a negative verdict.
     */
    fun describe(e: Evidence): String = when {
        e.cloudflareNtp ->
            "udp witness: time.cloudflare.com :123 REPLIED — udp to cloudflare's " +
                "network works, so WARP's ranges/ports are SELECTIVELY filtered here; " +
                "v6 warp or EDGE (tcp 443) are the usable paths"
        e.otherNtp ->
            "udp witness: external ntp replied but cloudflare's network stayed " +
                "silent — this network udp-filters cloudflare as a whole; try EDGE mode " +
                "(tcp 443, tls-verified) or a different network"
        else ->
            "udp witness: even ntp is dead — there is NO udp egress on this network " +
                "at all (or the active vpn drops it); warp cannot work here, EDGE mode " +
                "still can"
    }
}
