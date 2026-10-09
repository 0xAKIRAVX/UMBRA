package com.umbra.scanner.net

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.runInterruptible
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import kotlin.math.sqrt
import kotlin.random.Random

/**
 * REAL WARP endpoint validator — the UMBRA port of the BPB-Warp-Scanner
 * approach without xray-core:
 *
 *   UDP noise burst (optional, anti-DPI — same idea as xray's `noises`)
 *   → full WireGuard handshake for the registered account
 *   → ICMP echo request to 1.1.1.1 *inside* the encrypted tunnel
 *   → parse the echo reply
 *
 * An endpoint is only reported alive when data actually flows through the
 * WARP tunnel — exactly like BPB's generate_204-over-xray test, so the
 * results are directly usable in WireGuard / v2rayNG / Hiddify configs.
 */
data class WarpProbeStats(
    /** Total probe attempts (each = fresh handshake + ping). */
    val attempts: Int,
    /** Handshakes that completed with a valid AEAD response. */
    val handshakes: Int,
    /** Pings whose echo reply came back inside the tunnel. */
    val pings: Int,
    /** RTT (ms) of each full ping round-trip. */
    val pingLatenciesMs: List<Double>,
    /** RTT (ms) of each handshake round-trip. */
    val handshakeLatenciesMs: List<Double>,
    val cookieReplies: Int,
    val lastError: String?,
) {
    val success: Boolean get() = pings > 0

    /** BPB-style average latency of successful pings. */
    val avgPingMs: Double? get() = pingLatenciesMs.takeIf { it.isNotEmpty() }?.average()

    val jitterMs: Double?
        get() {
            val lat = pingLatenciesMs
            if (lat.size < 2) return null
            val mean = lat.average()
            val variance = lat.sumOf { (it - mean) * (it - mean) } / lat.size
            return sqrt(variance)
        }

    val loss: Double
        get() = if (attempts == 0) 1.0 else (attempts - pings).toDouble() / attempts
}

/** UDP noise config — mirrors BPB's default (5 random packets of 50-100 bytes, 1-5ms apart). */
data class UdpNoiseConfig(
    val enabled: Boolean = true,
    val count: Int = 5,
    val minPacket: Int = 50,
    val maxPacket: Int = 100,
    val minDelayMs: Int = 1,
    val maxDelayMs: Int = 5,
)

class WarpProbe(
    private val account: WarpAccount,
    private val noise: UdpNoiseConfig = UdpNoiseConfig(),
    /** Address pinged through the tunnel — Cloudflare's own anycast DNS. */
    private val pingTarget: ByteArray = byteArrayOf(1, 1, 1, 1),
) {

    /** WARP client_id (reserved bytes) — required by Cloudflare's data plane. */
    private val reserved: ByteArray = WgProtocol.warpReserved(account.reserved)

    /**
     * Probes one endpoint [attempts] times with [timeoutMs] per datagram wait.
     * Cooperatively cancellable (runInterruptible sockets). Each call builds its
     * own Random — a single WarpProbe may be shared by concurrent coroutines.
     */
    suspend fun probe(
        ip: ByteArray,
        port: Int,
        attempts: Int,
        timeoutMs: Int,
        interAttemptDelayMs: Long = 200,
    ): WarpProbeStats {
        val random = Random(System.nanoTime())
        val addr = InetAddress.getByAddress(ip)
        val target = InetSocketAddress(addr, port)
        val src = parseV4(account.v4) ?: byteArrayOf(172.toByte(), 16, 0, 2)

        val pingLat = ArrayList<Double>(attempts)
        val hsLat = ArrayList<Double>(attempts)
        var handshakes = 0
        var pings = 0
        var cookieReplies = 0
        var lastError: String? = null

        // v3.3 fix (THE WARP crash): DatagramSocket() creation and connect() can
        // throw (fd exhaustion, network torn down mid-scan). An escapee here —
        // like the old unprotected socket.send()s — used to race up through the
        // whole coroutine tree and ABORT the entire scan with "engine failure".
        // A probe that cannot even open a socket is simply a dead endpoint.
        val socket = try {
            DatagramSocket().also {
                it.soTimeout = timeoutMs
                it.connect(target)
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            return WarpProbeStats(
                attempts = attempts.coerceAtLeast(1),
                handshakes = 0,
                pings = 0,
                pingLatenciesMs = emptyList(),
                handshakeLatenciesMs = emptyList(),
                cookieReplies = 0,
                lastError = "udp ${e.javaClass.simpleName}",
            )
        }
        try {
            repeat(attempts.coerceAtLeast(1)) { attempt ->
                val outcome = try {
                    probeOnce(socket, target, src, timeoutMs, random)
                } catch (e: kotlinx.coroutines.CancellationException) {
                    throw e
                } catch (e: Exception) {
                    // belt & braces: NOTHING thrown by a single attempt may
                    // escape — a UDP error on one endpoint must never kill the
                    // remaining thousands of probes in the storm.
                    ProbeOutcome.Failed("udp ${e.javaClass.simpleName}")
                }
                when (outcome) {
                    is ProbeOutcome.Full -> {
                        handshakes++
                        pings++
                        pingLat.add(outcome.pingMs)
                        hsLat.add(outcome.hsMs)
                    }
                    is ProbeOutcome.HandshakeOnly -> {
                        handshakes++
                        hsLat.add(outcome.hsMs)
                        lastError = "handshake ok · no data plane (${outcome.reason})"
                    }
                    is ProbeOutcome.CookieReply -> cookieReplies++
                    is ProbeOutcome.Failed -> lastError = outcome.reason
                }
                if (interAttemptDelayMs > 0 && attempt < attempts - 1) {
                    delay(interAttemptDelayMs)
                }
            }
        } finally {
            runCatching { socket.close() }
        }

        return WarpProbeStats(
            attempts = attempts.coerceAtLeast(1),
            handshakes = handshakes,
            pings = pings,
            pingLatenciesMs = pingLat,
            handshakeLatenciesMs = hsLat,
            cookieReplies = cookieReplies,
            lastError = lastError,
        )
    }

    private sealed interface ProbeOutcome {
        data class Full(val hsMs: Double, val pingMs: Double) : ProbeOutcome
        data class HandshakeOnly(val hsMs: Double, val reason: String) : ProbeOutcome
        data class CookieReply(val note: String = "cookie reply — alive under load") : ProbeOutcome
        data class Failed(val reason: String) : ProbeOutcome
    }

    private suspend fun probeOnce(
        socket: DatagramSocket,
        target: InetSocketAddress,
        tunnelSrc: ByteArray,
        timeoutMs: Int,
        random: Random,
    ): ProbeOutcome {
        val buf = ByteArray(2048)

        // 1. UDP noise burst (anti-DPI) — xray `noises` equivalent.
        // v3.3 fix: noise sends to a port nobody answers can trigger ICMP
        // port-unreachable, and on a CONNECTED datagram socket the kernel
        // surfaces that as PortUnreachableException on the very next send.
        // The old unguarded send() was the #1 reason WARP scans collapsed.
        if (noise.enabled) {
            repeat(noise.count.coerceIn(1, 50)) {
                val n = noise.minPacket + random.nextInt(
                    (noise.maxPacket - noise.minPacket).coerceAtLeast(1))
                val pkt = ByteArray(n).also { random.nextBytes(it) }
                if (!sendSafe(socket, pkt, target)) {
                    return ProbeOutcome.Failed("udp send refused")
                }
                delay(noise.minDelayMs + random.nextInt(
                    (noise.maxDelayMs - noise.minDelayMs).coerceAtLeast(1)).toLong())
            }
        }

        // 2. handshake initiation (fresh ephemeral + index + timestamp)
        val senderIndex = random.nextInt()
        val ephPriv = WgCrypto.clampScalar(ByteArray(32).also { random.nextBytes(it) })
        val (initPacket, pending) = WgProtocol.buildInitiation(
            account.privateKey, account.publicKey, account.responderPublicKey,
            senderIndex, ephPriv,
            reserved = reserved,
        )

        val t0 = System.nanoTime()
        if (!sendSafe(socket, initPacket, target)) {
            return ProbeOutcome.Failed("udp send refused")
        }
        val respPacket = DatagramPacket(buf, buf.size)
        try {
            runInterruptible(Dispatchers.IO) { socket.receive(respPacket) }
        } catch (e: SocketTimeoutException) {
            return ProbeOutcome.Failed("handshake timeout")
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            return ProbeOutcome.Failed("udp ${e.javaClass.simpleName}")
        }
        val hsMs = (System.nanoTime() - t0) / 1e6
        val resp = buf.copyOf(respPacket.length)

        // 3. consume the response
        val (session, err) = WgProtocol.consumeResponse(pending, account.privateKey, resp)
        if (session == null) {
            // type 3 cookie reply still proves a live WARP endpoint (under load)
            return if (resp.size == WgProtocol.COOKIE_REPLY_SIZE &&
                WgProtocol.leInt(resp, 0) == WgProtocol.MSG_COOKIE_REPLY
            ) {
                ProbeOutcome.CookieReply()
            } else {
                ProbeOutcome.Failed(err)
            }
        }

        // 4. ICMP echo request inside the tunnel
        val ident = (random.nextInt(0x8000) or 0x8000)
        val inner = WgProtocol.icmpEchoRequest(tunnelSrc, pingTarget, ident, 1)
        val transport = session.buildTransport(inner)
        val t1 = System.nanoTime()
        if (!sendSafe(socket, transport, target)) {
            return ProbeOutcome.HandshakeOnly(hsMs, "ping send refused")
        }
        val dataPacket = DatagramPacket(buf, buf.size)
        try {
            runInterruptible(Dispatchers.IO) { socket.receive(dataPacket) }
        } catch (e: SocketTimeoutException) {
            return ProbeOutcome.HandshakeOnly(hsMs, "ping timeout")
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            return ProbeOutcome.HandshakeOnly(hsMs, "udp ${e.javaClass.simpleName}")
        }
        val pingMs = (System.nanoTime() - t1) / 1e6
        val innerReply = session.openTransport(buf.copyOf(dataPacket.length))
            ?: return ProbeOutcome.HandshakeOnly(hsMs, "bad transport reply")

        return if (WgProtocol.parseEchoReply(innerReply, ident, 1)) {
            ProbeOutcome.Full(hsMs, pingMs)
        } else {
            ProbeOutcome.HandshakeOnly(hsMs, "not our echo")
        }
    }

    /**
     * v3.3: interruptible, exception-proof datagram send. A connected UDP
     * socket throws PortUnreachableException / SocketException when the OS
     * reports ICMP errors for the destination — that is a normal, expected
     * outcome when probing thousands of random endpoints and is converted to
     * a simple false instead of being allowed to escape.
     */
    private suspend fun sendSafe(
        socket: DatagramSocket,
        data: ByteArray,
        target: InetSocketAddress,
    ): Boolean = try {
        runInterruptible(Dispatchers.IO) {
            socket.send(DatagramPacket(data, data.size, target))
        }
        true
    } catch (e: kotlinx.coroutines.CancellationException) {
        throw e
    } catch (_: Exception) {
        false
    }

    private fun parseV4(text: String): ByteArray? {
        val parts = text.trim().split('.')
        if (parts.size != 4) return null
        val bytes = parts.map { it.toIntOrNull() ?: return null }
        if (bytes.any { it !in 0..255 }) return null
        return ByteArray(4) { bytes[it].toByte() }
    }
}
