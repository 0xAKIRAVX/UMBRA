package com.umbra.scanner.debug

import com.umbra.scanner.core.IpProtocol
import com.umbra.scanner.core.IpText
import com.umbra.scanner.net.WarpAccount
import com.umbra.scanner.net.WarpProbe
import com.umbra.scanner.net.WarpRegistration
import com.umbra.scanner.net.WgCrypto
import com.umbra.scanner.net.WgProtocol
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import kotlin.random.Random

/**
 * v3.12 — the single-endpoint MICROSCOPE: the "0 ALIVE, but WHY?" answer.
 *
 * Every previous honesty feature answered the question for a WHOLE scan
 * (witness gates, recovery sweeps, evidence probes). This one answers it
 * for ONE endpoint the user types in: it walks the exact probe pipeline
 * stage by stage — parse → resolve → identity → packet build → send →
 * wait → classify — TIMING each stage and dumping the raw bytes of both
 * the 148-byte WireGuard initiation and whatever came back.
 *
 * The output is deliberately raw (hex + field annotations + per-stage
 * milliseconds): the point is that "162.159.192.1:2408 silent" and
 * "socket error / icmp unreachable" and "reply type 3 cookie" are three
 * completely different worlds, and a user (or a bug report pasted into a
 * GitHub issue) can now SEE which one they are in.
 *
 * Socket semantics deliberately mirror [WarpProbe] (the live-verified
 * path): connected socket for the WG exchange, noise on a separate
 * unconnected socket to RANDOM destinations (never the target — the v3.5
 * QUIC-poisoning lesson), stray-datagram skipping, ICMP errors surfaced
 * as classifications instead of crashes.
 */
object DeepEndpointTest {

    /** Default WARP port when the input omits one. */
    const val DEFAULT_PORT = 2408

    // ------------------------------------------------------------- seams --
    // Production implementations below; JVM tests inject offline outcomes.

    /** Resolves a hostname to literal IP strings (v4 + v6). */
    @Volatile
    internal var dnsResolver: suspend (String) -> List<String> =
        { host -> resolveHost(host) }

    /** Silent identity reuse/registration, exactly like the engine's. */
    @Volatile
    internal var registrationProvider: suspend () -> WarpAccount =
        { WarpRegistration.register(null, fresh = false) }

    /**
     * The raw WG exchange: sends [packet] to ip:port after the noise burst,
     * waits [timeoutMs] skipping strays, returns the reply (or the socket
     * error class, or null = silent). [senderIndex] is only carried for the
     * report — classification of the reply happens in the pure layer.
     */
    @Volatile
    internal var udpExchange: suspend (
        ip: ByteArray, port: Int, packet: ByteArray, timeoutMs: Int, senderIndex: Int,
    ) -> UdpExchange = { ip, port, packet, timeoutMs, _ ->
        realExchange(ip, port, packet, timeoutMs)
    }

    // ------------------------------------------------------------ model --

    /** One stage of the pipeline: name, human detail, wall duration. */
    data class DeepStage(val name: String, val detail: String, val ms: Long)

    enum class DeepOutcome {
        PARSE_ERROR, DNS_FAILED, IDENTITY_FAILED, SOCKET_ERROR,
        SILENT, COOKIE_REPLY, HANDSHAKE_OK, REPLY_UNPARSEABLE,
    }

    data class DeepTestReport(
        val input: String,
        val host: String?,
        val ip: String?,
        val family: IpProtocol?,
        val port: Int,
        val stages: List<DeepStage>,
        val attemptsRun: Int,
        val outcome: DeepOutcome,
        val outcomeDetail: String,
        /** Annotated hex dump of the LAST initiation packet sent. */
        val sentHex: String?,
        /** Hex dump of the first non-stray reply received (null = none). */
        val receivedHex: String?,
        val rttMs: Long?,
        val elapsedMs: Long,
        /** consumeResponse() verified the AEAD tag — cryptographic proof. */
        val aeadVerified: Boolean,
    )

    /** Result of the raw UDP exchange — everything a socket can tell us. */
    data class UdpExchange(
        val reply: ByteArray?,
        /** null + null reply = SILENT (timeout); non-null = socket-level error. */
        val error: String?,
        val localPort: Int,
        val rttMs: Long?,
        /** Stray (non-WG-length) datagrams skipped while waiting. */
        val straysSkipped: Int,
    )

    // ------------------------------------------------------------ run ----

    suspend fun run(
        inputRaw: String,
        timeoutMs: Int = 3000,
        attempts: Int = 2,
    ): DeepTestReport {
        val started = System.currentTimeMillis()
        val stages = ArrayList<DeepStage>()

        fun stage(name: String, detail: String, from: Long) {
            stages.add(DeepStage(name, detail, System.currentTimeMillis() - from))
        }

        // 1. parse
        var from = System.currentTimeMillis()
        val parsed = parseEndpoint(inputRaw)
        if (parsed == null) {
            stage("parse", "unrecognized input \"$inputRaw\"", from)
            return report(inputRaw, null, null, null, DEFAULT_PORT, stages, 0,
                DeepOutcome.PARSE_ERROR, "expected ip · ip:port · [v6]:port · host:port",
                null, null, null, started, false)
        }
        val (host, ipText, port) = parsed
        stage("parse", "host=\"${host}\" · ip=${ipText ?: "(to resolve)"} · port $port", from)

        // 2. resolve (only when the input is a hostname)
        var ipLiteral = ipText
        if (ipLiteral == null) {
            from = System.currentTimeMillis()
            val resolved = runCatching { dnsResolver(host) }.getOrDefault(emptyList())
            ipLiteral = resolved.firstOrNull()
            stage("dns", if (ipLiteral == null) {
                "\"$host\" resolved to nothing"
            } else {
                "resolved to ${resolved.joinToString(" · ")}"
            }, from)
            if (ipLiteral == null) {
                return report(inputRaw, host, null, null, port, stages, 0,
                    DeepOutcome.DNS_FAILED, "hostname did not resolve (offline? dns blocked?)",
                    null, null, null, started, false)
            }
        }
        val ipBytes = IpText.literalToBytes(ipLiteral)
        if (ipBytes == null) {
            return report(inputRaw, host, ipLiteral, null, port, stages, 0,
                DeepOutcome.PARSE_ERROR, "\"$ipLiteral\" is not a literal IP",
                null, null, null, started, false)
        }
        val family = if (ipBytes.size == 4) IpProtocol.IPv4 else IpProtocol.IPv6

        // 3. identity (needed for any WG handshake — ghost keys are dropped
        // silently by every responder; the v3.6.1 live census)
        from = System.currentTimeMillis()
        val account = try {
            registrationProvider()
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            null
        }
        stage("identity", if (account == null) {
            "no warp identity — registration failed"
        } else {
            "identity ready · tunnel ${account.v4}"
        }, from)
        if (account == null) {
            return report(inputRaw, host, ipLiteral, family, port, stages, 0,
                DeepOutcome.IDENTITY_FAILED,
                "the handshake needs a registered key — registration api unreachable " +
                    "and no stored identity (run full diagnostics for the transport verdict)",
                null, null, null, started, false)
        }

        // 4..n — attempt loop: fresh initiation each round (fresh ephemeral,
        // fresh index, bumped timestamp — a replayed timestamp is dropped).
        val random = Random(System.nanoTime())
        var attemptsRun = 0
        var lastSentHex: String? = null
        var lastReply: ByteArray? = null
        var lastError: String? = null
        var lastRtt: Long? = null
        var lastStrays = 0
        var pendingIndex = 0
        var pending: WgProtocol.PendingHandshake? = null
        val maxAttempts = attempts.coerceIn(1, 5)
        while (attemptsRun < maxAttempts) {
            if (attemptsRun > 0) delay(250)
            attemptsRun++
            from = System.currentTimeMillis()

            pendingIndex = random.nextInt()
            val ephPriv = WgCrypto.clampScalar(ByteArray(32).also { random.nextBytes(it) })
            val (packet, pend) = WgProtocol.buildInitiation(
                account.privateKey, account.publicKey, account.responderPublicKey,
                pendingIndex, ephPriv,
            )
            pending = pend
            lastSentHex = annotateInitiation(packet)
            stage(
                "build initiation #$attemptsRun",
                "148 bytes · type 1 · sender index 0x%08x · fresh X25519 ephemeral".format(pendingIndex),
                from,
            )

            from = System.currentTimeMillis()
            val ex = udpExchange(ipBytes, port, packet, timeoutMs, pendingIndex)
            lastError = ex.error
            lastRtt = ex.rttMs
            lastStrays = ex.straysSkipped
            stage(
                "exchange #$attemptsRun",
                when {
                    ex.error != null -> "socket: ${ex.error}"
                    ex.reply == null -> "silent — no reply within $timeoutMs ms" +
                        (if (ex.straysSkipped > 0) " · ${ex.straysSkipped} stray datagram(s) skipped" else "")
                    else -> "reply ${ex.reply.size} bytes in ${ex.rttMs} ms" +
                        (if (ex.straysSkipped > 0) " · ${ex.straysSkipped} stray skipped" else "") +
                        " · local port ${ex.localPort}"
                },
                from,
            )
            lastReply = ex.reply
            if (ex.reply != null || ex.error != null) break
        }

        // 5. classify + (when a response arrived) full AEAD verification
        val outcome = classifyReply(lastReply, lastError)
        var aeadVerified = false
        var detail = outcomeDetail(outcome, lastError, pendingIndex, lastReply, attemptsRun, timeoutMs)
        if (lastReply != null && pending != null) {
            val (session, err) = WgProtocol.consumeResponse(pending, account.privateKey, lastReply)
            aeadVerified = session != null
            if (session == null && outcome == DeepOutcome.REPLY_UNPARSEABLE) {
                detail = "reply received but not a valid handshake response — $err"
            }
        }

        return report(
            inputRaw, host, ipLiteral, family, port, stages, attemptsRun,
            outcome, detail, lastSentHex,
            lastReply?.let { hexDump(it) }, lastRtt, started, aeadVerified,
        )
    }

    // ------------------------------------------------- pure parsing layer --

    /** host / literal-IP / port triple; null = unparseable. Pure. */
    internal fun parseEndpoint(input: String): Triple<String, String?, Int>? {
        val s = input.trim()
        if (s.isEmpty()) return null
        val (host, portText) = when {
            s.startsWith("[") -> {
                // bracketed IPv6 — mandatory closing bracket
                if (!s.contains("]")) return null
                val close = s.indexOf(']')
                val after = s.substring(close + 1)
                if (after.isEmpty()) s.substring(1, close) to null
                else if (after.startsWith(":") && after.length > 1)
                    s.substring(1, close) to after.substring(1)
                else return null
            }
            s.count { it == ':' } == 1 -> {
                val idx = s.indexOf(':')
                s.substring(0, idx) to s.substring(idx + 1)
            }
            // bare IPv6 literal (multiple colons, no port)
            s.count { it == ':' } > 1 -> s to null
            else -> s to null
        }
        val port = when {
            portText == null -> DEFAULT_PORT
            else -> portText.toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
        }
        // literal or hostname?
        val literal = if (host.contains(':')) host else if (host.matches(Regex("\\d{1,3}(\\.\\d{1,3}){3}"))) {
            host.split('.').map { it.toIntOrNull() ?: return null }
                .takeIf { parts -> parts.all { it in 0..255 } }?.let { host }
        } else null
        return Triple(host, literal, port)
    }

    /**
     * Buckets a raw outcome — pure function, unit-tested. Mirrors WarpProbe's
     * outcome classes (response / cookie / failed) at the byte level.
     */
    internal fun classifyReply(reply: ByteArray?, socketError: String?): DeepOutcome = when {
        socketError != null -> DeepOutcome.SOCKET_ERROR
        reply == null -> DeepOutcome.SILENT
        reply.size == WgProtocol.RESPONSE_SIZE && reply[0].toInt() == WgProtocol.MSG_RESPONSE ->
            DeepOutcome.HANDSHAKE_OK
        reply.size == WgProtocol.COOKIE_REPLY_SIZE && reply[0].toInt() == WgProtocol.MSG_COOKIE_REPLY ->
            DeepOutcome.COOKIE_REPLY
        else -> DeepOutcome.REPLY_UNPARSEABLE
    }

    /** Human verdict per outcome — pure. */
    internal fun outcomeDetail(
        outcome: DeepOutcome,
        socketError: String?,
        senderIndex: Int,
        reply: ByteArray?,
        attempts: Int,
        timeoutMs: Int,
    ): String = when (outcome) {
        DeepOutcome.HANDSHAKE_OK ->
            "wireguard handshake answered — endpoint ALIVE (receiver index echoes " +
                "0x%08x — our packet)".format(senderIndex) +
                (reply?.let { " · ${it.size} bytes type ${it[0].toInt()}" } ?: "")
        DeepOutcome.COOKIE_REPLY ->
            "cookie reply (type 3) — the endpoint ANSWERED: alive and speaking " +
                "wireguard, currently demanding a cookie (load / mac2). usually still usable"
        DeepOutcome.SILENT ->
            "no reply in ${timeoutMs} ms × $attempts attempt(s) — this endpoint is dark " +
                "on this port from THIS network · try: another port (2408/894/928/500/1701) · " +
                "the ipv6 twin · run full diagnostics for the network verdict"
        DeepOutcome.SOCKET_ERROR ->
            "socket error — ${(socketError ?: "unknown").take(160)} · " +
                "port-unreachable means something on the path actively rejected the udp " +
                "datagram; other socket errors usually mean no usable network / vpn interference"
        DeepOutcome.REPLY_UNPARSEABLE ->
            "a datagram came back but it is not a wireguard handshake response " +
                "(length ${reply?.size ?: 0}) — another service (quic?) may own this port, " +
                "or a middlebox answered"
        DeepOutcome.PARSE_ERROR -> "input not understood"
        DeepOutcome.DNS_FAILED -> "hostname did not resolve"
        DeepOutcome.IDENTITY_FAILED -> "no warp identity available"
    }

    /** Offset-prefixed hex, 16 bytes per line. [maxBytes] caps the dump. */
    internal fun hexDump(bytes: ByteArray, maxBytes: Int = 128): String {
        val shown = minOf(bytes.size, maxBytes)
        return buildString {
            for (row in 0 until shown step 16) {
                append("%04x  ".format(row))
                for (i in row until minOf(row + 16, shown)) {
                    append("%02x ".format(bytes[i]))
                }
                if (shown < bytes.size) {
                    append("· +${bytes.size - shown} bytes")
                }
                append('\n')
            }
        }.trimEnd('\n')
    }

    /**
     * Annotated dump of the 148-byte initiation: the field map a bug report
     * needs (type · sender index · ephemeral pub · encrypted static ·
     * encrypted timestamp · mac1 · mac2). Pure.
     */
    internal fun annotateInitiation(packet: ByteArray): String = buildString {
        append("type 1 (initiation) · 148 bytes\n")
        append("sender  4..7    %08x\n".format(leInt(packet, 4)))
        append("ephem   8..39   ${hexLine(packet, 8, 32)}\n")
        append("static 40..87   ${hexLine(packet, 40, 48)} (aead)\n")
        append("tstamp 88..115  ${hexLine(packet, 88, 28)} (aead)\n")
        append("mac1  116..131  ${hexLine(packet, 116, 16)}\n")
        append("mac2  132..147  ${hexLine(packet, 132, 16)} (zero — no cookie)\n")
        append("--- raw ---\n")
        append(hexDump(packet, maxBytes = 160))
    }

    private fun hexLine(b: ByteArray, from: Int, len: Int): String =
        (from until from + len).joinToString(" ") { "%02x".format(b[it]) }

    private fun leInt(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xFF) or ((b[off + 1].toInt() and 0xFF) shl 8) or
            ((b[off + 2].toInt() and 0xFF) shl 16) or ((b[off + 3].toInt() and 0xFF) shl 24)

    // ------------------------------------------------- shareable report --

    /** Multi-line plain text for the share sheet / bug reports. Pure. */
    fun formatReport(r: DeepTestReport): String = buildString {
        append("UMBRA deep endpoint test · ").append(r.input).append('\n')
        append("target  ").append(r.ip ?: "?").append(':').append(r.port)
            .append(" · ").append(r.family?.name?.lowercase() ?: "?").append('\n')
        append("outcome ").append(r.outcome.name)
            .append(r.rttMs?.let { " · rtt ${it}ms" } ?: "").append('\n')
        append("detail  ").append(r.outcomeDetail).append('\n')
        if (r.aeadVerified) append("crypto  response AEAD verified — session keys derived\n")
        append("stages:\n")
        r.stages.forEach { st ->
            append("  · ").append(st.name).append(" — ").append(st.detail)
                .append(" (").append(st.ms).append("ms)\n")
        }
        r.sentHex?.let { append("sent packet:\n").append(it).append('\n') }
        r.receivedHex?.let { append("received:\n").append(it).append('\n') }
    }

    private fun report(
        input: String, host: String?, ip: String?, family: IpProtocol?, port: Int,
        stages: List<DeepStage>, attempts: Int, outcome: DeepOutcome, detail: String,
        sentHex: String?, receivedHex: String?, rtt: Long?, started: Long, aead: Boolean,
    ) = DeepTestReport(
        input, host, ip, family, port, stages, attempts, outcome, detail,
        sentHex, receivedHex, rtt, System.currentTimeMillis() - started, aead,
    )

    // ------------------------------------------------ production sockets --

    private suspend fun resolveHost(host: String): List<String> =
        withContext(Dispatchers.IO) {
            runCatching {
                InetAddress.getAllByName(host).mapNotNull { it.hostAddress }
            }.getOrDefault(emptyList())
        }

    /**
     * The real exchange — noise burst to RANDOM destinations (v3.5 lesson:
     * never to the target — WARP ports co-host QUIC and answer garbage),
     * connected socket for the handshake, stray-skipping receive loop.
     */
    private suspend fun realExchange(
        ip: ByteArray,
        port: Int,
        packet: ByteArray,
        timeoutMs: Int,
    ): UdpExchange = withContext(Dispatchers.IO) {
        val random = Random(System.nanoTime())
        val addr = InetAddress.getByAddress(ip)
        val target = InetSocketAddress(addr, port)

        val socket = try {
            DatagramSocket().also { it.connect(target) }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            return@withContext UdpExchange(null, "bind/connect failed: ${e.javaClass.simpleName}", -1, null, 0)
        }

        // anti-DPI noise burst — own unconnected socket, random destinations
        val noiseSocket = try { DatagramSocket() } catch (_: Exception) { null }
        try {
            repeat(3) {
                val n = 50 + random.nextInt(51)
                val junk = ByteArray(n).also { random.nextBytes(it) }
                val first = random.nextInt(1, 224)
                val dest = InetSocketAddress(
                    InetAddress.getByAddress(byteArrayOf(
                        first.toByte(),
                        random.nextInt(256).toByte(),
                        random.nextInt(256).toByte(),
                        random.nextInt(256).toByte(),
                    )),
                    1024 + random.nextInt(64_512),
                )
                runCatching { noiseSocket?.send(DatagramPacket(junk, junk.size, dest)) }
                delay((1 + random.nextInt(4)).toLong())
            }

            val t0 = System.nanoTime()
            try {
                socket.send(DatagramPacket(packet, packet.size, target))
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                return@withContext UdpExchange(
                    null, "send failed: ${e.javaClass.simpleName} — " +
                        "port-unreachable = icmp rejection on the path",
                    socket.localPort, null, 0,
                )
            }

            val buf = ByteArray(2048)
            receiveLoop(socket, buf, timeoutMs, t0)
        } finally {
            runCatching { socket.close() }
            runCatching { noiseSocket?.close() }
        }
    }

    /** The stray-skipping receive loop — every terminal is a [UdpExchange]. */
    private fun receiveLoop(
        socket: DatagramSocket,
        buf: ByteArray,
        timeoutMs: Int,
        t0: Long,
    ): UdpExchange {
        var strays = 0
        val deadline = System.nanoTime() + timeoutMs * 1_000_000L
        while (true) {
            val remaining = (deadline - System.nanoTime()) / 1_000_000L
            if (remaining <= 0) return UdpExchange(null, null, socket.localPort, null, strays)
            socket.soTimeout = remaining.toInt().coerceAtLeast(1)
            val respPacket = DatagramPacket(buf, buf.size)
            try {
                socket.receive(respPacket)
            } catch (e: SocketTimeoutException) {
                return UdpExchange(null, null, socket.localPort, null, strays)
            } catch (e: Exception) {
                return UdpExchange(
                    null, "receive failed: ${e.javaClass.simpleName}",
                    socket.localPort, null, strays,
                )
            }
            val len = respPacket.length
            if (len == WgProtocol.RESPONSE_SIZE || len == WgProtocol.COOKIE_REPLY_SIZE) {
                val rtt = (System.nanoTime() - t0) / 1_000_000L
                return UdpExchange(buf.copyOf(len), null, socket.localPort, rtt, strays)
            }
            // stray datagram (co-hosted QUIC/MASQUE answer) — record & skip
            strays++
        }
    }
}
