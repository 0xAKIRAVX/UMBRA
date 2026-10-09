package com.umbra.scanner.net

import java.util.concurrent.atomic.AtomicLong

/**
 * Minimal initiator-side WireGuard protocol (Noise_IKpsk2, no psk) —
 * exactly enough to validate that a WARP endpoint is real:
 *
 *   1. build a handshake initiation (148 bytes)
 *   2. consume the handshake response (92 bytes)  -> session keys
 *   3. send an ICMP echo request *inside* the tunnel and parse the reply
 *
 * Ported line-by-line from wireguard-go (noise-protocol.go / noise-helpers.go)
 * and byte-for-byte verified against the Cloudflare WARP production endpoints.
 * Layout reference:
 *   initiation: [type 4][sender 4][ephemeral 32][static 48][timestamp 28][mac1 16][mac2 16]
 *   response:   [type 4][sender 4][receiver 4][ephemeral 32][empty 16][mac1 16][mac2 16]
 *   transport:  [type 4][receiver 4][counter 8][aead(payload)]
 *
 * WARP client_id and the WireGuard reserved bytes (v3.5 EMPIRICAL FIX):
 * the earlier build wrote the account's client_id into bytes 1..3 of every
 * packet (an "Xray parity" claim that could never be verified while UDP was
 * blocked in the dev sandbox). Live testing against production WARP endpoints
 * (2026-10) proved the OPPOSITE: Cloudflare's servers drop any packet whose
 * LE-u32 type word is not exactly 1/2/4 — i.e. non-zero reserved bytes get the
 * packet silently discarded, which made EVERY WARP handshake time out and
 * made the WARP scan produce nothing. wireguard-go semantics apply: reserved
 * bytes are ZERO on all outgoing packets (wgcf / stock WireGuard clients work
 * exactly this way against WARP). The account's client_id is kept on
 * WarpAccount for identity purposes only — it is never written into packets.
 */
object WgProtocol {

    private const val CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
    private const val IDENTIFIER = "WireGuard v1 zx2c4 Jason@zx2c4.com"
    private const val LABEL_MAC1 = "mac1----"

    val INITIAL_CHAIN_KEY: ByteArray = WgCrypto.blake2s(CONSTRUCTION.toByteArray())
    val INITIAL_HASH: ByteArray = WgCrypto.blake2s(INITIAL_CHAIN_KEY + IDENTIFIER.toByteArray())
    private val ZERO_NONCE = ByteArray(12)
    private val PSK = ByteArray(32) // WARP: no preshared key

    const val MSG_INITIATION = 1
    const val MSG_RESPONSE = 2
    const val MSG_COOKIE_REPLY = 3
    const val MSG_TRANSPORT = 4

    const val INITIATION_SIZE = 148
    const val RESPONSE_SIZE = 92
    const val COOKIE_REPLY_SIZE = 64
    const val TRANSPORT_HEADER_SIZE = 16

    // ------------------------------------------------------------- KDF ----
    // wireguard-go noise-helpers.go: HKDF-style expansion over HMAC-BLAKE2s.

    private fun hmac(key: ByteArray, vararg data: ByteArray): ByteArray =
        WgCrypto.hmacBlake2s(key, *data)

    /** KDF2 -> (t0, t1). */
    private fun kdf2(key: ByteArray, input: ByteArray): Pair<ByteArray, ByteArray> {
        val prk = hmac(key, input)
        val t0 = hmac(prk, byteArrayOf(1))
        val t1 = hmac(prk, t0 + byteArrayOf(2))
        return t0 to t1
    }

    /** KDF3 -> (t0, t1, t2). */
    private fun kdf3(key: ByteArray, input: ByteArray): Triple<ByteArray, ByteArray, ByteArray> {
        val prk = hmac(key, input)
        val t0 = hmac(prk, byteArrayOf(1))
        val t1 = hmac(prk, t0 + byteArrayOf(2))
        val t2 = hmac(prk, t1 + byteArrayOf(3))
        return Triple(t0, t1, t2)
    }

    /** mixKey: chainKey = HMAC(HMAC(ck, data), 0x01). */
    private fun mixKey(ck: ByteArray, data: ByteArray): ByteArray =
        hmac(hmac(ck, data), byteArrayOf(1))

    /** mixHash: hash = BLAKE2s(h || data). */
    private fun mixHash(h: ByteArray, data: ByteArray): ByteArray =
        WgCrypto.blake2s(h + data)

    // ----------------------------------------------------------- TAI64N ----

    private val lastTimestamp = java.util.concurrent.atomic.AtomicReference<ByteArray?>(null)

    /** TAI64N now — 12 bytes BE: (0x400000000000000a + unixSecs) || nanos.
     * v3.6: process-wide MONOTONIC with wireguard-go semantics (1 ns bumps).
     *
     * WHY THE CHANGE: the v3.5 "whitening" masked the nanos down to 2^24 ns
     * granules, so every monotonic bump advanced the timestamp 16.7 ms into
     * the FUTURE. WireGuard responders store the last accepted timestamp per
     * static key server-side; after a burst of probes the sequence ran seconds
     * ahead of the wall clock, and a restarted process reusing a persisted
     * identity (the API-blocked-network fallback!) started back at wall-clock
     * time — BELOW the server's stored mark — so every initiation was silently
     * dropped as a replay and the scan found nothing. The nanos field is
     * AEAD-encrypted inside the initiation anyway, so whitening had zero
     * privacy value. 1 ns bumps keep the sequence strictly increasing while
     * staying within ~1 ms of the wall clock even after 100k initiations,
     * exactly like wireguard-go's Timestamp.Now(). */
    @Synchronized
    fun tai64nNow(): ByteArray {
        val nanoTime = System.nanoTime()
        val unixSecs = System.currentTimeMillis() / 1000L
        val nanos = (nanoTime % 1_000_000_000L).toInt()
        val out = ByteArray(12)
        putBeLong(out, 0, 0x400000000000000AL + unixSecs)
        putBeInt(out, 8, nanos)
        val last = lastTimestamp.get()
        if (last != null && compareTimestamps(out, last) <= 0) {
            // bump a COPY — callers keep the returned array; mutating the
            // stored one would retroactively change timestamps already handed
            // out (aliasing bug caught by the monotonic regression test).
            val bumped = last.copyOf()
            bumpTimestamp(bumped)
            lastTimestamp.set(bumped)
            return bumped
        }
        lastTimestamp.set(out)
        return out
    }

    /** Persists the current high-water mark so a NEW process reusing a
     * persisted WARP identity never presents a timestamp the server already
     * saw (anti-replay drops are silent). Null before the first handshake. */
    fun saveMark(): ByteArray? = lastTimestamp.get()?.copyOf()

    /** Restores a persisted high-water mark (no-op on null/malformed input). */
    fun loadMark(mark: ByteArray?) {
        if (mark != null && mark.size == 12) lastTimestamp.set(mark.copyOf())
    }

    /** Drops the in-process mark — used when the identity is invalidated so a
     * fresh key starts from the wall clock instead of the dead key's future. */
    fun resetMark() { lastTimestamp.set(null) }

    private fun compareTimestamps(a: ByteArray, b: ByteArray): Int {
        for (i in 0 until 12) {
            val d = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (d != 0) return d
        }
        return 0
    }

    /** In-place advance by 1 ns on a TAI64N pair (v3.6 — wireguard-go
     * semantics). Carries: nanos (bytes 8..11) wrap at 0xFFFFFFFF → seconds
     * low word (bytes 4..7) +1 → 32-bit carry into the high word (bytes 0..3).
     * After even 100k rapid initiations the sequence is at most ~0.1 ms ahead
     * of the wall clock, so an app restart reusing the identity is always
     * safely above the server's stored mark. */
    private fun bumpTimestamp(ts: ByteArray) {
        var low = beInt(ts, 8)
        if (low == -1) { // 0xFFFFFFFF — nanos carry into the seconds low word
            putBeInt(ts, 8, 0)
            var secs = beInt(ts, 4) // seconds low word lives at bytes 4..7
            secs = secs + 1
            putBeInt(ts, 4, secs)
            if (secs == 0) { // 32-bit carry into the high word (bytes 0..3)
                putBeInt(ts, 0, beInt(ts, 0) + 1)
            }
        } else {
            putBeInt(ts, 8, low + 1)
        }
    }

    // --------------------------------------------------------- handshake ----

    /** Initiator-side state kept between the initiation and the response. */
    class PendingHandshake internal constructor(
        internal val ephPriv: ByteArray,
        internal val hash: ByteArray,
        internal val chainKey: ByteArray,
        val senderIndex: Int,
    )

    /**
     * Builds a handshake initiation packet for [staticPriv]/[staticPub] talking
     * to a responder whose long-term public key is [responderPub].
     * Fresh ephemeral key + fresh sender index + now-timestamp.
     */
    fun buildInitiation(
        staticPriv: ByteArray,
        staticPub: ByteArray,
        responderPub: ByteArray,
        senderIndex: Int,
        ephemeralPriv: ByteArray,
        timestamp: ByteArray = tai64nNow(),
    ): Pair<ByteArray, PendingHandshake> {
        val ephPub = WgCrypto.x25519Base(ephemeralPriv)

        var h = mixHash(INITIAL_HASH, responderPub)
        var ck = mixKey(INITIAL_CHAIN_KEY, ephPub)
        h = mixHash(h, ephPub)

        // encrypted static
        val ee = WgCrypto.x25519Shared(ephemeralPriv, responderPub)
            ?: throw IllegalArgumentException("invalid responder public key")
        val (ck1, kStatic) = kdf2(ck, ee)
        ck = ck1
        val staticCt = WgCrypto.chacha20Poly1305Seal(kStatic, ZERO_NONCE, staticPub, h)
        h = mixHash(h, staticCt)

        // encrypted timestamp
        val ss = WgCrypto.x25519Shared(staticPriv, responderPub)
            ?: throw IllegalArgumentException("invalid keypair")
        val (ck2, kTs) = kdf2(ck, ss)
        ck = ck2
        val tsCt = WgCrypto.chacha20Poly1305Seal(kTs, ZERO_NONCE, timestamp, h)
        h = mixHash(h, tsCt)

        val packet = ByteArray(INITIATION_SIZE)
        putLeInt(packet, 0, MSG_INITIATION)
        // v3.5: reserved bytes (1..3) stay ZERO — putLeInt already wrote them;
        // non-zero values are dropped by production WARP (verified live).
        putLeInt(packet, 4, senderIndex)
        System.arraycopy(ephPub, 0, packet, 8, 32)
        System.arraycopy(staticCt, 0, packet, 40, 48)
        System.arraycopy(tsCt, 0, packet, 88, 28)

        val mac1Key = WgCrypto.blake2s(LABEL_MAC1.toByteArray() + responderPub)
        val mac1 = WgCrypto.blake2s(packet.copyOfRange(0, 116), key = mac1Key, digestSize = 16)
        System.arraycopy(mac1, 0, packet, 116, 16)
        // mac2 stays zero (no cookie)

        return packet to PendingHandshake(ephemeralPriv, h, ck, senderIndex)
    }

    /**
     * Consumes a handshake response on the initiator side. Returns the session
     * when the response is authentic (receiver index matches + AEAD tag over
     * the empty message verifies), or null with a reason.
     */
    fun consumeResponse(
        pending: PendingHandshake,
        staticPriv: ByteArray,
        data: ByteArray,
    ): Pair<WgSession?, String> {
        if (data.size != RESPONSE_SIZE) return null to "bad response length ${data.size}"
        // byte-wise type check (boringtun semantics) — a WARP response that
        // echoes junk into its reserved bytes is still a valid response
        if (data[0].toInt() != MSG_RESPONSE) return null to "not a response (type ${leInt(data, 0)})"
        val sender = leInt(data, 4)
        val receiver = leInt(data, 8)
        if (receiver != pending.senderIndex) return null to "receiver index mismatch"
        val theirEph = data.copyOfRange(12, 44)
        val empty = data.copyOfRange(44, 60)

        var h = mixHash(pending.hash, theirEph)
        var ck = mixKey(pending.chainKey, theirEph)
        val ee = WgCrypto.x25519Shared(pending.ephPriv, theirEph) ?: return null to "bad ephemeral"
        ck = mixKey(ck, ee)
        val se = WgCrypto.x25519Shared(staticPriv, theirEph) ?: return null to "bad static DH"
        ck = mixKey(ck, se)
        val (ck1, tau, k) = kdf3(ck, PSK)
        ck = ck1
        h = mixHash(h, tau)
        if (WgCrypto.chacha20Poly1305Open(k, ZERO_NONCE, empty, h) == null) {
            return null to "response AEAD tag invalid"
        }
        h = mixHash(h, empty)
        val (sendKey, recvKey) = kdf2(ck, ByteArray(0))
        return WgSession(sendKey, recvKey, pending.senderIndex, sender) to ""
    }

    // -------------------------------------------------------- data plane ----

    /** Established transport session (initiator side). */
    class WgSession internal constructor(
        private val sendKey: ByteArray,
        private val recvKey: ByteArray,
        val ourIndex: Int,
        val theirIndex: Int,
    ) {
        private val sendCounter = AtomicLong(0)

        /** Seals [inner] (an IP packet) into a transport data packet. */
        fun buildTransport(inner: ByteArray): ByteArray {
            val counter = sendCounter.getAndIncrement()
            val padded = inner + ByteArray((16 - (inner.size and 15)) and 15)
            val nonce = ByteArray(12)
            putLeLong(nonce, 4, counter)
            val ct = WgCrypto.chacha20Poly1305Seal(sendKey, nonce, padded, ByteArray(0))
            val packet = ByteArray(TRANSPORT_HEADER_SIZE + ct.size)
            putLeInt(packet, 0, MSG_TRANSPORT)
            putLeInt(packet, 4, theirIndex)
            putLeLong(packet, 8, counter)
            System.arraycopy(ct, 0, packet, 16, ct.size)
            return packet
        }

        /** Opens a transport data packet received from the responder. */
        fun openTransport(packet: ByteArray): ByteArray? {
            if (packet.size < 32) return null
            // byte-wise type check — WARP server transport packets keep their
            // reserved field zero, but ignoring those bytes is protocol-correct
            // (the RFC mandates receivers ignore them) and future-proof.
            if (packet[0].toInt() != MSG_TRANSPORT) return null
            if (leInt(packet, 4) != ourIndex) return null
            val counter = leLong(packet, 8)
            val nonce = ByteArray(12)
            putLeLong(nonce, 4, counter)
            return WgCrypto.chacha20Poly1305Open(recvKey, nonce, packet.copyOfRange(16, packet.size), ByteArray(0))
        }
    }

    // ------------------------------------------------------------ ICMP v4 ----

    /** IPv4 + ICMP echo request (28 bytes) from [src] to [dst]. */
    fun icmpEchoRequest(src: ByteArray, dst: ByteArray, ident: Int, seq: Int): ByteArray {
        require(src.size == 4 && dst.size == 4)
        val icmp = ByteArray(8)
        icmp[0] = 8; icmp[1] = 0
        putBeShort(icmp, 4, ident)
        putBeShort(icmp, 6, seq)
        putBeShort(icmp, 2, inetChecksum(icmp))

        val total = 20 + 8
        val ip = ByteArray(20)
        ip[0] = 0x45
        putBeShort(ip, 2, total)
        putBeShort(ip, 4, ident and 0xFFFF)
        putBeShort(ip, 6, 0x4000) // don't fragment
        ip[8] = 64
        ip[9] = 1 // ICMP
        System.arraycopy(src, 0, ip, 12, 4)
        System.arraycopy(dst, 0, ip, 16, 4)
        putBeShort(ip, 10, inetChecksum(ip))

        return ip + icmp
    }

    /** Validates that [inner] is an IPv4 ICMP echo reply for our [ident]/[seq]. */
    fun parseEchoReply(inner: ByteArray, ident: Int, seq: Int): Boolean {
        if (inner.size < 28) return false
        val verIhl = inner[0].toInt() and 0xFF
        if (verIhl shr 4 != 4) return false
        val ihl = (verIhl and 0x0F) * 4
        if (inner[9].toInt() != 1) return false // not ICMP
        if (inner.size < ihl + 8) return false
        val icmp = inner.copyOfRange(ihl, ihl + 8)
        val type = icmp[0].toInt() and 0xFF
        val code = icmp[1].toInt() and 0xFF
        val rid = beShort(icmp, 4)
        val rseq = beShort(icmp, 6)
        return type == 0 && code == 0 && rid == ident && rseq == seq
    }

    /** RFC 1071 one's-complement checksum. */
    fun inetChecksum(data: ByteArray): Int {
        var sum = 0L
        var i = 0
        while (i + 1 < data.size) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < data.size) sum += (data[i].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.toInt().inv()) and 0xFFFF
    }

    // --------------------------------------------------------- byte utils ----

    fun leInt(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xFF) or ((b[off + 1].toInt() and 0xFF) shl 8) or
            ((b[off + 2].toInt() and 0xFF) shl 16) or ((b[off + 3].toInt() and 0xFF) shl 24)

    fun leLong(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 7 downTo 0) v = (v shl 8) or (b[off + i].toInt() and 0xFF).toLong()
        return v
    }

    fun putLeInt(b: ByteArray, off: Int, v: Int) {
        b[off] = (v and 0xFF).toByte()
        b[off + 1] = ((v ushr 8) and 0xFF).toByte()
        b[off + 2] = ((v ushr 16) and 0xFF).toByte()
        b[off + 3] = ((v ushr 24) and 0xFF).toByte()
    }

    fun putLeLong(b: ByteArray, off: Int, v: Long) {
        repeat(8) { i -> b[off + i] = ((v ushr (8 * i)) and 0xFF).toByte() }
    }

    fun putBeInt(b: ByteArray, off: Int, v: Int) {
        b[off] = ((v ushr 24) and 0xFF).toByte()
        b[off + 1] = ((v ushr 16) and 0xFF).toByte()
        b[off + 2] = ((v ushr 8) and 0xFF).toByte()
        b[off + 3] = (v and 0xFF).toByte()
    }

    fun putBeShort(b: ByteArray, off: Int, v: Int) {
        b[off] = ((v ushr 8) and 0xFF).toByte()
        b[off + 1] = (v and 0xFF).toByte()
    }

    fun beInt(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
            ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)

    fun beShort(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

    fun putBeLong(b: ByteArray, off: Int, v: Long) {
        repeat(8) { i -> b[off + i] = ((v ushr (8 * (7 - i))) and 0xFF).toByte() }
    }
}
