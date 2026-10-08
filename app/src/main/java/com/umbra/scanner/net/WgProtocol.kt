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
 * WARP extension (verified against Xray-core proxy/wireguard/bind.go Send()):
 * Cloudflare's data plane reads the 3-byte WireGuard "reserved" field (bytes
 * 1..3 of EVERY packet, handshake included) as the account's client_id. A
 * packet without it cannot be associated with the registered identity and is
 * silently dropped — this was the root cause of "fake" scan results.
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

    /** TAI64N now — 12 bytes BE: (0x400000000000000a + unixSecs) || (nanos & ~0xFFFFFF). */
    fun tai64nNow(): ByteArray {
        val nanoTime = System.nanoTime()
        val unixSecs = System.currentTimeMillis() / 1000L
        val nanos = (nanoTime % 1_000_000_000L).toInt() and (0xFF000000.toInt()) // whitener
        val out = ByteArray(12)
        putBeLong(out, 0, 0x400000000000000AL + unixSecs)
        putBeInt(out, 8, nanos)
        return out
    }

    // --------------------------------------------------------- handshake ----

    /** Initiator-side state kept between the initiation and the response. */
    class PendingHandshake internal constructor(
        internal val ephPriv: ByteArray,
        internal val hash: ByteArray,
        internal val chainKey: ByteArray,
        internal val reserved: ByteArray,
        val senderIndex: Int,
    )

    /** WARP client_id bytes carried in the reserved field of every packet. */
    fun warpReserved(accountClientId: ByteArray): ByteArray =
        if (accountClientId.size >= 3) accountClientId.copyOf(3)
        else accountClientId + ByteArray(3 - accountClientId.size)

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
        /** WARP account client_id — written into the reserved bytes (1..3). */
        reserved: ByteArray = ByteArray(3),
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
        // WARP: reserved bytes carry the client_id (Xray bind.go parity)
        writeReserved(packet, reserved)
        putLeInt(packet, 4, senderIndex)
        System.arraycopy(ephPub, 0, packet, 8, 32)
        System.arraycopy(staticCt, 0, packet, 40, 48)
        System.arraycopy(tsCt, 0, packet, 88, 28)

        val mac1Key = WgCrypto.blake2s(LABEL_MAC1.toByteArray() + responderPub)
        val mac1 = WgCrypto.blake2s(packet.copyOfRange(0, 116), key = mac1Key, digestSize = 16)
        System.arraycopy(mac1, 0, packet, 116, 16)
        // mac2 stays zero (no cookie)

        return packet to PendingHandshake(ephemeralPriv, h, ck, warpReserved(reserved), senderIndex)
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
        val type = leInt(data, 0)
        if (type != MSG_RESPONSE) return null to "not a response (type $type)"
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
        return WgSession(sendKey, recvKey, pending.senderIndex, sender, pending.reserved) to ""
    }

    // -------------------------------------------------------- data plane ----

    /** Established transport session (initiator side). */
    class WgSession internal constructor(
        private val sendKey: ByteArray,
        private val recvKey: ByteArray,
        val ourIndex: Int,
        val theirIndex: Int,
        /** WARP client_id — written into bytes 1..3 of every outgoing packet. */
        private val reserved: ByteArray = ByteArray(3),
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
            writeReserved(packet, reserved)
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

    /** Writes the WARP client_id into the WireGuard reserved bytes (1..3). */
    private fun writeReserved(packet: ByteArray, reserved: ByteArray) {
        for (i in 0..2) packet[1 + i] = reserved.getOrElse(i) { 0 }
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
