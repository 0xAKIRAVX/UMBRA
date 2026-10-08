package com.umbra.scanner

import com.umbra.scanner.net.WgCrypto
import com.umbra.scanner.net.WgProtocol
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Differential tests: every Kotlin crypto/protocol path is compared
 * byte-for-byte against the Python reference implementation
 * (scripts/warp_probe_ref.py), which was itself verified live against
 * production Cloudflare WARP endpoints. If these pass, the Android probe
 * speaks exactly the same bytes as the validated reference.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class WgProtocolTest {

    private fun hex(s: String): ByteArray =
        s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun vectors(): JSONObject {
        val stream = javaClass.classLoader!!.getResourceAsStream("warp_vectors.json")
            ?: throw IllegalStateException("warp_vectors.json missing from test resources")
        return JSONObject(stream.readBytes().decodeToString())
    }

    // ── BLAKE2s ──────────────────────────────────────────────────

    @Test
    fun `blake2s matches reference`() {
        val arr = vectors().getJSONArray("blake2s")
        for (i in 0 until arr.length()) {
            val c = arr.getJSONObject(i)
            val out = WgCrypto.blake2s(hex(c.getString("data")))
            assertArrayEquals(hex(c.getString("out")), out)
        }
    }

    @Test
    fun `blake2s empty digest is the well known value`() {
        val empty = WgCrypto.blake2s(ByteArray(0))
        assertEquals("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
            empty.joinToString("") { "%02x".format(it) })
    }

    @Test
    fun `keyed blake2s 128-bit mac matches reference`() {
        val arr = vectors().getJSONArray("blake2s_keyed128")
        for (i in 0 until arr.length()) {
            val c = arr.getJSONObject(i)
            val out = WgCrypto.blake2s(
                hex(c.getString("data")), key = hex(c.getString("key")), digestSize = 16)
            assertArrayEquals(hex(c.getString("out")), out)
        }
    }

    @Test
    fun `hmac blake2s matches reference`() {
        val arr = vectors().getJSONArray("hmac_blake2s")
        for (i in 0 until arr.length()) {
            val c = arr.getJSONObject(i)
            val out = WgCrypto.hmacBlake2s(hex(c.getString("key")), hex(c.getString("data")))
            assertArrayEquals(hex(c.getString("out")), out)
        }
    }

    // ── X25519 ───────────────────────────────────────────────────

    @Test
    fun `x25519 public keys and shared secrets match reference`() {
        val arr = vectors().getJSONArray("x25519")
        for (i in 0 until arr.length()) {
            val c = arr.getJSONObject(i)
            val priv = hex(c.getString("priv"))
            assertArrayEquals(hex(c.getString("pub")), WgCrypto.x25519Base(priv))
            assertArrayEquals(
                hex(c.getString("shared")),
                WgCrypto.x25519Shared(priv, hex(c.getString("peer_pub"))))
        }
    }

    @Test
    fun `x25519 rfc7748 vector`() {
        val v = vectors().getJSONObject("x25519_rfc7748")
        val out = WgCrypto.x25519(hex(v.getString("scalar")), hex(v.getString("u")))
        assertArrayEquals(hex(v.getString("out")), out)
    }

    // ── ChaCha20-Poly1305 ────────────────────────────────────────

    @Test
    fun `aead seal matches reference and opens back`() {
        val arr = vectors().getJSONArray("aead")
        for (i in 0 until arr.length()) {
            val c = arr.getJSONObject(i)
            val key = hex(c.getString("key"))
            val nonce = hex(c.getString("nonce"))
            val pt = hex(c.getString("pt"))
            val ad = hex(c.getString("ad"))
            val ct = WgCrypto.chacha20Poly1305Seal(key, nonce, pt, ad)
            assertArrayEquals(hex(c.getString("ct")), ct)
            assertArrayEquals(pt, WgCrypto.chacha20Poly1305Open(key, nonce, ct, ad))
        }
    }

    @Test
    fun `aead rejects tampered ciphertext`() {
        val key = ByteArray(32) { (it + 1).toByte() }
        val nonce = ByteArray(12)
        val ct = WgCrypto.chacha20Poly1305Seal(key, nonce, "hello warp".toByteArray(), ByteArray(0))
        ct[0] = (ct[0].toInt() xor 0x40).toByte()
        assertNull(WgCrypto.chacha20Poly1305Open(key, nonce, ct, ByteArray(0)))
    }

    // ── full handshake ───────────────────────────────────────────

    @Test
    fun `handshake initiation packet matches reference byte for byte`() {
        val hs = vectors().getJSONObject("handshake")
        val (packet, pending) = WgProtocol.buildInitiation(
            staticPriv = hex(hs.getString("init_static_priv")),
            staticPub = hex(hs.getString("init_static_pub")),
            responderPub = hex(hs.getString("resp_static_pub")),
            senderIndex = hs.getInt("sender_index"),
            ephemeralPriv = hex(hs.getString("eph_priv")),
            timestamp = hex(hs.getString("timestamp")),
            reserved = hex(hs.getString("reserved")),
        )
        assertEquals(148, packet.size)
        assertArrayEquals(hex(hs.getString("init_packet")), packet)

        // and the response consumption yields the reference session keys
        val (session, err) = WgProtocol.consumeResponse(
            pending, hex(hs.getString("init_static_priv")), hex(hs.getString("response_packet")))
        assertNotNull("consumeResponse failed: $err", session)
        assertEquals(hs.getInt("their_index"), session!!.theirIndex)
    }

    @Test
    fun `session keys derive identically and transport roundtrips`() {
        val v = vectors()
        val hs = v.getJSONObject("handshake")
        val initPriv = hex(hs.getString("init_static_priv"))
        val (packet, pending) = WgProtocol.buildInitiation(
            staticPriv = initPriv,
            staticPub = hex(hs.getString("init_static_pub")),
            responderPub = hex(hs.getString("resp_static_pub")),
            senderIndex = hs.getInt("sender_index"),
            ephemeralPriv = hex(hs.getString("eph_priv")),
            timestamp = hex(hs.getString("timestamp")),
            reserved = hex(hs.getString("reserved")),
        )
        val (session, _) = WgProtocol.consumeResponse(pending, initPriv, hex(hs.getString("response_packet")))
        assertNotNull(session)

        // transport request (echo request inside the tunnel)
        val tr = v.getJSONObject("transport_req")
        val inner = WgProtocol.icmpEchoRequest(
            byteArrayOf(172.toByte(), 16, 0, 2), byteArrayOf(1, 1, 1, 1),
            tr.getInt("ident"), tr.getInt("seq"))
        val packetOut = session!!.buildTransport(inner)
        assertArrayEquals(hex(tr.getString("packet")), packetOut)

        // transport reply decrypts to the reference inner packet + parses as echo
        val reply = v.getJSONObject("transport_reply")
        val innerReply = session.openTransport(hex(reply.getString("packet")))
        assertNotNull(innerReply)
        assertArrayEquals(hex(reply.getString("inner")), innerReply!!)
        assertTrue(WgProtocol.parseEchoReply(innerReply, tr.getInt("ident"), tr.getInt("seq")))
    }

    @Test
    fun `response with wrong receiver index is rejected`() {
        val hs = vectors().getJSONObject("handshake")
        val initPriv = hex(hs.getString("init_static_priv"))
        val (packet, pending) = WgProtocol.buildInitiation(
            staticPriv = initPriv,
            staticPub = hex(hs.getString("init_static_pub")),
            responderPub = hex(hs.getString("resp_static_pub")),
            senderIndex = hs.getInt("sender_index"),
            ephemeralPriv = hex(hs.getString("eph_priv")),
            timestamp = hex(hs.getString("timestamp")),
            reserved = hex(hs.getString("reserved")),
        )
        val resp = hex(hs.getString("response_packet"))
        resp[8] = (resp[8].toInt() xor 0x01).toByte() // corrupt receiver index
        val (session, err) = WgProtocol.consumeResponse(pending, initPriv, resp)
        assertNull(session)
        assertTrue(err.isNotEmpty())
    }

    @Test
    fun `warp reserved bytes ride in packet bytes 1 to 3`() {
        val hs = vectors().getJSONObject("handshake")
        val reserved = hex(hs.getString("reserved"))
        val (packet, _) = WgProtocol.buildInitiation(
            staticPriv = hex(hs.getString("init_static_priv")),
            staticPub = hex(hs.getString("init_static_pub")),
            responderPub = hex(hs.getString("resp_static_pub")),
            senderIndex = hs.getInt("sender_index"),
            ephemeralPriv = hex(hs.getString("eph_priv")),
            timestamp = hex(hs.getString("timestamp")),
            reserved = reserved,
        )
        // type byte stays 1, the 3 WARP client_id bytes follow immediately
        assertEquals(1, packet[0].toInt())
        for (i in 0..2) assertEquals(reserved[i], packet[1 + i])
        // and the transport packets carry them too
        val initPriv = hex(hs.getString("init_static_priv"))
        val (_, pending) = WgProtocol.buildInitiation(
            staticPriv = initPriv,
            staticPub = hex(hs.getString("init_static_pub")),
            responderPub = hex(hs.getString("resp_static_pub")),
            senderIndex = hs.getInt("sender_index"),
            ephemeralPriv = hex(hs.getString("eph_priv")),
            timestamp = hex(hs.getString("timestamp")),
            reserved = reserved,
        )
        val (session, _) = WgProtocol.consumeResponse(
            pending, initPriv, hex(hs.getString("response_packet")))
        assertNotNull(session)
        val tr = vectors().getJSONObject("transport_req")
        val inner = WgProtocol.icmpEchoRequest(
            byteArrayOf(172.toByte(), 16, 0, 2), byteArrayOf(1, 1, 1, 1),
            tr.getInt("ident"), tr.getInt("seq"))
        val tp = session!!.buildTransport(inner)
        for (i in 0..2) assertEquals(reserved[i], tp[1 + i])
    }

    @Test
    fun `tai64n has whitened nanoseconds and correct base`() {
        val ts = WgProtocol.tai64nNow()
        assertEquals(12, ts.size)
        val secsBase = WgProtocol.beInt(ts, 0).toLong() shl 32 or (WgProtocol.beInt(ts, 4).toLong() and 0xFFFFFFFF)
        val nowSecs = System.currentTimeMillis() / 1000
        val delta = kotlin.math.abs(secsBase - 0x400000000000000AL - nowSecs)
        assertTrue("timestamp $secsBase too far from now", delta <= 2)
        val nanos = WgProtocol.beInt(ts, 8)
        assertEquals("nanos must be whitened (low 24 bits zero)", 0, nanos and 0xFFFFFF)
    }

    // ── ICMP ─────────────────────────────────────────────────────

    @Test
    fun `icmp checksums are valid and reply parsing works`() {
        val req = WgProtocol.icmpEchoRequest(
            byteArrayOf(172.toByte(), 16, 0, 2), byteArrayOf(1, 1, 1, 1), 0xA1B2, 7)
        assertEquals(28, req.size)
        // verify ipv4 header checksum (one's-complement sum incl. checksum = 0xFFFF)
        assertEquals(0xFFFF, oneComplementSum(req.copyOfRange(0, 20)))
        // verify icmp checksum
        assertEquals(0xFFFF, oneComplementSum(req.copyOfRange(20, 28)))
        // is a valid echo request
        assertEquals(8, req[20].toInt())
        // builds the exact reference bytes (transport_req inner is unpadded there)
        val tr = vectors().getJSONObject("transport_req")
        val ref = hex(tr.getString("inner")).copyOfRange(0, 28)
        assertArrayEquals(ref, req)
    }

    private fun oneComplementSum(data: ByteArray): Int {
        var sum = 0L
        var i = 0
        while (i + 1 < data.size) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < data.size) sum += (data[i].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.toInt()) and 0xFFFF
    }
}
