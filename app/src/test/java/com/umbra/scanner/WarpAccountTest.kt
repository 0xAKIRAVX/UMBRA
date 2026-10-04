package com.umbra.scanner

import com.umbra.scanner.net.WarpRegistration
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Unit tests for the WARP account registration logic (pure functions). */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class WarpAccountTest {

    @Test
    fun `payload matches the BPB wire format`() {
        val payload = WarpRegistration.buildPayload("aGVsbG8=", "2026-10-04T12:00:00.000Z")
        val o = JSONObject(payload)
        assertEquals("", o.getString("install_id"))
        assertEquals("", o.getString("fcm_token"))
        assertEquals("2026-10-04T12:00:00.000Z", o.getString("tos"))
        assertEquals("Android", o.getString("type"))
        assertEquals("PC", o.getString("model"))
        assertEquals("en_US", o.getString("locale"))
        assertEquals(true, o.getBoolean("warp_enabled"))
        assertEquals("aGVsbG8=", o.getString("key"))
    }

    @Test
    fun `tos timestamp is iso utc`() {
        val ts = WarpRegistration.tosTimestamp(0L)
        assertEquals("1970-01-01T00:00:00.000Z", ts)
    }

    @Test
    fun `parses a realistic registration response`() {
        // the exact response shape the CF API returns (BPB warp.go WarpConfig)
        val clientKey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa="
        val body = """
        {
          "config": {
            "client_id": "DEBW",
            "interface": {
              "addresses": { "v6": "2606:4700:110:88db::1", "v4": "172.16.0.2" }
            },
            "peers": [ { "public_key": "$clientKey" } ]
          }
        }
        """.trimIndent()
        val priv = ByteArray(32) { 1 }
        val pub = ByteArray(32) { 2 }
        val account = WarpRegistration.parseResponse(body, priv, pub)
        assertNotNull(account)
        assertEquals(3, account!!.reserved.size)
        // "DEBW" is base64 — decodes to 0x0C 0x40 0x56
        assertEquals(listOf(12, 64, 86), account.reserved.map { it.toInt() })
        assertEquals("2606:4700:110:88db::1", account.v6)
        assertEquals("172.16.0.2", account.v4)
        assertEquals(32, account.responderPublicKey.size)
        assertEquals(priv, account.privateKey)
        assertEquals(pub, account.publicKey)
    }

    @Test
    fun `rejects malformed responses`() {
        assertNull(WarpRegistration.parseResponse("{}", ByteArray(32), ByteArray(32)))
        assertNull(WarpRegistration.parseResponse("not json", ByteArray(32), ByteArray(32)))
        assertNull(WarpRegistration.parseResponse("""{"config":{"peers":[]}}""", ByteArray(32), ByteArray(32)))
    }

    @Test
    fun `v4 falls back to 172_16_0_2 when absent`() {
        val body = """
        {
          "config": {
            "client_id": "DEBW",
            "interface": { "addresses": { "v6": "2606:4700:110::1" } },
            "peers": [ { "public_key": "${"a".repeat(43)}=" } ]
          }
        }
        """.trimIndent()
        val account = WarpRegistration.parseResponse(body, ByteArray(32), ByteArray(32))
        assertNotNull(account)
        assertEquals("172.16.0.2", account!!.v4)
    }

    @Test
    fun `identity generation is clamped and matches public key`() {
        val rnd = kotlin.random.Random(42)
        val (priv, pub) = WarpRegistration.newIdentity(rnd)
        assertEquals(32, priv.size)
        assertEquals(0, priv[0].toInt() and 7)          // low 3 bits cleared
        assertEquals(64, priv[31].toInt() and 64)      // bit 254 (byte bit 6) set
        assertEquals(0, priv[31].toInt() and 128)      // bit 255 (byte bit 7) clear
        // exact clamped public key reproducibility
        val (priv2, pub2) = WarpRegistration.newIdentity(kotlin.random.Random(42))
        assertEquals(priv.toList(), priv2.toList())
        assertEquals(pub.toList(), pub2.toList())
        // public key must equal X25519(priv, 9)
        assertEquals(com.umbra.scanner.net.WgCrypto.x25519Base(priv).toList(), pub.toList())
    }
}
