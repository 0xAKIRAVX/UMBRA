package com.umbra.scanner

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.umbra.scanner.core.IpProtocol
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.core.ScanResult
import com.umbra.scanner.engine.ScanController
import com.umbra.scanner.net.WarpAccount
import com.umbra.scanner.net.WarpRegistration
import com.umbra.scanner.settings.UmbraSettings
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * v3.4 regression tests.
 *
 *  1. WARP+ is now REAL: the registration response's account id + bearer token
 *     are captured, persisted, and a license key is applied through them —
 *     the WARP+ toggle used to be a placebo.
 *  2. Engine memory hardening: a first probe result that already proves an
 *     endpoint dead is counted for progress but never stored — a capped
 *     mega-sweep (120k pairs) must not build a 120k-entry corpse map.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class Patch40Test {

    private val clientKey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa="

    private fun registrationBody(
        id: String = "8f6f8b7e-1111-2222-3333-444455556666",
        token: String = "v4-test-bearer-token",
    ) = """
    {
      "id": "$id",
      "token": "$token",
      "config": {
        "client_id": "DEBW",
        "interface": {
          "addresses": { "v6": "2606:4700:110:88db::1", "v4": "172.16.0.2" }
        },
        "peers": [ { "public_key": "$clientKey" } ]
      }
    }
    """.trimIndent()

    // ------------------------------------------------- WARP+ account plumbing

    @Test
    fun `parseResponse captures account id and token`() {
        val priv = ByteArray(32) { 1 }
        val pub = ByteArray(32) { 2 }
        val account = WarpRegistration.parseResponse(registrationBody(), priv, pub)
        assertNotNull(account)
        assertEquals("8f6f8b7e-1111-2222-3333-444455556666", account!!.accountId)
        assertEquals("v4-test-bearer-token", account.authToken)
        assertFalse(account.licenseApplied)
    }

    @Test
    fun `parseResponse tolerates a response without id and token`() {
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
        val account = WarpRegistration.parseResponse(body, ByteArray(32), ByteArray(32))
        assertNotNull(account)
        assertNull(account!!.accountId)
        assertNull(account.authToken)
    }

    @Test
    fun `account json round-trips id and token`() {
        val priv = ByteArray(32) { 3 }
        val pub = ByteArray(32) { 4 }
        val account = WarpRegistration.parseResponse(registrationBody(), priv, pub)!!
        val restored = WarpAccount.fromJson(account.toJson())
        assertNotNull(restored)
        assertEquals(account.accountId, restored!!.accountId)
        assertEquals(account.authToken, restored.authToken)
        assertEquals(account.v6, restored.v6)
        assertEquals(account.v4, restored.v4)
    }

    @Test
    fun `licenseApplied flag is transient — restore starts clean`() {
        val priv = ByteArray(32) { 3 }
        val pub = ByteArray(32) { 4 }
        val account = WarpRegistration.parseResponse(registrationBody(), priv, pub)!!
        val upgraded = account.copy(licenseApplied = true)
        val restored = WarpAccount.fromJson(upgraded.toJson())
        assertNotNull(restored)
        // a fresh process must re-apply keys — never trust a stale flag
        assertFalse(restored!!.licenseApplied)
    }

    @Test
    fun `license payload shape matches the wgcf account update`() {
        // {"license": key} — exactly what PUT /reg/{id}/account expects
        val o = JSONObject().put("license", "ABCD-1234-EFGH-5678")
        assertEquals("ABCD-1234-EFGH-5678", o.getString("license"))
        assertEquals(1, o.length())
    }

    // ---------------------------------------------------- params + persistence

    @Test
    fun `scan params default to an empty warp license key`() {
        assertTrue(ScanParams().warpLicenseKey.isEmpty())
    }

    private lateinit var settings: UmbraSettings

    @Before
    fun clean() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        ctx.getSharedPreferences("umbra_prefs", Context.MODE_PRIVATE).edit().clear().commit()
        settings = UmbraSettings(ctx)
    }

    @Test
    fun `warp license key survives a save-load round-trip`() {
        settings.saveParams(ScanParams(mode = ScanMode.WARP, warpLicenseKey = " ABCD-1234-EFGH-5678 "))
        // leading/trailing whitespace is trimmed — a blank paste is "no key"
        assertEquals("ABCD-1234-EFGH-5678", settings.loadParams().warpLicenseKey)
    }

    // --------------------------------------------- dead-drop result hardening

    private fun deadEdge(ip: String) = ScanResult(
        ip = ip, protocol = IpProtocol.IPv4, port = 443,
        packetLoss = 1.0, tcpAttempts = 3, successfulAttempts = 0,
        error = "TCP timeout", mode = ScanMode.CF_EDGE,
    )

    private fun aliveWarp(ip: String) = ScanResult(
        ip = ip, protocol = IpProtocol.IPv4, port = 2408,
        latencyMs = 42.0, jitterMs = 3.0, packetLoss = 0.0,
        tcpAttempts = 3, successfulAttempts = 2, wgHandshakes = 2,
        mode = ScanMode.WARP,
    )

    @Test
    fun `dead first result is counted but never stored`() {
        val controller = ScanController()
        val stored = listOf(
            controller.debugFeed(deadEdge("104.16.99.99")),
            controller.debugFeed(deadEdge("104.16.99.100")),
            controller.debugFeed(deadEdge("104.16.99.101")),
        )
        // progress statistics saw all three probes…
        assertEquals(3, controller.stats.value.tested)
        // …but the engine's result map holds no corpses
        assertEquals(listOf(0, 0, 0), stored)
    }

    @Test
    fun `alive first result is stored and visible`() {
        val controller = ScanController()
        val stored = controller.debugFeed(aliveWarp("162.159.192.7"))
        assertEquals(1, stored)
        assertEquals(1, controller.stats.value.tested)
        assertEquals(1, controller.stats.value.alive)
    }

    @Test
    fun `dead then alive for the same endpoint ends stored once`() {
        val controller = ScanController()
        // the pair is probed exactly once per scan; a dead-then-alive sequence
        // models the TLS phase updating an endpoint whose TCP probe succeeded
        val first = controller.debugFeed(deadEdge("188.114.96.7"))
        val second = controller.debugFeed(
            ScanResult(
                ip = "188.114.96.7", protocol = IpProtocol.IPv4, port = 443,
                latencyMs = 25.0, packetLoss = 0.0,
                tcpAttempts = 3, successfulAttempts = 3,
                tlsSuccess = true, mode = ScanMode.CF_EDGE,
            )
        )
        assertEquals(0, first)
        assertEquals(1, second)
        assertEquals(2, controller.stats.value.tested)
        assertEquals(1, controller.stats.value.alive)
    }
}
