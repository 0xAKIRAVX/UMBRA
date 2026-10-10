package com.umbra.scanner

import com.umbra.scanner.core.IpProtocol
import com.umbra.scanner.core.ResultCodec
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The persisted smart-picks store: ScanResult JSON round-trip fidelity —
 * every field the results board and pick logic read must survive.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ResultCodecTest {

    @Test
    fun `full result round-trips unchanged`() {
        val r = ScanResult(
            ip = "2606:4700:d0::a29f:c001",
            protocol = IpProtocol.IPv6,
            port = 2408,
            latencyMs = 187.4,
            jitterMs = 22.6,
            packetLoss = 0.33,
            speedMbps = 8.51,
            downloadedBytes = 1_048_576L,
            tcpAttempts = 3,
            successfulAttempts = 2,
            tlsSuccess = true,
            tlsHandshakeMs = 210.0,
            httpStatus = 200,
            wgHandshakes = 3,
            error = "handshake ok · no data plane",
            mode = ScanMode.ENDPOINT,
        )
        val restored = ResultCodec.fromJson(ResultCodec.toJson(r))
        assertEquals(r, restored)
    }

    @Test
    fun `sparse result round-trips with defaults`() {
        val r = ScanResult(ip = "104.16.1.1", protocol = IpProtocol.IPv4, port = 443)
        val restored = ResultCodec.fromJson(ResultCodec.toJson(r))
        assertEquals(r, restored)
    }

    @Test
    fun `list round-trip keeps order and drops garbage`() {
        val list = listOf(
            ScanResult(ip = "1.1.1.1", protocol = IpProtocol.IPv4, port = 443, latencyMs = 12.0),
            ScanResult(ip = "1.0.0.1", protocol = IpProtocol.IPv4, port = 8443, latencyMs = 15.0),
        )
        val restored = ResultCodec.fromJsonList(ResultCodec.toJsonList(list))
        assertEquals(list, restored)

        assertEquals(emptyList<ScanResult>(), ResultCodec.fromJsonList(null))
        assertEquals(emptyList<ScanResult>(), ResultCodec.fromJsonList(""))
        assertEquals(emptyList<ScanResult>(), ResultCodec.fromJsonList("]["))
    }

    @Test
    fun `alive survives the trip for both modes`() {
        val edge = ScanResult(
            ip = "104.16.1.1", protocol = IpProtocol.IPv4, port = 443,
            tlsSuccess = true, httpStatus = 200, mode = ScanMode.CF_EDGE,
        )
        val endpoint = ScanResult(
            ip = "162.159.192.1", protocol = IpProtocol.IPv4, port = 2408,
            tcpAttempts = 3, successfulAttempts = 3, wgHandshakes = 3, mode = ScanMode.ENDPOINT,
        )
        val rEdge = ResultCodec.fromJson(ResultCodec.toJson(edge))
        val rWarp = ResultCodec.fromJson(ResultCodec.toJson(endpoint))
        assertNotNull(rEdge)
        assertNotNull(rWarp)
        assertTrue(rEdge!!.alive)
        assertTrue(rWarp!!.alive)
    }

    @Test
    fun `v38 endpoint-mode row round-trips with handshake aliveness`() {
        // v3.8: alive = a WireGuard handshake answered (NOT tcp-alive — the
        // fake-endpoint fix); a v6 endpoint on a random warp port must
        // survive persistence intact.
        val r = ScanResult(
            ip = "2606:4700:d0::a29f:c001",
            protocol = IpProtocol.IPv6,
            port = 2408,
            latencyMs = 88.5,
            jitterMs = 6.25,
            packetLoss = 0.0,
            tcpAttempts = 3,
            successfulAttempts = 3,
            wgHandshakes = 3,
            mode = ScanMode.ENDPOINT,
        )
        val back = ResultCodec.fromJson(ResultCodec.toJson(r))
        assertNotNull(back)
        assertEquals(ScanMode.ENDPOINT, back!!.mode)
        assertEquals(r.ip, back.ip)
        assertEquals(2408, back.port)
        assertEquals(88.5, back.latencyMs!!, 0.0001)
        assertEquals(6.25, back.jitterMs!!, 0.0001)
        assertTrue(back.alive)

        // v3.8: a row with ONLY tcp-alive proof is NOT alive — the exact
        // fake-endpoint contract that shipped as the v3.7 bug
        val tcpOnly = r.copy(wgHandshakes = 0)
        val backTcpOnly = ResultCodec.fromJson(ResultCodec.toJson(tcpOnly))!!
        assertTrue(!backTcpOnly.alive)

        val dead = r.copy(successfulAttempts = 0, wgHandshakes = 0, latencyMs = null)
        val backDead = ResultCodec.fromJson(ResultCodec.toJson(dead))!!
        assertTrue(!backDead.alive)
    }
}
