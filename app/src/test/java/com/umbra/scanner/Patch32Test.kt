package com.umbra.scanner

import com.umbra.scanner.core.IpProtocol
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanResult
import com.umbra.scanner.core.ResultCodec
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * v3.2 regression tests for the bug-hunt patch:
 *  1. "TLS VERIFY off" no longer zero-fills EDGE results (tlsSkipped fallback)
 *  2. ResultCodec round-trips the new tlsSkipped flag
 *  3. TCP-only results are reported honestly (alive, but marked)
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class Patch32Test {

    private fun edgeResult(
        ok: Int,
        tls: Boolean = false,
        http: Int? = null,
        skipped: Boolean = false,
    ) = ScanResult(
        ip = "104.16.1.1",
        protocol = IpProtocol.IPv4,
        port = 443,
        latencyMs = 45.0,
        tcpAttempts = 3,
        successfulAttempts = ok,
        tlsSuccess = tls,
        httpStatus = http,
        tlsSkipped = skipped,
        mode = ScanMode.CF_EDGE,
    )

    @Test
    fun `tls verify off keeps tcp-alive endpoints alive`() {
        // v3.1.1 bug: tlsVerify off -> no TLS phase, no speed phase, alive never
        // true -> finalize dropped everything -> empty board after a long scan.
        val r = edgeResult(ok = 3, skipped = true)
        assertTrue("tcp-alive endpoint must stay alive when the user disabled TLS verify", r.alive)
    }

    @Test
    fun `tls verify on still requires proof for edge`() {
        // With verification ON (tlsSkipped=false), a bare TCP-alive result is
        // still NOT alive — the DPI-fake protection must be preserved.
        val r = edgeResult(ok = 3, skipped = false)
        assertFalse("tcp-alive alone must not count as alive when TLS verify is on", r.alive)
    }

    @Test
    fun `tls success and http 200 remain alive regardless`() {
        assertTrue(edgeResult(ok = 3, tls = true).alive)
        assertTrue(edgeResult(ok = 3, http = 200).alive)
    }

    @Test
    fun `failed endpoints are never alive even when skipped`() {
        val r = edgeResult(ok = 0, skipped = true)
        assertFalse("failed endpoint must stay dead", r.alive)
    }

    @Test
    fun `warp alive ignores tlsSkipped`() {
        // v3.8: the contract moved to ENDPOINT mode — alive = the WireGuard
        // handshake answered, regardless of any tls flags
        val r = ScanResult(
            ip = "162.159.192.1",
            protocol = IpProtocol.IPv4,
            port = 2408,
            successfulAttempts = 2,
            wgHandshakes = 2,
            tlsSkipped = true,
            mode = ScanMode.ENDPOINT,
        )
        assertTrue(r.alive)
    }

    @Test
    fun `result codec round-trips tlsSkipped`() {
        val r = edgeResult(ok = 3, skipped = true)
        val json = ResultCodec.toJson(r)
        val back = ResultCodec.fromJson(json)!!
        assertTrue("tlsSkipped must survive persistence", back.tlsSkipped)
        assertTrue(back.alive)

        val r2 = edgeResult(ok = 3, skipped = false, tls = true)
        val back2 = ResultCodec.fromJson(ResultCodec.toJson(r2))!!
        assertFalse("absence must default to false", back2.tlsSkipped)
        assertTrue(back2.tlsSuccess)
    }
}
