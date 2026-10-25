package com.umbra.scanner

import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.core.ScanPhase
import com.umbra.scanner.core.ScanResult
import com.umbra.scanner.core.IpProtocol
import com.umbra.scanner.engine.ScanEngine
import com.umbra.scanner.engine.sessionStartLine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import kotlin.math.abs

/**
 * v4.2 regression tests — the DEEP MEASURE phase (the answer to
 * «برنامه سریع آیپی‌ها رو پیدا می‌کنه و اصلاً فرصت نمی‌کنه تا واقعی
 * بسنجه‌شون — پینگ و سرعت و پایداری») and the honest Akamai probe host
 * (the answer to «آیپی‌های آکامای فیک هستن و کار نمی‌کنن»).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class Patch420Test {

    private val engine = ScanEngine()

    // ── deepTcpStats: the pure math behind the reported ping/loss ──────────

    @Test
    fun `deep stats compute avg min jitter loss`() {
        val s = engine.deepTcpStats(listOf(100.0, 200.0, 300.0), failures = 1)
        assertEquals(200.0, s.avgMs!!, 1e-9)
        assertEquals(100.0, s.minMs!!, 1e-9)
        assertEquals(81.6497, s.jitterMs!!, 1e-3)
        assertEquals("1 failure of 4 total", 0.25, s.loss, 1e-9)
    }

    @Test
    fun `deep stats with zero failures report zero loss`() {
        val s = engine.deepTcpStats(listOf(90.0, 110.0, 105.0, 95.0), failures = 0)
        assertEquals(0.0, s.loss, 1e-9)
        assertEquals(100.0, s.avgMs!!, 1e-9)
        assertEquals(90.0, s.minMs!!, 1e-9)
        assertTrue(s.jitterMs!! > 0.0 && s.jitterMs!! < 10.0)
    }

    @Test
    fun `deep stats of a fully flaky endpoint are honest`() {
        val s = engine.deepTcpStats(emptyList(), failures = 8)
        assertNull(s.avgMs)
        assertNull(s.minMs)
        assertNull(s.jitterMs)
        assertEquals(1.0, s.loss, 1e-9)
    }

    @Test
    fun `single sample has no jitter`() {
        val s = engine.deepTcpStats(listOf(123.0), failures = 0)
        assertNull(s.jitterMs)
        assertEquals(123.0, s.avgMs!!, 1e-9)
        assertEquals(0.0, s.loss, 1e-9)
    }

    @Test
    fun `jitter formula matches tcp probe jitter (same ruler everywhere)`() {
        val lat = listOf(20.0, 40.0, 60.0)
        val fromDeep = engine.deepTcpStats(lat, 0).jitterMs!!
        val fromTcp = com.umbra.scanner.net.TcpProbe.jitterOf(lat)!!
        assertTrue(abs(fromDeep - fromTcp) < 1e-9)
    }

    // ── merge: the deep numbers REPLACE the single-sample discovery ones ──

    @Test
    fun `merge - deep measurement replaces the lucky first round trip`() {
        val discovered = ScanResult(
            ip = "23.33.178.195", protocol = IpProtocol.IPv4, port = 443,
            latencyMs = 42.0, jitterMs = null, packetLoss = 0.0,
            tcpAttempts = 3, successfulAttempts = 3,
            tlsSuccess = true, tlsHandshakeMs = 42.0,
            mode = ScanMode.AKAMAI,
        )
        val deep = discovered.copy(
            latencyMs = 187.5, jitterMs = 25.0, packetLoss = 0.125,
            tcpAttempts = 8, successfulAttempts = 7, tlsHandshakeMs = 150.0,
        )
        val merged = discovered.merge(deep)
        assertEquals("the deep AVG replaces the single-sample latency", 187.5, merged.latencyMs!!, 1e-9)
        assertEquals(25.0, merged.jitterMs!!, 1e-9)
        assertEquals("deep loss is real stability, not the storm's 3-attempt guess", 0.125, merged.packetLoss, 1e-9)
        assertEquals(8, merged.tcpAttempts)
        assertTrue(merged.alive)
        assertNull("alive endpoint keeps no stale error", merged.error)
    }

    @Test
    fun `merge - fully flaky deep round keeps the endpoint alive with a warning`() {
        val validated = ScanResult(
            ip = "88.221.87.159", protocol = IpProtocol.IPv4, port = 443,
            latencyMs = 120.0, packetLoss = 0.0, tcpAttempts = 3, successfulAttempts = 3,
            tlsSuccess = true, mode = ScanMode.AKAMAI,
        )
        val deep = validated.copy(
            latencyMs = null, jitterMs = null, packetLoss = 1.0,
            tcpAttempts = 8, successfulAttempts = 0,
            error = "deep measure · 8/8 samples lost",
        )
        val merged = validated.merge(deep)
        assertTrue("TLS-verified once → still alive, flagged flaky", merged.alive)
        assertNotNull(merged.error)
        assertEquals(1.0, merged.packetLoss, 1e-9)
    }

    // ── phase plumbing ─────────────────────────────────────────────────────

    @Test
    fun `calibrate sits between validation and ranking, done is last`() {
        assertEquals(4, ScanPhase.CALIBRATE.order)
        assertTrue(ScanPhase.PROBE.order < ScanPhase.CALIBRATE.order)
        assertTrue(ScanPhase.WG.order < ScanPhase.CALIBRATE.order)
        assertTrue(ScanPhase.CALIBRATE.order < ScanPhase.RANKING.order)
        assertTrue(ScanPhase.RANKING.order < ScanPhase.SPEED.order)
        assertTrue(ScanPhase.SPEED.order < ScanPhase.DONE.order)
        assertEquals("the phase bar label is its user-facing name", "DEEP MEASURE", ScanPhase.CALIBRATE.label)
    }

    // ── deep defaults + session line ───────────────────────────────────────

    @Test
    fun `deep measure defaults on with census-calibrated counts`() {
        val p = ScanParams()
        assertTrue("deep measure ships ON — it is the point of v4.2", p.deepMeasure)
        assertEquals(30, p.deepTopN)
        assertEquals(8, p.deepSamples)
    }

    @Test
    fun `session start line names the deep measure and the akamai sni`() {
        // ENDPOINT names the wg rounds
        val wg = sessionStartLine(ScanParams(mode = ScanMode.ENDPOINT, deepMeasure = true))
        assertTrue(wg.contains("deep measure ×8 wg rounds"))
        // AKAMAI names the census-proven SNI + real-page throughput
        val akamai = sessionStartLine(ScanParams(mode = ScanMode.AKAMAI, deepMeasure = true))
        assertTrue(akamai.contains("deep measure ×8"))
        assertTrue(akamai.contains("sni www.bing.com"))
        assertTrue(akamai.contains("real-page throughput"))
        // a deep-off scan says nothing about it
        val off = sessionStartLine(ScanParams(mode = ScanMode.CF_EDGE, deepMeasure = false))
        assertTrue(!off.contains("deep measure"))
        // the v4.0.1 hostile-locale contract still holds (no Turkish dotless ı)
        assertTrue(!akamai.contains('ı'))
    }
}
