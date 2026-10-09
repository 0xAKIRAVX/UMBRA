package com.umbra.scanner

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.umbra.scanner.core.IpProtocol
import com.umbra.scanner.core.NetFamily
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.core.ScanPhase
import com.umbra.scanner.core.ScanResult
import com.umbra.scanner.engine.ScanEngine
import com.umbra.scanner.engine.ScanSink
import com.umbra.scanner.net.UdpEvidence
import com.umbra.scanner.net.WarpAccount
import com.umbra.scanner.settings.UmbraSettings
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.IOException

/**
 * v3.8 regression tests — the release that removed the WARP mode and made
 * endpoint validation REAL (a WireGuard handshake, never a TCP connect):
 *
 *  - engine: ENDPOINT flow registers an identity silently, prepends the
 *    live-verified seeds, and a zero-result scan diagnoses itself with
 *    independent UDP evidence (never a bare "0 found").
 *  - engine: no identity → honest abort. A TCP-only fallback (the v3.7
 *    fake-endpoint generator) must NEVER run.
 *  - settings: pre-v3.8 persisted mode ordinals migrate (WARP→ENDPOINT,
 *    CUSTOM→CUSTOM), exactly once.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class Patch80Test {

    private class RecordingSink : ScanSink {
        val phases = ArrayList<ScanPhase>()
        val logs = ArrayList<String>()
        val results = ArrayList<ScanResult>()
        var generated = 0
        override fun onPhase(phase: ScanPhase) { phases.add(phase) }
        override fun onGenerated(count: Int) { generated = count }
        override fun onResult(result: ScanResult) { results.add(result) }
        override fun onActive(delta: Int) {}
        override fun onLog(line: String) { logs.add(line) }
        override fun snapshot(): List<ScanResult> = ArrayList(results)
    }

    private fun fakeAccount(): WarpAccount = WarpAccount(
        privateKey = ByteArray(32) { it.toByte() },
        publicKey = ByteArray(32) { (it + 1).toByte() },
        reserved = byteArrayOf(1, 2, 3),
        v6 = "2606:4700:d111:222:333:444:555:666",
        v4 = "172.16.0.2",
        responderPublicKey = ByteArray(32) { (it + 7).toByte() },
    )

    private fun endpointParams(
        count: Int = 4,
        family: NetFamily = NetFamily.V4,
    ) = ScanParams(
        mode = ScanMode.ENDPOINT,
        family = family,
        port = 0,
        endpointsCount = count,
        warpAttempts = 1,
        tcpTimeoutMs = 300,          // engine coerces to the 2000ms wg floor
        concurrency = 150,
        udpNoise = false,             // no noise in unit tests
        speedTest = false,
    )

    // ── engine: happy plumbing (probes themselves dead without network) ────

    @Test
    fun `endpoint scan registers identity silently and prepends seeds`() = runBlocking {
        val engine = ScanEngine()
        engine.registrationProvider = { fakeAccount() }
        val sink = RecordingSink()
        engine.run(endpointParams(count = 4), sink)

        // identity phase ran and logged as silent internal plumbing
        assertTrue(sink.phases.contains(ScanPhase.REGISTER))
        assertTrue(sink.logs.any { it.contains("warp identity") && it.contains("api.cloudflareclient.com") })
        assertTrue(sink.logs.any { it.contains("warp identity ready") })

        // 4 random + the census-verified seeds = the whole pool
        assertEquals(4 + com.umbra.scanner.core.Presets.WARP_SEED_ENDPOINTS.size, sink.generated)
        assertTrue(sink.logs.any { it.contains("live-verified seeds") })

        // WG storm phase (not TCP — that is the v3.7 fake-endpoint path)
        assertTrue(sink.phases.contains(ScanPhase.WG))
        assertTrue(sink.phases.contains(ScanPhase.DONE))
    }

    @Test
    fun `zero-result endpoint scan diagnoses itself with udp evidence`() = runBlocking {
        val engine = ScanEngine()
        engine.registrationProvider = { fakeAccount() }
        // seam: no NTP witness answered either → "no udp egress" world
        engine.evidenceGatherer = { UdpEvidence.Evidence(cloudflareNtp = false, otherNtp = false) }
        val sink = RecordingSink()
        engine.run(endpointParams(count = 2), sink)

        val done = sink.logs.last()
        assertTrue("completion line must exist: $done", done.contains("endpoint scan done"))
        assertTrue("must count handshakes: $done", done.contains("handshakes"))
        // the diagnosis: probe failure classes + the witness verdict
        assertTrue("failure tally expected: $done", done.contains("handshake timeout ×"))
        assertTrue("witness verdict expected: $done", done.contains("even ntp is dead"))
        // the fake TCP fallback must NEVER appear
        assertTrue(sink.logs.none { it.contains("tcp storm done") })
    }

    @Test
    fun `no identity means honest abort - never a tcp-only fallback`() = runBlocking {
        val engine = ScanEngine()
        engine.registrationProvider = { throw IOException("api unreachable") }
        val sink = RecordingSink()
        engine.run(endpointParams(count = 2), sink)

        assertTrue(sink.logs.any { it.contains("cannot validate endpoints without a warp identity") })
        assertTrue(sink.logs.any { it.contains("v3.7 bug") }) // the lesson is stated
        assertTrue(sink.phases.contains(ScanPhase.DONE))
        // no probe ever ran — dead silence beats fake results
        assertTrue(sink.results.isEmpty())
        assertTrue(sink.logs.none { it.contains("tcp storm done") })
    }

    // ── settings: the v3.8 ordinal migration ───────────────────────────────

    private lateinit var settings: UmbraSettings
    private lateinit var ctx: Context

    @Before
    fun clean() {
        ctx = ApplicationProvider.getApplicationContext()
        ctx.getSharedPreferences("umbra_prefs", Context.MODE_PRIVATE).edit().clear().commit()
        settings = UmbraSettings(ctx)
    }

    @Test
    fun `old warp mode migrates to endpoint`() {
        // pre-v3.8 install: p_mode = 1 (the removed WARP mode)
        ctx.getSharedPreferences("umbra_prefs", Context.MODE_PRIVATE).edit()
            .putInt("p_mode", 1).commit()
        assertEquals(ScanMode.ENDPOINT, settings.lastScanMode())
        // loadParams performs the one-time rewrite…
        assertEquals(ScanMode.ENDPOINT, settings.loadParams().mode)
        val stored = ctx.getSharedPreferences("umbra_prefs", Context.MODE_PRIVATE)
            .getInt("p_mode", -1)
        assertEquals(ScanMode.ENDPOINT.ordinal, stored)
        // …and stays stable afterwards
        assertEquals(ScanMode.ENDPOINT, settings.loadParams().mode)
        assertEquals(ScanMode.ENDPOINT, settings.lastScanMode())
    }

    @Test
    fun `old custom mode stays custom after migration`() {
        ctx.getSharedPreferences("umbra_prefs", Context.MODE_PRIVATE).edit()
            .putInt("p_mode", 2).commit() // pre-v3.8 CUSTOM
        assertEquals(ScanMode.CUSTOM, settings.lastScanMode())
        assertEquals(ScanMode.CUSTOM, settings.loadParams().mode)
    }

    @Test
    fun `post-migration ordinals read in the new space`() {
        // flag already set + stored 2 = ENDPOINT in the NEW ordinal space
        ctx.getSharedPreferences("umbra_prefs", Context.MODE_PRIVATE).edit()
            .putInt("p_mode", 2)
            .putBoolean("p_mode_mig_v38", true)
            .commit()
        assertEquals(ScanMode.ENDPOINT, settings.lastScanMode())
    }

    @Test
    fun `endpoint results persist into the warp bucket of the smart board`() {
        // v3.8: ENDPOINT rows ARE warp endpoints — they must hydrate the warp
        // side of the smart-pick board after a restart
        val rows = listOf(
            ScanResult(
                ip = "188.114.96.1", protocol = IpProtocol.IPv4, port = 2408,
                latencyMs = 42.0, packetLoss = 0.0, tcpAttempts = 3,
                successfulAttempts = 2, wgHandshakes = 3, mode = ScanMode.ENDPOINT,
            )
        )
        settings.saveParams(ScanParams(mode = ScanMode.ENDPOINT))
        settings.saveScanResults(ScanMode.ENDPOINT, rows)
        assertEquals(1, settings.savedWarpResults.value.size)
        assertTrue(settings.savedEdgeResults.value.isEmpty())
        // fresh controller hydrates from the warp bucket (ResultsRestoreTest
        // covers the controller side)
    }
}
