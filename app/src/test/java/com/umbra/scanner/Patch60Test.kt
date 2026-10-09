package com.umbra.scanner

import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.core.ScanPhase
import com.umbra.scanner.core.ScanResult
import com.umbra.scanner.engine.ScanEngine
import com.umbra.scanner.engine.ScanSink
import com.umbra.scanner.engine.WarpGate
import com.umbra.scanner.engine.classifyWarpProbe
import com.umbra.scanner.net.WarpAccount
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * v3.6 — the "WARP scanner still has problems" round, closed at the source:
 *
 *  1. TAI64N replay-window fix (see WgProtocolTest for the timestamp tests)
 *  2. the WARP pre-flight gate — every decision branch below
 *  3. zero-result scans now carry a classified failure tally
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class Patch60Test {

    // capture production seams so tests never leak fakes into other suites
    private val realProber = WarpGate.seedProber
    private val realSweeper = WarpGate.portSweeper
    private val realRegistrar = WarpGate.freshRegistrar
    private val realEvidence = WarpGate.evidenceGatherer
    private val realV6Seeds = WarpGate.v6Seeds

    @Before
    fun hermeticSeams() {
        // v3.6.2: the gate now consults NTP evidence + v6 seeds on the way to
        // a negative verdict — keep these tests offline and deterministic.
        WarpGate.evidenceGatherer = { com.umbra.scanner.net.UdpEvidence.Evidence(false, false) }
        WarpGate.v6Seeds = { emptyList() }
    }

    @After
    fun restoreSeams() {
        WarpGate.seedProber = realProber
        WarpGate.portSweeper = realSweeper
        WarpGate.freshRegistrar = realRegistrar
        WarpGate.evidenceGatherer = realEvidence
        WarpGate.v6Seeds = realV6Seeds
    }

    private fun fakeAccount(tag: String = "stored"): WarpAccount = WarpAccount(
        privateKey = ByteArray(32) { it.toByte() },
        publicKey = ByteArray(32) { (it + 1).toByte() },
        reserved = byteArrayOf(1, 2, 3),
        v6 = "2606:4700:d1:1234::$tag".take(39),
        v4 = "172.16.0.2",
        responderPublicKey = ByteArray(32) { (it + 2).toByte() },
    )

    // ── WarpGate decision tree ──────────────────────────────────────────

    @Test
    fun `gate ok when the seed answers with the current identity`() = runBlocking {
        WarpGate.seedProber = { _, _, _, _ -> WarpGate.SeedStats(handshakes = 1, cookieReplies = 0, pingMs = 87.5) }
        val out = WarpGate.check(fakeAccount(), 2408, 3000) {}
        assertTrue(out is WarpGate.Outcome.Ok)
        assertEquals(1, (out as WarpGate.Outcome.Ok).let { 1 }) // compiles the cast
        assertTrue(out.note.contains("preflight ok"))
    }

    @Test
    fun `gate accepts a cookie reply as proof of a live path`() = runBlocking {
        // endpoints under load answer handshakes with cookie replies — the UDP
        // path is proven even though the identity stays unproven
        WarpGate.seedProber = { _, _, _, _ -> WarpGate.SeedStats(handshakes = 0, cookieReplies = 1, pingMs = null) }
        val out = WarpGate.check(fakeAccount(), 2408, 3000) {}
        assertTrue(out is WarpGate.Outcome.Ok)
    }

    @Test
    fun `gate swaps a stale identity when a fresh registration answers`() = runBlocking {
        val stale = fakeAccount("stale")
        val fresh = fakeAccount("fresh")
        // original identity: silence; fresh identity: handshake
        WarpGate.seedProber = { account, _, _, _ ->
            if (account === fresh) WarpGate.SeedStats(1, 0, 44.0) else null
        }
        WarpGate.freshRegistrar = { fresh }
        val out = WarpGate.check(stale, 2408, 3000) {}
        assertTrue("expected Ok, got $out", out is WarpGate.Outcome.Ok)
        assertTrue((out as WarpGate.Outcome.Ok).account === fresh)
        assertTrue(out.note.contains("stale"))
    }

    @Test
    fun `gate adapts ports when the primary port is blocked but others verify`() = runBlocking {
        val fresh = fakeAccount()
        WarpGate.seedProber = { _, _, _, _ -> null } // primary port dead everywhere
        WarpGate.freshRegistrar = { fresh }
        WarpGate.portSweeper = { _, _ -> mapOf(500 to 21.0, 894 to 22.0, 443 to 23.0) }
        val out = WarpGate.check(fakeAccount(), 2408, 3000) {}
        assertTrue("expected Adapt, got $out", out is WarpGate.Outcome.Adapt)
        assertEquals(listOf(443, 500, 894), (out as WarpGate.Outcome.Adapt).ports)
        assertTrue(out.note.contains("port 2408 is blocked"))
    }

    @Test
    fun `gate blocks the scan when a fresh identity gets no answer anywhere`() = runBlocking {
        WarpGate.seedProber = { _, _, _, _ -> null }
        WarpGate.freshRegistrar = { fakeAccount("fresh") }
        WarpGate.portSweeper = { _, _ -> emptyMap() }
        val out = WarpGate.check(fakeAccount(), 2408, 3000) {}
        assertTrue("expected Blocked, got $out", out is WarpGate.Outcome.Blocked)
        assertTrue((out as WarpGate.Outcome.Blocked).note.contains("warp unreachable"))
    }

    @Test
    fun `gate is unverifiable when the api is blocked and no port answers`() = runBlocking {
        val stored = fakeAccount()
        WarpGate.seedProber = { _, _, _, _ -> null }
        WarpGate.freshRegistrar = { null } // registration API unreachable
        WarpGate.portSweeper = { _, _ -> emptyMap() }
        val out = WarpGate.check(stored, 2408, 3000) {}
        assertTrue("expected Unverifiable, got $out", out is WarpGate.Outcome.Unverifiable)
        assertTrue((out as WarpGate.Outcome.Unverifiable).account === stored)
        assertTrue(out.note.contains("identity unverifiable"))
    }

    @Test
    fun `gate adapts with the stored identity when the api is blocked but ports answer`() = runBlocking {
        val stored = fakeAccount()
        WarpGate.seedProber = { _, _, _, _ -> null }
        WarpGate.freshRegistrar = { null }
        WarpGate.portSweeper = { acc, _ ->
            if (acc === stored) mapOf(2408 to 30.0) else emptyMap()
        }
        val out = WarpGate.check(stored, 894, 3000) {}
        assertTrue("expected Adapt, got $out", out is WarpGate.Outcome.Adapt)
        assertTrue((out as WarpGate.Outcome.Adapt).account === stored)
        assertEquals(listOf(2408), out.ports)
    }

    // ── engine integration: the blocked network aborts BEFORE the storm ──

    @Test
    fun `engine ends the scan at the gate when the network blocks warp`() = runBlocking {
        val engine = ScanEngine()
        engine.registrationProvider = { fakeAccount() }
        WarpGate.seedProber = { _, _, _, _ -> null }
        WarpGate.freshRegistrar = { fakeAccount("fresh") }
        WarpGate.portSweeper = { _, _ -> emptyMap() }

        val phases = ArrayList<ScanPhase>()
        val logs = ArrayList<String>()
        val results = ArrayList<ScanResult>()
        val sink = object : ScanSink {
            override fun onPhase(phase: ScanPhase) { phases.add(phase) }
            override fun onGenerated(count: Int) {}
            override fun onResult(result: ScanResult) { results.add(result) }
            override fun onActive(delta: Int) {}
            override fun onLog(line: String) { logs.add(line) }
            override fun snapshot(): List<ScanResult> = results
        }
        engine.run(
            ScanParams(mode = ScanMode.WARP, port = 2408, samplesPerPrefix = 4, speedTest = false),
            sink,
        )

        assertTrue("scan must reach DONE, got $phases", phases.contains(ScanPhase.DONE))
        assertEquals("no probe may run on a blocked network", 0, results.size)
        assertTrue(
            "the abort reason must be logged honestly",
            logs.any { it.contains("warp unreachable") },
        )
        assertTrue(logs.any { it.contains("preflight") })
    }

    // ── zero-result diagnosis buckets ───────────────────────────────────

    @Test
    fun `probe classifier buckets every outcome`() {
        assertNull("full success tallies nothing", classifyWarpProbe(1, 1, 0, null))
        assertEquals("handshake ok · no data plane", classifyWarpProbe(1, 0, 0, "ping timeout"))
        assertEquals("cookie reply (alive under load)", classifyWarpProbe(0, 0, 1, null))
        assertEquals("handshake timeout", classifyWarpProbe(0, 0, 0, "handshake timeout"))
        assertEquals("handshake timeout", classifyWarpProbe(0, 0, 0, "ping timeout"))
        assertEquals("icmp port-unreachable", classifyWarpProbe(0, 0, 0, "udp PortUnreachableException"))
        assertEquals("udp send blocked", classifyWarpProbe(0, 0, 0, "udp send refused"))
        assertEquals("no handshake", classifyWarpProbe(0, 0, 0, null))
        assertEquals("udp SocketException", classifyWarpProbe(0, 0, 0, "udp SocketException"))
    }

    @Test
    fun `timestamp mark apis are safe on empty state`() {
        com.umbra.scanner.net.WgProtocol.resetMark()
        assertNull(com.umbra.scanner.net.WgProtocol.saveMark())
        com.umbra.scanner.net.WgProtocol.loadMark(null) // must not throw
        assertNotNull(com.umbra.scanner.net.WgProtocol.tai64nNow())
    }
}
