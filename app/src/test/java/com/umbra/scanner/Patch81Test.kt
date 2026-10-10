package com.umbra.scanner

import com.umbra.scanner.core.Candidate
import com.umbra.scanner.core.EndpointPair
import com.umbra.scanner.core.IpProtocol
import com.umbra.scanner.core.IpText
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanResult
import com.umbra.scanner.engine.assembleEndpointPool
import com.umbra.scanner.net.WarpProbeStats
import com.umbra.scanner.ui.screens.endpointText
import com.umbra.scanner.ui.screens.onModeSwitchToggles
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.random.Random

/**
 * v3.8.1 regression tests — the full-codebase bug hunt after v3.8.0:
 *
 *  1. ENGINE: the endpoint pool is deduplicated against the seeds (progress
 *     can reach 100%, the completion line no longer overcounts).
 *  2. STATS: a handshake-validated endpoint no longer reports "loss 100%"
 *     (loss counts rounds where the endpoint answered NOTHING).
 *  3. UI: the mode switcher no longer poisons EDGE/CUSTOM with TLS-off
 *     (the toggle snapshot/restore contract).
 *  4. UI: best-endpoint display carries the port, IPv6 bracketed.
 */
class Patch81Test {

    // ── 1. endpoint pool dedup (progress-stuck-under-100% fix) ────────────

    private fun pair(ip: String, port: Int): EndpointPair =
        IpText.literalToBytes(ip)!!.let { EndpointPair(Candidate(it), port) }

    @Test
    fun `seed collisions in the random draw are dropped - seeds first`() {
        val seeds = listOf(pair("188.114.96.1", 2408), pair("162.159.192.42", 2408))
        val drawn = listOf(
            pair("188.114.96.1", 2408),   // exact seed duplicate
            pair("188.114.96.1", 894),    // same IP, DIFFERENT port — kept
            pair("162.159.192.42", 2408), // exact seed duplicate
            pair("8.6.112.7", 2408),      // fresh
            pair("8.35.211.4", 500),      // fresh
        )
        val pool = assembleEndpointPool(seeds, drawn)
        // 2 seeds + 3 kept draws (894 variant + the two fresh pairs)
        assertEquals(2 + 3, pool.size)
        // seeds lead the pool — they are the guaranteed-fast head start
        assertEquals("188.114.96.1", pool[0].candidate.text)
        assertEquals(2408, pool[0].port)
        assertEquals("162.159.192.42", pool[1].candidate.text)
        // the same IP on a different port survives (it IS a different endpoint)
        assertTrue(pool.any { it.candidate.text == "188.114.96.1" && it.port == 894 })
        // no duplicate ip:port anywhere
        val ids = pool.map { "${it.candidate.text}:${it.port}" }
        assertEquals(ids.size, ids.distinct().size)
    }

    @Test
    fun `no seeds means the draw passes through untouched`() {
        val drawn = listOf(pair("8.6.112.7", 2408), pair("8.35.211.4", 500))
        assertEquals(drawn, assembleEndpointPool(emptyList(), drawn))
    }

    @Test
    fun `pinned-port sweep over the full v4 pool cannot emit duplicate ids`() {
        // exhaustive-adjacent scenario: the draw covers every pool host, so
        // every seed v4 host collides — the pool must still be duplicate-free
        val seeds = listOf(pair("188.114.96.1", 2408), pair("162.159.192.1", 894))
        val drawn = buildList {
            for (b in com.umbra.scanner.core.Presets.WARP_V4) {
                val prefix = b.substringBeforeLast('.')
                for (h in 1..254) add(pair("$prefix.$h", 2408))
            }
        }
        val pool = assembleEndpointPool(seeds, drawn)
        val ids = pool.map { "${it.candidate.text}:${it.port}" }
        assertEquals(ids.size, ids.distinct().size)
        // both seed hosts appear exactly once (seed first, draw's copy dropped)
        assertEquals(1, ids.count { it == "188.114.96.1:2408" })
    }

    // ── 2. endpoint loss semantics (100%-loss-on-validated fix) ───────────

    @Test
    fun `handshake-only rounds are successful rounds - loss zero`() {
        val st = WarpProbeStats(
            attempts = 3, handshakes = 3, pings = 0,
            pingLatenciesMs = emptyList(),
            handshakeLatenciesMs = listOf(60.0, 55.0, 58.0),
            cookieReplies = 0, lastError = "handshake ok · no data plane",
        )
        assertEquals(0.0, st.loss, 1e-9)
        // latency falls back to the handshake RTT — still ranked, still alive
        assertEquals((60.0 + 55.0 + 58.0) / 3.0, st.avgHandshakeMs!!, 1e-9)
    }

    @Test
    fun `partial answers produce the honest per-round loss`() {
        // 2 of 3 rounds answered (one with ping, one with handshake only)
        val st = WarpProbeStats(
            attempts = 3, handshakes = 2, pings = 1,
            pingLatenciesMs = listOf(52.0),
            handshakeLatenciesMs = listOf(48.0, 61.0),
            cookieReplies = 0, lastError = null,
        )
        assertEquals(1.0 / 3.0, st.loss, 1e-9)
    }

    @Test
    fun `total silence is full loss`() {
        val st = WarpProbeStats(
            attempts = 3, handshakes = 0, pings = 0,
            pingLatenciesMs = emptyList(),
            handshakeLatenciesMs = emptyList(),
            cookieReplies = 0, lastError = "handshake timeout",
        )
        assertEquals(1.0, st.loss, 1e-9)
    }

    @Test
    fun `a validated handshake-only row shows loss 0 percent`() {
        val row = ScanResult(
            ip = "162.159.192.42", protocol = IpProtocol.IPv4, port = 2408,
            latencyMs = 42.0, packetLoss = 0.0,
            tcpAttempts = 3, successfulAttempts = 0, wgHandshakes = 3,
            mode = ScanMode.ENDPOINT,
        )
        assertTrue(row.alive)
        assertEquals(0, row.lossPct) // the Done panel contradiction is gone
    }

    // ── 3. mode-switch toggle restore (the TLS-off poisoning fix) ─────────

    @Test
    fun `entering endpoint snapshots and leaving restores the toggles`() {
        // EDGE start: TLS + speed ON (the honest defaults)
        var state = onModeSwitchToggles(
            ScanMode.CF_EDGE, ScanMode.CF_EDGE, tls = true, speed = true,
            savedTls = null, savedSpeed = null,
        )
        assertEquals(true, state.tls)
        assertEquals(true, state.speed)

        // pass through ENDPOINT: toggles forced OFF, snapshot taken
        state = onModeSwitchToggles(
            ScanMode.ENDPOINT, ScanMode.CF_EDGE,
            tls = state.tls, speed = state.speed,
            savedTls = state.savedTls, savedSpeed = state.savedSpeed,
        )
        assertEquals(false, state.tls)
        assertEquals(false, state.speed)
        assertEquals(true, state.savedTls)   // the user's EDGE choice remembered
        assertEquals(true, state.savedSpeed)

        // back to EDGE: snapshot restored — NOT left off
        state = onModeSwitchToggles(
            ScanMode.CF_EDGE, ScanMode.ENDPOINT,
            tls = state.tls, speed = state.speed,
            savedTls = state.savedTls, savedSpeed = state.savedSpeed,
        )
        assertTrue("EDGE scans must regain TLS verification", state.tls)
        assertTrue("EDGE scans must regain the speed test", state.speed)
        assertNull("snapshot cleared after restore", state.savedTls)
        assertNull(state.savedSpeed)
    }

    @Test
    fun `the user's own off choices survive a round trip through endpoint`() {
        // user deliberately ran EDGE with TLS off + speed off
        val r1 = onModeSwitchToggles(
            ScanMode.ENDPOINT, ScanMode.CF_EDGE, tls = false, speed = false,
            savedTls = null, savedSpeed = null,
        )
        val r2 = onModeSwitchToggles(
            ScanMode.CF_EDGE, ScanMode.ENDPOINT,
            tls = r1.tls, speed = r1.speed, savedTls = r1.savedTls, savedSpeed = r1.savedSpeed,
        )
        assertEquals(false, r2.tls)   // their choice, not a forced default
        assertEquals(false, r2.speed)
    }

    @Test
    fun `edge-to-custom switches never touch the toggles`() {
        val r = onModeSwitchToggles(
            ScanMode.CUSTOM, ScanMode.CF_EDGE, tls = true, speed = false,
            savedTls = null, savedSpeed = null,
        )
        assertEquals(true, r.tls)
        assertEquals(false, r.speed)
        assertNull(r.savedTls)
    }

    @Test
    fun `repeat endpoint entries keep the original snapshot`() {
        val r1 = onModeSwitchToggles(
            ScanMode.ENDPOINT, ScanMode.CF_EDGE, true, true, null, null,
        )
        // user manually re-enables speed INSIDE endpoint mode, then switches
        // EDGE→ENDPOINT again: the first snapshot must survive
        val r2 = onModeSwitchToggles(
            ScanMode.ENDPOINT, ScanMode.CF_EDGE,
            tls = r1.tls, speed = true, savedTls = r1.savedTls, savedSpeed = r1.savedSpeed,
        )
        assertEquals(true, r2.savedTls)
        assertEquals(true, r2.savedSpeed)
        // leaving now restores the ORIGINAL snapshot
        val r3 = onModeSwitchToggles(
            ScanMode.CF_EDGE, ScanMode.ENDPOINT,
            tls = r2.tls, speed = r2.speed, savedTls = r2.savedTls, savedSpeed = r2.savedSpeed,
        )
        assertTrue(r3.tls)
    }

    // ── 4. endpoint display text (port carried, IPv6 bracketed) ───────────

    @Test
    fun `endpoint text carries the port for v4`() {
        val row = ScanResult(
            ip = "162.159.192.42", protocol = IpProtocol.IPv4, port = 894,
            mode = ScanMode.ENDPOINT,
        )
        assertEquals("162.159.192.42:894", row.endpointText())
    }

    @Test
    fun `endpoint text brackets ipv6 - never an ambiguous address`() {
        val row = ScanResult(
            ip = "2606:4700:d0::a29f:c001", protocol = IpProtocol.IPv6, port = 2408,
            mode = ScanMode.ENDPOINT,
        )
        assertEquals("[2606:4700:d0::a29f:c001]:2408", row.endpointText())
    }

    // guard: the helper stays deterministic (no hidden state)
    @Test
    fun `endpoint text is stable across calls`() {
        val row = ScanResult(ip = "188.114.96.1", protocol = IpProtocol.IPv4, port = 443)
        assertEquals(row.endpointText(), row.endpointText())
    }

    @Test
    fun `random draw never emits a seed pair as a duplicate under pinned port`() {
        // statistical guard over the real generator + assembler
        val seeds = com.umbra.scanner.core.Presets.WARP_SEED_ENDPOINTS
            .mapNotNull { (ip, p) -> IpText.literalToBytes(ip)?.let { EndpointPair(Candidate(it), p) } }
        repeat(12) { seed ->
            val drawn = com.umbra.scanner.core.IpGenerator.generateEndpoints(
                com.umbra.scanner.core.NetFamily.V4, 1500, 2408, Random(seed),
            )
            val pool = assembleEndpointPool(seeds, drawn)
            val ids = pool.map { "${it.candidate.text}:${it.port}" }
            assertEquals("seed $seed produced duplicates", ids.size, ids.distinct().size)
            assertTrue("seeds must lead the pool", ids.take(seeds.size) == seeds.map { "${it.candidate.text}:${it.port}" })
        }
    }
}
