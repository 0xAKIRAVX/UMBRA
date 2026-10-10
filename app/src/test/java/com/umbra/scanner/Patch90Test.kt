package com.umbra.scanner

import com.umbra.scanner.core.EndpointPair
import com.umbra.scanner.core.IpText
import com.umbra.scanner.core.NetFamily
import com.umbra.scanner.core.Presets
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.core.ScanPhase
import com.umbra.scanner.core.ScanResult
import com.umbra.scanner.engine.ScanEngine
import com.umbra.scanner.engine.ScanSink
import com.umbra.scanner.engine.slidingRatePerSec
import com.umbra.scanner.net.WarpAccount
import com.umbra.scanner.net.WarpProbeBudget
import com.umbra.scanner.net.attemptTimeoutMs
import com.umbra.scanner.net.noisePacketsFor
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.IOException

/**
 * v3.9 regression tests — THE frozen-scan release (the user's screenshot:
 * TESTED 0/504 · ALIVE 0 · RATE 0.0/S · ACTIVE 320 · ELAPSED 1:43):
 *
 * Root causes fixed and guarded here:
 *  1. every blocking UDP receive serialized behind the 64-thread IO pool
 *     (the storm now rides an elastic Dispatchers.IO.limitedParallelism view)
 *  2. every retry waited the FULL timeout and no early exit existed — the
 *     budget ladder halves retry budgets and stops once an endpoint is
 *     proven (pure fns: attemptTimeoutMs / noisePacketsFor / stopAfter)
 *  3. no environment verdict: a WARP-UDP-filtered network ground the whole
 *     pool silently — the pre-flight witness gate now answers in one short
 *     round and self-heals a stale identity before ever aborting honestly
 *  4. the stats card rate/ETA were cumulative-since-start (0.0/s through
 *     the silent lead-in) — now a 15 s sliding window (slidingRatePerSec)
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class Patch90Test {

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

    private fun fakeAccount(seed: Int = 0): WarpAccount = WarpAccount(
        privateKey = ByteArray(32) { (it + seed).toByte() },
        publicKey = ByteArray(32) { (it + seed + 1).toByte() },
        reserved = byteArrayOf(1, 2, 3),
        v6 = "2606:4700:d111:222:333:444:555:666",
        v4 = "172.16.0.2",
        responderPublicKey = ByteArray(32) { (it + seed + 7).toByte() },
    )

    private fun endpointParams(count: Int = 4) = ScanParams(
        mode = ScanMode.ENDPOINT,
        family = NetFamily.V4,
        port = 0,
        endpointsCount = count,
        warpAttempts = 1,
        tcpTimeoutMs = 300,          // engine coerces to the 2000ms wg floor
        concurrency = 64,
        udpNoise = false,
        speedTest = false,
    )

    // ── pure functions: the budget ladder ─────────────────────────────────

    @Test
    fun `first attempt gets the full timeout - congested-but-alive endpoints deserve it`() {
        assertEquals(2000, attemptTimeoutMs(0, 2000))
        assertEquals(6000, attemptTimeoutMs(0, 6000))
        // degenerate indices stay on the full budget
        assertEquals(2000, attemptTimeoutMs(-1, 2000))
    }

    @Test
    fun `retries wait half the budget with a 700ms floor`() {
        assertEquals(1000, attemptTimeoutMs(1, 2000))
        assertEquals(3000, attemptTimeoutMs(3, 6000))
        // base below the floor: never ABOVE the base
        assertEquals(300, attemptTimeoutMs(1, 300))
        // base exactly at the floor
        assertEquals(700, attemptTimeoutMs(1, 700))
        assertEquals(700, attemptTimeoutMs(5, 700))
    }

    @Test
    fun `dead-endpoint burn shrinks with the ladder - the screenshot math`() {
        // the user-shaped scan: 7 retries at a 6s slider timeout
        // v3.8: 7 × 6000 = 42 000 ms of lane time per dead endpoint
        // v3.9: 6000 + 6 × 3000 = 24 000 ms — 43% of the old burn
        var total = 0L
        for (i in 0 until 7) total += attemptTimeoutMs(i, 6000)
        assertEquals(24_000L, total)
        // 3 retries at the 2s wg floor: v3.8 6000 ms → v3.9 4000 ms (2000 + 2×1000)
        total = 0
        for (i in 0 until 3) total += attemptTimeoutMs(i, 2000)
        assertEquals(4_000L, total)
    }

    @Test
    fun `noise burst rides the first attempt only - later rounds a single packet`() {
        assertEquals(5, noisePacketsFor(0, 5))
        assertEquals(1, noisePacketsFor(1, 5))
        assertEquals(1, noisePacketsFor(6, 5))
        assertEquals(0, noisePacketsFor(1, 0))
        assertEquals(0, noisePacketsFor(0, 0))
        // configured above the cap stays capped
        assertEquals(50, noisePacketsFor(0, 99))
    }

    @Test
    fun `probe stops once the endpoint is proven or its bonus round ran`() {
        // proven + measured: stop immediately
        assertTrue(WarpProbeBudget.stopAfter(fullSeen = true, bonusSpent = false))
        assertTrue(WarpProbeBudget.stopAfter(fullSeen = true, bonusSpent = true))
        // alive-without-ping after the one bonus round: stop
        assertTrue(WarpProbeBudget.stopAfter(fullSeen = false, bonusSpent = true))
        // silence never stops early — retries exist for it
        assertFalse(WarpProbeBudget.stopAfter(fullSeen = false, bonusSpent = false))
    }

    // ── pure function: the sliding rate ───────────────────────────────────

    @Test
    fun `sliding rate is zero with no events and cumulative while young`() {
        assertEquals(0.0, slidingRatePerSec(emptyList(), nowMs = 10_000, elapsedMs = 5_000), 1e-9)
        // elapsed < window → window IS the scan so far: 3 events / 3 s = 1/s
        assertEquals(1.0, slidingRatePerSec(listOf(1_000, 2_000, 3_000), nowMs = 4_000, elapsedMs = 3_000), 1e-9)
    }

    @Test
    fun `sliding rate spikes when results land and decays when they stop`() {
        val now = 60_000L
        // 10 events in the last 2s inside a 15s window → 10/15 ≈ 0.67/s …
        val recent = (48_000 until 58_000 step 1_000).map { it.toLong() }
        assertEquals(10.0 * 1000 / 15_000, slidingRatePerSec(recent, now, elapsedMs = 60_000), 1e-9)
        // …the old cumulative rate with 10 tested over 60s would read 0.17/s
        // through the whole silent lead-in — the frozen 0.0/s card
        // events all older than the window: rate decays to 0 honestly
        val stale = (1_000 until 11_000 step 1_000).map { it.toLong() }
        assertEquals(0.0, slidingRatePerSec(stale, now, elapsedMs = 60_000), 1e-9)
        // mixed: only the recent half counts
        val mixed = stale + recent
        assertEquals(10.0 * 1000 / 15_000, slidingRatePerSec(mixed, now, elapsedMs = 60_000), 1e-9)
    }

    // ── pure function: the witness pool ───────────────────────────────────

    @Test
    fun `witness pool is seeds first plus a bounded random tail`() {
        val seeds = Presets.WARP_SEED_ENDPOINTS.mapNotNull { (ip, p) ->
            IpText.literalToBytes(ip)?.let { EndpointPair(com.umbra.scanner.core.Candidate(it), p) }
        }
        val drawn = (1..500).mapNotNull { n ->
            IpText.literalToBytes("162.159.192.$n")?.let {
                EndpointPair(com.umbra.scanner.core.Candidate(it), 2408)
            }
        }
        val pool = ScanEngine().buildWitnessPool(seeds + drawn)
        assertEquals(12 + seeds.size, pool.size)
        // the census seeds lead — a healthy network answers them in one RTT
        assertEquals(seeds, pool.take(seeds.size))
        // tiny pools pass through whole
        val tiny = ScanEngine().buildWitnessPool(seeds)
        assertEquals(seeds.size, tiny.size)
    }

    // ── engine: the witness gate flows (offline via seams) ────────────────

    @Test
    fun `witness pass skips re-registration and rolls the storm`() = runBlocking {
        val engine = ScanEngine()
        var registrations = 0
        engine.registrationProvider = { _, fresh ->
            registrations++
            if (fresh) throw IOException("must not happen") // gate passed — no heal needed
            fakeAccount()
        }
        engine.witnessProber = { _, _, _ -> 4 }
        val sink = RecordingSink()
        engine.run(endpointParams(count = 3), sink)

        assertEquals(1, registrations)
        assertTrue(sink.logs.any { it.contains("pre-flight witness · 4/") && it.contains("udp path live") })
        assertTrue(sink.phases.contains(ScanPhase.WG))
        assertTrue(sink.phases.contains(ScanPhase.DONE))
        assertTrue(sink.logs.none { it.contains("re-registering") })
    }

    @Test
    fun `stale identity self-heals - fresh key answers and the storm uses it`() = runBlocking {
        val engine = ScanEngine()
        val stale = fakeAccount(seed = 1)
        val healed = fakeAccount(seed = 2)
        var usedForWitness: WarpAccount? = null
        engine.registrationProvider = { _, fresh ->
            if (fresh) healed else stale
        }
        engine.witnessProber = { acc, _, _ ->
            usedForWitness = acc
            if (acc === stale) 0 else 5   // stale key silent, fresh key answers
        }
        val sink = RecordingSink()
        engine.run(endpointParams(count = 3), sink)

        // both identities were actually probed (self-heal, not blind trust)
        assertEquals(healed, usedForWitness)
        assertTrue(sink.logs.any { it.contains("fresh identity · 5/") && it.contains("udp path live") })
        assertTrue(sink.phases.contains(ScanPhase.WG))
        assertTrue(sink.phases.contains(ScanPhase.DONE))
        assertTrue(sink.logs.none { it.contains("endpoint scan aborted") })
    }

    @Test
    fun `witness abort on a udp-filtered network - honest verdict, no storm grind`() = runBlocking {
        val engine = ScanEngine()
        val acc = fakeAccount()
        engine.registrationProvider = { _, _ -> acc }
        engine.witnessProber = { _, _, _ -> 0 }   // every round silent — filtered network
        engine.sweepProber = { _, _, _ -> emptyList() } // v3.10: the ladder's last rung is silent too
        val sink = RecordingSink()
        engine.run(endpointParams(count = 500), sink)

        // the verdict names the world and states the remedies
        assertTrue(sink.logs.any { it.contains("warp udp is silent on this network even with a fresh identity") })
        assertTrue(sink.logs.any { it.contains("endpoint scan aborted") })
        // v3.10: the ladder ran — the abort names what the sweep covered
        // (random ports + ipv6 are tried AUTOMATICALLY now, not advised)
        assertTrue(sink.logs.any { it.contains("recovery sweep") })
        assertTrue(sink.logs.any { it.contains("recovery sweep already covered") })
        assertTrue(sink.logs.any { it.contains("another network/isp") })
        assertTrue(sink.logs.none { it.contains("try: random ports") })
        // THE contract: the 504-pool storm NEVER runs — the frozen screen is
        // structurally impossible on a filtered network now
        assertFalse(sink.phases.contains(ScanPhase.WG))
        assertTrue(sink.phases.contains(ScanPhase.DONE))
    }

    @Test
    fun `witness abort when a stale identity cannot be refreshed - api unreachable`() = runBlocking {
        val engine = ScanEngine()
        var freshAttempts = 0
        engine.registrationProvider = { _, fresh ->
            if (fresh) { freshAttempts++; throw IOException("api unreachable") }
            fakeAccount()
        }
        engine.witnessProber = { _, _, _ -> 0 }
        engine.sweepProber = { _, _, _ -> emptyList() } // v3.10: even the ladder is silent
        val sink = RecordingSink()
        engine.run(endpointParams(count = 4), sink)

        assertEquals(1, freshAttempts)
        assertTrue(sink.logs.any { it.contains("identity may be expired and the registration api is unreachable") })
        assertFalse(sink.phases.contains(ScanPhase.WG))
        assertTrue(sink.phases.contains(ScanPhase.DONE))
    }

    // ── engine: the storm heartbeat (liveness while results are pending) ──

    @Test
    fun `wg storm heartbeat line is honest about progress`() = runBlocking {
        // the heartbeat coroutine only fires on 10s boundaries — with a tiny
        // offline pool the scan finishes long before the first beat, so this
        // guards the CONTRACT instead: a completed storm never leaves the
        // heartbeat's "lanes busy" line dangling as the final word when
        // results did land (the completion line must be the last WG word).
        val engine = ScanEngine()
        engine.registrationProvider = { _, _ -> fakeAccount() }
        engine.witnessProber = { _, _, _ -> 3 }
        val sink = RecordingSink()
        engine.run(endpointParams(count = 3), sink)
        val lastWgLine = sink.logs.last { it.startsWith("wg storm") || it.startsWith("endpoint scan done") }
        assertTrue(lastWgLine.startsWith("endpoint scan done"))
    }
}
