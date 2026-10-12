package com.umbra.scanner

import com.umbra.scanner.core.Candidate
import com.umbra.scanner.core.EndpointPair
import com.umbra.scanner.core.IpGenerator
import com.umbra.scanner.core.IpProtocol
import com.umbra.scanner.core.IpText
import com.umbra.scanner.core.NetFamily
import com.umbra.scanner.core.Presets
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.core.ScanPhase
import com.umbra.scanner.core.ScanResult
import com.umbra.scanner.engine.ScanEngine
import com.umbra.scanner.engine.ScanEngine.WitnessHit
import com.umbra.scanner.engine.ScanSink
import com.umbra.scanner.net.WarpAccount
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.IOException
import kotlin.random.Random

/**
 * v3.10 regression tests — THE "0 ALIVE on a recoverable network" release
 * (the user's screenshot: DONE · 0 ALIVE · 0/504 TESTED · 12S · scan
 * aborted with advice the user had to act on MANUALLY).
 *
 * Root causes fixed and guarded here:
 *  1. the v3.9 witness tail drew only from the FRONT of the generated pool
 *     — 100% IPv4 on a dual-stack scan, so "v4 WARP filtered · v6 passes"
 *     networks false-aborted before a single v6 probe (witness pool is now
 *     family-balanced)
 *  2. silence after the identity round aborted outright — the recovery
 *     ladder now sweeps EVERY canonical WARP port on the census + pool IPs
 *     (v4 first, then v6 twins) and re-aims the pool onto any answering
 *     path; only total silence still aborts, and the verdict then names the
 *     sweep coverage
 *  3. the re-aimed pool draws its ports from the PROVEN winners only (the
 *     port-choices generator overload)
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class Patch100Test {

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

    private fun endpointParams(
        count: Int = 4,
        family: NetFamily = NetFamily.V4,
        port: Int = 0,
    ) = ScanParams(
        mode = ScanMode.ENDPOINT,
        family = family,
        port = port,
        endpointsCount = count,
        warpAttempts = 1,
        tcpTimeoutMs = 300,          // engine coerces to the 2000ms wg floor
        concurrency = 8,
        udpNoise = false,
        speedTest = false,
    )

    private fun pair(ip: String, port: Int): EndpointPair {
        val bytes = IpText.literalToBytes(ip)!!
        return EndpointPair(Candidate(bytes), port)
    }

    private fun hit(ip: String, port: Int, rtt: Double = 50.0): WitnessHit =
        WitnessHit(pair(ip, port), rtt)

    private fun pairId(p: EndpointPair): String = "${p.candidate.text}:${p.port}"

    // ── the family-balanced witness pool ─────────────────────────────────

    @Test
    fun `witness pool is family balanced on a dual stack scan`() {
        val engine = ScanEngine()
        val seeds = Presets.WARP_SEED_ENDPOINTS.map { (ip, p) -> pair(ip, p) }
        val v4Tail = (1..6).map { pair("162.159.192.$it", 2408) }
        val v6Tail = (1..6).map { pair("2606:4700:d0::a29f:c00$it", 894) }
        val pool = engine.buildWitnessPool(seeds + v4Tail + v6Tail)

        assertEquals(seeds.size + 12, pool.size)
        assertEquals(seeds, pool.take(seeds.size))
        val tail = pool.drop(seeds.size)
        assertEquals(6, tail.count { it.candidate.protocol == IpProtocol.IPv4 })
        assertEquals(6, tail.count { it.candidate.protocol == IpProtocol.IPv6 })
    }

    @Test
    fun `witness pool stays all v4 when the scan has no v6 pairs`() {
        val engine = ScanEngine()
        val seeds = Presets.WARP_SEED_ENDPOINTS.map { (ip, p) -> pair(ip, p) }
        val v4Tail = (1..20).map { pair("188.114.96.$it", 2408) }
        val pool = engine.buildWitnessPool(seeds + v4Tail)
        assertEquals(seeds.size + 12, pool.size)
        assertTrue(pool.drop(seeds.size).all { it.candidate.protocol == IpProtocol.IPv4 })
    }

    @Test
    fun `witness pool is all v6 on a v6-only scan`() {
        val engine = ScanEngine()
        val seeds = Presets.WARP_SEED_ENDPOINTS.map { (ip, p) -> pair(ip, p) }
        val v6Tail = (1..20).map { pair("2606:4700:d1::${it}0", 500) }
        val pool = engine.buildWitnessPool(seeds + v6Tail)
        assertEquals(seeds.size + 12, pool.size)
        assertTrue(pool.drop(seeds.size).all { it.candidate.protocol == IpProtocol.IPv6 })
    }

    // ── the recovery sweep grid ───────────────────────────────────────────

    @Test
    fun `v4 sweep grid covers every canonical port on census and pool ips`() {
        val engine = ScanEngine()
        val seeds = Presets.WARP_SEED_ENDPOINTS.map { (ip, p) -> pair(ip, p) }
        val poolTail = (1..10).map { pair("8.34.146.$it", 2408) }
        val grid = engine.buildSweepPool(seeds + poolTail, v6 = false)

        val ips = grid.map { it.candidate.text }.distinct()
        // 3 census IPs + 2 drawn pool IPs
        assertEquals(3 + ScanEngine.SWEEP_EXTRA_POOL_IPS, ips.size)
        assertTrue(ips.containsAll(Presets.WARP_SEED_V4))
        // EVERY canonical WARP port is probed on every IP
        for (ip in ips) {
            val ports = grid.filter { it.candidate.text == ip }.map { it.port }
            assertEquals(Presets.WARP_PORTS_FULL.toSet(), ports.toSet())
        }
        // deduplicated on ip:port
        assertEquals(grid.size, grid.map { "${it.candidate.text}:${it.port}" }.distinct().size)
    }

    @Test
    fun `v6 sweep grid is the embedded twins of the same ips`() {
        val engine = ScanEngine()
        val seeds = Presets.WARP_SEED_ENDPOINTS.map { (ip, p) -> pair(ip, p) }
        val grid = engine.buildSweepPool(seeds, v6 = true)

        assertTrue(grid.isNotEmpty())
        assertTrue(grid.all { it.candidate.protocol == IpProtocol.IPv6 })
        // 2606:4700:d0::a29f:c001 is the embedded twin of 162.159.192.1
        assertTrue(grid.any { it.candidate.text.equals("2606:4700:d0::a29f:c001", ignoreCase = true) })
        val v6Ports = grid.filter {
            it.candidate.text.equals("2606:4700:d0::a29f:c001", ignoreCase = true)
        }.map { it.port }.toSet()
        assertEquals(Presets.WARP_PORTS_FULL.toSet(), v6Ports)
    }

    @Test
    fun `sweep grid survives a pool with no v4 tail`() {
        val engine = ScanEngine()
        val seeds = Presets.WARP_SEED_ENDPOINTS.map { (ip, p) -> pair(ip, p) }
        val grid = engine.buildSweepPool(seeds, v6 = false)
        assertEquals(Presets.WARP_SEED_V4.size, grid.map { it.candidate.text }.distinct().size)
    }

    // ── the re-aim (pool rebuilt onto a proven path) ──────────────────────

    @Test
    fun `re-aim puts winners first and draws only winning ports`() {
        val engine = ScanEngine()
        val hits = listOf(
            hit("188.114.96.1", 894, rtt = 80.0),
            hit("162.159.192.42", 894, rtt = 60.0),
            hit("162.159.192.1", 928, rtt = 70.0),
        )
        val reAimed = engine.reAimPool(60, hits, NetFamily.V4, Random(7))

        assertEquals(60, reAimed.size)
        // the PROVEN pairs lead the pool
        assertEquals(hits.map { pairId(it.pair) }.toSet(), reAimed.take(3).map { pairId(it) }.toSet())
        // every drawn pair rides a winning port
        assertTrue(reAimed.drop(3).all { it.port in setOf(894, 928) })
        // v4 winners on a v4 scan: stays v4
        assertTrue(reAimed.all { it.candidate.protocol == IpProtocol.IPv4 })
    }

    @Test
    fun `re-aim flips a v4-configured scan onto v6 when only v6 answered`() {
        val engine = ScanEngine()
        val hits = listOf(
            hit("2606:4700:d0::a29f:c001", 928, rtt = 90.0),
            hit("2606:4700:d0::bc72:6001", 894, rtt = 40.0),
        )
        val reAimed = engine.reAimPool(40, hits, NetFamily.V4, Random(11))

        assertEquals(40, reAimed.size)
        assertTrue(reAimed.all { it.candidate.protocol == IpProtocol.IPv6 })
        assertTrue(reAimed.drop(2).all { it.port in setOf(894, 928) })
    }

    @Test
    fun `re-aim keeps both families when both answered and both were configured`() {
        val engine = ScanEngine()
        val hits = listOf(
            hit("188.114.96.1", 894, rtt = 80.0),
            hit("2606:4700:d0::a29f:c001", 928, rtt = 90.0),
        )
        val reAimed = engine.reAimPool(30, hits, NetFamily.BOTH, Random(3))
        assertEquals(30, reAimed.size)
        assertTrue(reAimed.any { it.candidate.protocol == IpProtocol.IPv4 })
        assertTrue(reAimed.any { it.candidate.protocol == IpProtocol.IPv6 })
        // both answer sides keep their own winning ports
        assertTrue(reAimed.all { it.port in setOf(894, 928) })
    }

    @Test
    fun `re-aim never returns fewer pairs than the winners themselves`() {
        val engine = ScanEngine()
        val hits = (1..10).map { hit("188.114.96.$it", 894) }
        val reAimed = engine.reAimPool(4, hits, NetFamily.V4, Random(5))
        assertEquals(hits.map { pairId(it.pair) }.toSet(), reAimed.map { pairId(it) }.toSet())
    }

    // ── the port-choices generator overload ──────────────────────────────

    @Test
    fun `generator draws every pair port from the choices menu`() {
        val drawn = IpGenerator.generateEndpoints(
            NetFamily.V4, 200, listOf(894, 928, 500), Random(9),
        )
        assertEquals(200, drawn.size)
        assertTrue(drawn.all { it.port in setOf(894, 928, 500) })
        // diversity: 200 draws over 3 ports must use more than one
        assertTrue(drawn.map { it.port }.distinct().size > 1)
        // no duplicate pairs
        assertEquals(200, drawn.map { pairId(it) }.distinct().size)
    }

    @Test
    fun `generator falls back to the canonical list on empty or invalid choices`() {
        val empty = IpGenerator.generateEndpoints(NetFamily.V4, 10, emptyList(), Random(1))
        assertTrue(empty.all { it.port in Presets.WARP_PORTS_FULL })
        val invalid = IpGenerator.generateEndpoints(NetFamily.V4, 10, listOf(0, -5, 70000), Random(2))
        assertTrue(invalid.all { it.port in Presets.WARP_PORTS_FULL })
    }

    @Test
    fun `pinned port generator behavior is unchanged through the new overload`() {
        val pinned = IpGenerator.generateEndpoints(NetFamily.V4, 30, 2408, Random(4))
        assertTrue(pinned.all { it.port == 2408 })
        val randomPorts = IpGenerator.generateEndpoints(NetFamily.V4, 30, 0, Random(4))
        assertTrue(randomPorts.all { it.port in Presets.WARP_PORTS_FULL })
    }

    // ── engine: the ladder flows (offline via seams) ─────────────────────

    @Test
    fun `port sweep rescues a port-filtered network - pool re-aimed and storm rolls`() = runBlocking {
        val engine = ScanEngine()
        val acc = fakeAccount()
        engine.registrationProvider = { _, _ -> acc }
        engine.witnessProber = { _, _, _ -> 0 }   // the configured path is silent
        engine.sweepProber = { _, pairs, _ ->
            // the FULL-PORT sweep finds a passing port on the census IPs
            pairs.filter { it.candidate.text == "188.114.96.1" && it.port == 894 }
                .map { WitnessHit(it, 55.0) }
        }
        val sink = RecordingSink()
        engine.run(endpointParams(count = 8, port = 2408), sink)

        // the ladder ran and said so
        assertTrue(sink.logs.any { it.contains("recovery sweep") && it.contains("full port grid") })
        assertTrue(sink.logs.any { it.contains("scan re-aimed") && it.contains("winning port(s) 894") })
        // the pool was rebuilt — onGenerated re-announced the re-aimed size
        assertEquals(8 + Presets.WARP_SEED_ENDPOINTS.size, sink.generated)
        // THE contract: the storm ROLLED (no abort) and probed the winning pair
        assertTrue(sink.phases.contains(ScanPhase.WG))
        assertTrue(sink.phases.contains(ScanPhase.DONE))
        assertFalse(sink.logs.any { it.contains("endpoint scan aborted") })
        assertTrue(sink.results.any { it.id == "188.114.96.1:894" })
    }

    @Test
    fun `v6 sweep rescues a v4-filtered network - scan flips onto v6`() = runBlocking {
        val engine = ScanEngine()
        val acc = fakeAccount()
        engine.registrationProvider = { _, _ -> acc }
        engine.witnessProber = { _, _, _ -> 0 }
        engine.sweepProber = { _, pairs, _ ->
            // v4 grid: silent. v6 grid: a twin answers.
            pairs.filter { it.candidate.protocol == IpProtocol.IPv6 && it.port == 928 }
                .map { WitnessHit(it, 120.0) }
        }
        val sink = RecordingSink()
        engine.run(endpointParams(count = 6, family = NetFamily.V4, port = 2408), sink)

        assertTrue(sink.logs.any { it.contains("scan re-aimed") && it.contains("ipv6") })
        assertTrue(sink.phases.contains(ScanPhase.WG))
        assertFalse(sink.logs.any { it.contains("endpoint scan aborted") })
        // the v6 twins of the seeds were probed by the re-aimed storm
        assertTrue(sink.results.any { it.protocol == IpProtocol.IPv6 })
    }

    @Test
    fun `sweep that answers with the stored identity proves the key alive`() = runBlocking {
        val engine = ScanEngine()
        val stale = fakeAccount(seed = 1)
        engine.registrationProvider = { _, fresh ->
            if (fresh) throw IOException("registration api unreachable")
            stale
        }
        engine.witnessProber = { _, _, _ -> 0 }
        engine.sweepProber = { _, pairs, _ ->
            pairs.filter { it.port == 500 }.take(1).map { WitnessHit(it, 60.0) }
        }
        val sink = RecordingSink()
        engine.run(endpointParams(count = 6, port = 2408), sink)

        // the stored identity answered the sweep — it is NOT dead, the
        // configured path was the filtered part
        assertTrue(sink.logs.any {
            it.contains("recovery sweep answered with the STORED identity")
        })
        assertTrue(sink.phases.contains(ScanPhase.WG))
        assertFalse(sink.logs.any { it.contains("identity may be expired") })
    }

    @Test
    fun `v6 sweep only runs after the v4 grid found nothing`() = runBlocking {
        val engine = ScanEngine()
        val acc = fakeAccount()
        engine.registrationProvider = { _, _ -> acc }
        engine.witnessProber = { _, _, _ -> 0 }
        var v4Rounds = 0
        var v6Rounds = 0
        engine.sweepProber = { _, pairs, _ ->
            if (pairs.all { it.candidate.protocol == IpProtocol.IPv4 }) {
                v4Rounds++
                // the v4 grid answers immediately — the v6 round never runs
                pairs.filter { it.port == 894 }.take(2).map { WitnessHit(it, 40.0) }
            } else {
                v6Rounds++
                emptyList()
            }
        }
        val sink = RecordingSink()
        engine.run(endpointParams(count = 6, family = NetFamily.BOTH, port = 2408), sink)

        assertEquals(1, v4Rounds)
        assertEquals(0, v6Rounds)
        assertTrue(sink.phases.contains(ScanPhase.WG))
    }
}
