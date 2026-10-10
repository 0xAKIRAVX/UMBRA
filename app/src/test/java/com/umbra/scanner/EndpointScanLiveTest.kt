package com.umbra.scanner

import com.umbra.scanner.core.NetFamily
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.core.ScanPhase
import com.umbra.scanner.core.ScanResult
import com.umbra.scanner.core.SmartRanking
import com.umbra.scanner.engine.ScanEngine
import com.umbra.scanner.engine.ScanSink
import kotlinx.coroutines.runBlocking
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * v3.8 LIVE test — the ENDPOINT scan path end-to-end against the real
 * Cloudflare WARP anycast pool: identity registration → WireGuard handshake
 * validation → RTT ranking. This is the BPB-Warp-Scanner method, and the
 * exact contract the v3.7 release broke (TCP-alive "endpoints" that never
 * worked). Runs only when UMBRA_LIVE_TEST=1 is set.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class EndpointScanLiveTest {

    @Test
    fun `live endpoint scan validates real wireguard handshakes`() {
        assumeTrue(System.getenv("UMBRA_LIVE_TEST") == "1")
        // The prepended census-verified seeds guarantee handshake answers on
        // an open network; the random pool rides along to prove the storm.
        // Random ports stay ON (BPB behavior) — the seeds pin their own ports.
        val params = ScanParams(
            mode = ScanMode.ENDPOINT,
            family = NetFamily.BOTH,
            port = 0, // RANDOM — BPB behavior; seeds carry their own ports
            endpointsCount = 120,
            warpAttempts = 2,
            tcpTimeoutMs = 3000,
            concurrency = 64,
            udpNoise = true,
            tlsVerify = false,
            speedTest = false,
        )
        val logs = ConcurrentLinkedQueue<String>()
        val results = ConcurrentLinkedQueue<ScanResult>()
        val phases = ConcurrentLinkedQueue<ScanPhase>()

        val engine = ScanEngine()
        runBlocking {
            engine.run(params, object : ScanSink {
                override fun onPhase(phase: ScanPhase) { phases.add(phase) }
                override fun onGenerated(count: Int) {
                    logs.add("generated $count endpoints")
                }
                override fun onResult(result: ScanResult) { results.add(result) }
                override fun onActive(delta: Int) {}
                override fun onLog(line: String) { logs.add(line) }
                override fun snapshot(): List<ScanResult> = ArrayList(results)
            })
        }

        check(ScanPhase.REGISTER in phases) { "engine never registered an identity: ${logs.joinToString(" | ")}" }
        check(ScanPhase.WG in phases) { "engine never entered the WG phase: ${logs.joinToString(" | ")}" }
        check(ScanPhase.DONE in phases) { "engine never completed: ${logs.joinToString(" | ")}" }

        // THE v3.8 contract: alive endpoints are exactly the ones whose
        // WireGuard handshake ANSWERED — usable in real configs.
        val alive = results.filter { it.alive }
        check(alive.isNotEmpty()) {
            "endpoint scan validated NOTHING — logs: ${logs.joinToString(" | ")}"
        }
        check(alive.all { it.wgHandshakes > 0 }) {
            "alive rows must carry handshake proof (the anti-fake-endpoint contract)"
        }
        check(alive.all { it.latencyMs != null }) { "validated endpoints must carry an RTT" }
        check(alive.all { it.port in com.umbra.scanner.core.Presets.WARP_PORTS_FULL })

        // the prepended seeds must have had their chance (and on an open
        // network at least one answers — they are census-verified)
        val seedTexts = com.umbra.scanner.core.Presets.WARP_SEED_ENDPOINTS.map { it.first }
        val seedHits = alive.filter { it.ip in seedTexts }
        check(seedHits.isNotEmpty()) { "no prepended seed validated: ${logs.joinToString(" | ")}" }

        val ranked = SmartRanking.sort(alive, null)
        val best = ranked.first()
        println(
            "live endpoint scan: ${alive.size} handshake-validated of ${params.endpointsCount} · " +
                "v4 ${alive.count { it.protocol == com.umbra.scanner.core.IpProtocol.IPv4 }} · " +
                "v6 ${alive.count { it.protocol == com.umbra.scanner.core.IpProtocol.IPv6 }} · " +
                "seed hits ${seedHits.size} · " +
                "best ${best.ip}:${best.port} ${"%.0f".format(best.latencyMs!!)}ms"
        )
    }

    @Test
    fun `live endpoint scan completes with an honest verdict on a dead path`() {
        assumeTrue(System.getenv("UMBRA_LIVE_TEST") == "1")
        // A tiny scan with no seeds answering would still complete and carry
        // the zero-result diagnosis (probe tally + witness). From THIS network
        // the seeds answer, so the contract checked here is: completion,
        // a "endpoint scan done" line, and correct handshake accounting.
        val params = ScanParams(
            mode = ScanMode.ENDPOINT,
            family = NetFamily.V4,
            port = 0, // RANDOM
            endpointsCount = 40,
            warpAttempts = 1,
            tcpTimeoutMs = 1200,
            concurrency = 32,
            udpNoise = false,
            tlsVerify = false,
            speedTest = false,
        )
        val logs = java.util.concurrent.ConcurrentLinkedQueue<String>()
        val results = java.util.concurrent.ConcurrentLinkedQueue<ScanResult>()
        val phases = java.util.concurrent.ConcurrentLinkedQueue<ScanPhase>()
        val engine = ScanEngine()
        kotlinx.coroutines.runBlocking {
            engine.run(params, object : ScanSink {
                override fun onPhase(phase: ScanPhase) { phases.add(phase) }
                override fun onGenerated(count: Int) {}
                override fun onResult(result: ScanResult) { results.add(result) }
                override fun onActive(delta: Int) {}
                override fun onLog(line: String) { logs.add(line) }
                override fun snapshot(): List<ScanResult> = ArrayList(results)
            })
        }
        check(ScanPhase.DONE in phases) { "engine never completed: ${logs.joinToString(" | ")}" }
        check(logs.any { it.startsWith("endpoint scan done") }) {
            "no completion line: ${logs.joinToString(" | ")}"
        }
        // TCP-only fakes must never be reported (the v3.7 bug contract)
        check(results.filter { it.alive }.all { it.wgHandshakes > 0 })
        println("random-port endpoint scan verdict: ${logs.last()}")
    }

    @Test
    fun `live recovery sweep finds answering warp paths on the full port grid`() {
        assumeTrue(System.getenv("UMBRA_LIVE_TEST") == "1")
        // v3.10: the recovery-ladder machinery itself — the full-port sweep
        // grid (census + pool IPs × every canonical WARP port) against real
        // Cloudflare. On an open network this MUST find answering paths
        // (it is strictly wider than the witness that passes here); a zero
        // would mean the sweep — the fix for the "0 ALIVE · aborted" screen —
        // is itself broken.
        val engine = ScanEngine()
        val params = ScanParams(
            mode = ScanMode.ENDPOINT,
            family = NetFamily.V4,
            port = 0,
            endpointsCount = 8,
            warpAttempts = 1,
            tcpTimeoutMs = 3000,
            concurrency = 32,
            udpNoise = false,
            tlsVerify = false,
            speedTest = false,
        )
        val drawn = com.umbra.scanner.core.IpGenerator.generateEndpoints(
            NetFamily.V4, params.endpointsCount, 0,
        )
        val seeds = com.umbra.scanner.core.Presets.WARP_SEED_ENDPOINTS.mapNotNull { (ip, p) ->
            com.umbra.scanner.core.IpText.literalToBytes(ip)?.let {
                com.umbra.scanner.core.EndpointPair(com.umbra.scanner.core.Candidate(it), p)
            }
        }
        val grid = engine.buildSweepPool(seeds + drawn, v6 = false)
        check(grid.size >= 3 * com.umbra.scanner.core.Presets.warpPortsCount()) {
            "sweep grid too small: ${grid.size}"
        }
        val account = runBlocking {
            com.umbra.scanner.net.WarpRegistration.register()
        }
        val hits = runBlocking {
            engine.sweepProber(account, grid, 2500)
        }
        check(hits.isNotEmpty()) { "recovery sweep found NOTHING on an open network" }
        check(hits.all { it.pair.port in com.umbra.scanner.core.Presets.WARP_PORTS_FULL })
        val bestRtt = hits.firstOrNull { it.rttMs < Double.MAX_VALUE }?.rttMs
        println(
            "live recovery sweep: ${hits.size}/${grid.size} answered · " +
                "ports ${hits.map { it.pair.port }.distinct().sorted()} · " +
                "best ${bestRtt?.let { "%.0f".format(it) + "ms" } ?: "cookie"}"
        )
    }
}
