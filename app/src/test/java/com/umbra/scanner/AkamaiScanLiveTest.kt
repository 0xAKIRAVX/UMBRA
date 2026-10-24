package com.umbra.scanner

import com.umbra.scanner.core.NetFamily
import com.umbra.scanner.core.Presets
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.core.ScanPhase
import com.umbra.scanner.core.ScanResult
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
 * v4.1 LIVE test — the AKAMAI scan path end-to-end against Akamai's real
 * production edge: TCP :443 storm over the published Akamai ranges → strict
 * TLS verification for SNI=www.akamai.com → latency ranking with the
 * throughput phase skipped (no Akamai metered endpoint exists).
 *
 * Runs only when UMBRA_LIVE_TEST=1. The candidate list prepends two
 * live-verified /32s (23.13.59.120 served a valid www.akamai.com certificate
 * in the 2026-10-23 recon; 184.51.102.209 is a current DNS answer for
 * www.akamai.com) so an open network is GUARANTEED TLS-verified results —
 * the rest of the draw proves the storm over the full Akamai pool the same
 * way the census seeds do for the ENDPOINT scan.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class AkamaiScanLiveTest {

    @Test
    fun `live akamai scan tls-verifies real akamai edges and ranks by latency`() {
        assumeTrue(System.getenv("UMBRA_LIVE_TEST") == "1")
        // two live-verified /32s first, then the full published pool
        val cidrs = listOf("23.13.59.120/32", "184.51.102.209/32") +
            Presets.cidrsFor(ScanMode.AKAMAI, NetFamily.V4) // v4 only: the CI sandbox has no v6 route
        val params = ScanParams(
            mode = ScanMode.AKAMAI,
            cidrs = cidrs,
            family = NetFamily.V4,
            port = 443,
            samplesPerPrefix = 10,
            tcpAttempts = 2,
            tcpTimeoutMs = 2500,
            concurrency = 64,
            tlsVerify = true,
            verifyTopN = 400,
            // ON PURPOSE: proves the skip branch — akamai must rank by
            // latency and never attempt a download.
            speedTest = true,
        )
        val logs = ConcurrentLinkedQueue<String>()
        val results = ConcurrentLinkedQueue<ScanResult>()
        val phases = ConcurrentLinkedQueue<ScanPhase>()

        val engine = ScanEngine()
        runBlocking {
            engine.run(params, object : ScanSink {
                override fun onPhase(phase: ScanPhase) { phases.add(phase) }
                override fun onGenerated(count: Int) { logs.add("generated $count candidates") }
                override fun onResult(result: ScanResult) { results.add(result) }
                override fun onActive(delta: Int) {}
                override fun onLog(line: String) { logs.add(line) }
                override fun snapshot(): List<ScanResult> = ArrayList(results)
            })
        }

        check(ScanPhase.TCP in phases) { "engine never ran the TCP storm: ${logs.joinToString(" | ")}" }
        check(ScanPhase.PROBE in phases) { "engine never ran the TLS verify: ${logs.joinToString(" | ")}" }
        check(ScanPhase.RANKING in phases) { "the skip branch must still walk the bar through RANKING" }
        check(ScanPhase.DONE in phases) { "engine never completed: ${logs.joinToString(" | ")}" }
        check(ScanPhase.SPEED !in phases) { "akamai scans must never run a throughput phase" }
        check(phases.none { it == ScanPhase.REGISTER || it == ScanPhase.WG }) {
            "akamai scans never register an identity or probe wireguard"
        }
        check(logs.any { it.contains("speed phase skipped") }) {
            "the honest skip line is missing: ${logs.joinToString(" | ")}"
        }
        check(logs.any { it.contains("www.akamai.com") }) {
            "the TLS verify log must name the akamai SNI: ${logs.joinToString(" | ")}"
        }

        // THE v4.1 contract: alive == TLS-cert-verified for www.akamai.com.
        val alive = results.filter { it.alive }
        check(alive.isNotEmpty()) {
            "no TLS-verified akamai edge — even the live-verified /32s failed; " +
                "the network filters akamai TLS: ${logs.joinToString(" | ")}"
        }
        check(alive.all { it.tlsSuccess }) { "alive without a TLS proof is the v3.7 fake-endpoint bug" }
        check(alive.all { it.latencyMs != null }) { "a latency-ranked mode must carry latency on every alive row" }
        check(alive.none { it.speedMbps != null }) { "no akamai row may claim a measured throughput" }
        check(alive.none { it.wgHandshakes > 0 }) { "no akamai row may claim a wireguard proof" }
        check(alive.map { it.ip }.containsAll(listOf("23.13.59.120", "184.51.102.209"))) {
            "the live-verified seed IPs did not validate: ${alive.map { it.ip }}"
        }

        // ranking sanity: best alive row is among the lowest latencies
        val fastest = results.filter { it.latencyMs != null }.minByOrNull { it.latencyMs!! }
        check(fastest == null || fastest.alive || fastest.tcpAlive) {
            "fastest row must at least be tcp-alive"
        }
        logs.forEach { println("[akamai-live] $it") }
        println("[akamai-live] alive=${alive.size} best=${alive.minByOrNull { it.latencyMs ?: Double.MAX_VALUE }?.ip}")
    }
}
