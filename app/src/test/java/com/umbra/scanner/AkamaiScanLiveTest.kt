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
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * v4.2 LIVE test — the AKAMAI scan path end-to-end against Akamai's real
 * production edge, with the v4.2 contracts:
 *
 *   TCP :443 storm over the live-census Akamai ranges → strict TLS
 *   verification for SNI=www.bing.com (the census-proven host: 9/9 edges
 *   served a valid cert + HTTP 200 + a real ~78 KB body — www.akamai.com
 *   only answers a 403 stub) → DEEP MEASURE (multi-sample ping/jitter/loss
 *   on the top verified rows) → REAL throughput on repeated bing page
 *   fetches (body-transfer time only).
 *
 * Runs only when UMBRA_LIVE_TEST=1. The candidate list prepends three
 * live-verified /32s (23.13.59.120 and 184.51.102.209 served BOTH a valid
 * www.bing.com certificate and HTTP 200 in the 2026-10-25 census;
 * 23.200.145.144 is a current DNS answer for www.akamai.com and also
 * serves bing) so an open network is GUARANTEED TLS-verified results.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class AkamaiScanLiveTest {

    @Test
    fun `live akamai scan - cert-validated, deep-measured, real throughput`() {
        assumeTrue(System.getenv("UMBRA_LIVE_TEST") == "1")
        // live-verified bing-serving /32s first, then the full census pool
        val cidrs = listOf("23.13.59.120/32", "184.51.102.209/32", "23.200.145.144/32") +
            Presets.cidrsFor(ScanMode.AKAMAI, NetFamily.V4) // v4 only: the CI sandbox has no v6 route
        val params = ScanParams(
            mode = ScanMode.AKAMAI,
            cidrs = cidrs,
            family = NetFamily.V4,
            port = 443,
            samplesPerPrefix = 8,
            tcpAttempts = 2,
            tcpTimeoutMs = 2500,
            concurrency = 64,
            tlsVerify = true,
            verifyTopN = 400,
            speedTest = true,
            speedTopN = 3,
            speedConcurrency = 2,
            downloadBytes = 512L * 1024,
            // v4.2: the deep-measure phase — the whole point of this release
            deepMeasure = true,
            deepTopN = 6,
            deepSamples = 4,
        )
        val logs = ConcurrentLinkedQueue<String>()
        // the store must MERGE by id exactly like the controller's sink —
        // the deep-measure phase re-emits rows for already-verified ips.
        val store = ConcurrentHashMap<String, ScanResult>()
        val phases = ConcurrentLinkedQueue<ScanPhase>()

        val engine = ScanEngine()
        runBlocking {
            engine.run(params, object : ScanSink {
                override fun onPhase(phase: ScanPhase) { phases.add(phase) }
                override fun onGenerated(count: Int) { logs.add("generated $count candidates") }
                override fun onResult(result: ScanResult) {
                    store.merge(result.id, result) { old, new -> old.merge(new) }
                }
                override fun onActive(delta: Int) {}
                override fun onLog(line: String) { logs.add(line) }
                override fun snapshot(): List<ScanResult> = ArrayList(store.values)
            })
        }

        check(ScanPhase.TCP in phases) { "engine never ran the TCP storm: ${logs.joinToString(" | ")}" }
        check(ScanPhase.PROBE in phases) { "engine never ran the TLS verify: ${logs.joinToString(" | ")}" }
        // v4.2 contract: the deep-measure phase runs and the speed phase
        // (repeated real-page fetches) is no longer skipped.
        check(ScanPhase.CALIBRATE in phases) {
            "the DEEP MEASURE phase never ran: ${logs.joinToString(" | ")}"
        }
        check(logs.any { it.startsWith("deep measure ·") }) { "missing the deep-measure start line" }
        check(logs.any { it.contains("deep measure done") }) { "missing the deep-measure completion line" }
        check(ScanPhase.SPEED in phases) {
            "akamai scans now run a REAL throughput phase (v4.2): ${logs.joinToString(" | ")}"
        }
        check(ScanPhase.DONE in phases) { "engine never completed: ${logs.joinToString(" | ")}" }
        check(phases.none { it == ScanPhase.REGISTER || it == ScanPhase.WG }) {
            "akamai scans never register an identity or probe wireguard"
        }
        check(logs.any { it.contains("www.bing.com") }) {
            "the TLS verify log must name the census-proven akamai SNI: ${logs.joinToString(" | ")}"
        }
        check(logs.any { it.contains("repeated real-page fetches") }) {
            "the speed log must name the v4.2 akamai throughput method"
        }

        // THE v4.2 contract: alive == TLS-cert-verified for www.bing.com.
        val alive = store.values.filter { it.alive }
        check(alive.isNotEmpty()) {
            "no TLS-verified akamai edge — even the live-verified /32s failed; " +
                "the network filters akamai TLS: ${logs.joinToString(" | ")}"
        }
        check(alive.all { it.tlsSuccess }) { "alive without a TLS proof is the v3.7 fake-endpoint bug" }
        check(alive.all { it.latencyMs != null }) { "every alive row must carry latency" }
        check(alive.none { it.wgHandshakes > 0 }) { "no akamai row may claim a wireguard proof" }
        check(alive.map { it.ip }.containsAll(listOf("23.13.59.120", "184.51.102.209"))) {
            "the live-verified seed IPs did not validate: ${alive.map { it.ip }}"
        }
        // deep-measured rows carry multi-sample attempts + real jitter
        check(alive.any { it.tcpAttempts >= params.deepSamples }) {
            "the deep measure must leave multi-sample attempt counts on the rows"
        }
        check(alive.any { it.jitterMs != null }) {
            "deep-measured rows must carry real jitter numbers"
        }
        // v4.2: the throughput is REAL now — at least one alive row measured
        // Mbps on repeated bing page fetches.
        check(alive.any { (it.speedMbps ?: 0.0) > 0.0 }) {
            "expected ≥1 real-throughput measurement (bing real-page fetches): " +
                alive.joinToString { "${it.ip} spd=${it.speedMbps}" }
        }

        logs.forEach { println("[akamai-live] $it") }
        alive.sortedBy { it.latencyMs ?: Double.MAX_VALUE }.take(5).forEach {
            println(
                "[akamai-live] ${it.ip} · lat ${it.latencyMs} · jit ${it.jitterMs} · " +
                    "loss ${it.packetLoss} · ${it.speedMbps} Mbps"
            )
        }
    }
}
