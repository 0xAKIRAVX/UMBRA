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
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * v3.7 LIVE test — the ENDPOINT scan path end-to-end against the real
 * Cloudflare WARP anycast pool (TCP only, exactly what a UDP-blocked
 * device runs). Runs only when UMBRA_LIVE_TEST=1 is set.
 */
class EndpointScanLiveTest {

    @Test
    fun `live endpoint scan finds alive TCP endpoints across the warp pool`() {
        assumeTrue(System.getenv("UMBRA_LIVE_TEST") == "1")
        // NOTE: this sandbox's egress only opens TCP :443 (verified: warp IPs
        // answer :443 in ~6ms; 2408/894 time out HERE but work on real phones),
        // so the end-to-end proof pins :443. Random-port behavior is pinned by
        // unit tests (pool membership, dedup, family split).
        val params = ScanParams(
            mode = ScanMode.ENDPOINT,
            family = NetFamily.BOTH,
            port = 443, // pinned — the provably-reachable port from this network
            endpointsCount = 120,
            tcpAttempts = 2,
            tcpTimeoutMs = 2500,
            concurrency = 64,
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

        check(ScanPhase.TCP in phases) { "engine never entered the TCP phase: ${logs.joinToString(" | ")}" }
        check(ScanPhase.DONE in phases) { "engine never completed: ${logs.joinToString(" | ")}" }

        val alive = results.filter { it.alive }
        check(alive.isNotEmpty()) {
            "endpoint scan found NOTHING alive — logs: ${logs.joinToString(" | ")}"
        }
        check(alive.all { it.latencyMs != null }) { "alive endpoints must carry a latency" }
        check(alive.all { it.port in com.umbra.scanner.core.Presets.WARP_PORTS_FULL })

        val ranked = SmartRanking.sort(alive, null)
        val best = ranked.first()
        println(
            "live endpoint scan: ${alive.size} alive of ${params.endpointsCount} · " +
                "v4 ${alive.count { it.protocol == com.umbra.scanner.core.IpProtocol.IPv4 }} · " +
                "v6 ${alive.count { it.protocol == com.umbra.scanner.core.IpProtocol.IPv6 }} · " +
                "best ${best.ip}:${best.port} ${"%.0f".format(best.latencyMs!!)}ms"
        )
    }

    @Test
    fun `live endpoint scan with RANDOM ports runs to an honest verdict`() {
        assumeTrue(System.getenv("UMBRA_LIVE_TEST") == "1")
        // Random ports from this sandbox will mostly time out (egress opens
        // :443 only) — the CONTRACT here is completion + an honest zero-result
        // diagnosis line, never a hang or a silent empty board.
        val params = ScanParams(
            mode = ScanMode.ENDPOINT,
            family = NetFamily.V4,
            port = 0, // RANDOM — BPB behavior
            endpointsCount = 40,
            tcpAttempts = 1,
            tcpTimeoutMs = 1200,
            concurrency = 32,
            tlsVerify = false,
            speedTest = false,
        )
        val logs = java.util.concurrent.ConcurrentLinkedQueue<String>()
        val phases = java.util.concurrent.ConcurrentLinkedQueue<ScanPhase>()
        val engine = ScanEngine()
        kotlinx.coroutines.runBlocking {
            engine.run(params, object : ScanSink {
                override fun onPhase(phase: ScanPhase) { phases.add(phase) }
                override fun onGenerated(count: Int) {}
                override fun onResult(result: ScanResult) {}
                override fun onActive(delta: Int) {}
                override fun onLog(line: String) { logs.add(line) }
                override fun snapshot(): List<ScanResult> = emptyList()
            })
        }
        check(ScanPhase.DONE in phases) { "engine never completed: ${logs.joinToString(" | ")}" }
        check(logs.any { it.startsWith("endpoint storm done") }) {
            "no completion line: ${logs.joinToString(" | ")}"
        }
        println("random-port endpoint scan verdict: ${logs.last()}")
    }
}
