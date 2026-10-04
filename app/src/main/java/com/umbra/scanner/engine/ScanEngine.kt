package com.umbra.scanner.engine

import com.umbra.scanner.core.Candidate
import com.umbra.scanner.core.IpGenerator
import com.umbra.scanner.core.IpText
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.core.ScanPhase
import com.umbra.scanner.core.ScanResult
import com.umbra.scanner.net.ExactIpHttps
import com.umbra.scanner.net.TcpProbe
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.random.Random

interface ScanSink {
    fun onPhase(phase: ScanPhase)
    fun onGenerated(count: Int)
    fun onResult(result: ScanResult)
    fun onActive(delta: Int)
    fun onLog(line: String)
    fun snapshot(): List<ScanResult>
}

/**
 * UMBRA scan engine.
 * Phase 1  generate   — random candidates per CIDR (never full enumeration of big blocks)
 * Phase 2  tcp storm  — parallel handshake probes, latency + jitter + loss
 * Phase 3  tls probe  — optional exact-IP TLS verification (WARP endpoints)
 * Phase 4  speed      — exact-IP HTTPS download (SNI/Host = speed.cloudflare.com)
 *
 * Fully cooperative-cancellable: runInterruptible sockets abort on stop().
 */
class ScanEngine(private val random: Random = Random(System.nanoTime())) {

    suspend fun run(params: ScanParams, sink: ScanSink) = coroutineScope {
        _sink = sink
        sink.onPhase(ScanPhase.GENERATING)
        val candidates = if (params.mode == ScanMode.WARP) {
            // WARP endpoints: v4 pool + v4-embedded v6 (d0/d1) — uniform /48
            // sampling can never hit the real 2606:4700:d0::a29f:xxxx pattern.
            IpGenerator.generateWarp(params.family, params.samplesPerPrefix, random)
        } else {
            IpGenerator.generate(params.cidrs, params.family, params.samplesPerPrefix, random)
        }
        val ports = params.effectivePorts
        val pairCount = candidates.size * ports.size
        sink.onGenerated(pairCount)
        sink.onLog(
            "generated ${candidates.size} candidates × ${ports.size} port(s) = $pairCount probes" +
                if (ports.size > 1) " · sweep" else " · port ${params.port}"
        )
        if (candidates.isEmpty() || ports.isEmpty()) {
            sink.onLog("no valid candidates — check CIDR list / port selection")
            sink.onPhase(ScanPhase.DONE)
            return@coroutineScope
        }

        // ---- TCP storm: every (candidate, port) pair ----
        sink.onPhase(ScanPhase.TCP)
        val active = AtomicInteger(0)
        val stormSem = Semaphore(params.concurrency.coerceIn(4, 500))
        val stormCh = Channel<ScanResult>(Channel.UNLIMITED)
        val stormCollector = launch(Dispatchers.Default) {
            for (r in stormCh) sink.onResult(r)
        }
        val jobs = ArrayList<Job>(pairCount)
        for (cand in candidates) {
            for (p in ports) {
                jobs.add(launch(Dispatchers.IO) {
                    stormSem.withPermit {
                        active.incrementAndGet(); sink.onActive(1)
                        try {
                            // sweeping hits many ports per IP — 1 extra retry keeps
                            // the storm fast without blurring loss statistics
                            val attempts = if (ports.size > 1 && params.tcpAttempts > 3) 3 else params.tcpAttempts
                            stormCh.send(probeTcp(cand, p, attempts, params))
                        } finally {
                            active.decrementAndGet(); sink.onActive(-1)
                        }
                    }
                })
            }
        }
        jobs.joinAll()
        stormCh.close()
        stormCollector.join()
        val alive = sink.snapshot().count { it.alive }
        sink.onLog("tcp storm done · alive $alive / $pairCount")

        // ---- TLS verify (WARP endpoints, or edge without speed test) ----
        if (params.needsTlsPhase) {
            sink.onPhase(ScanPhase.PROBE)
            val targets = sink.snapshot().filter { it.alive }
                .sortedBy { it.latencyMs ?: Double.MAX_VALUE }
                .take(params.verifyTopN.coerceIn(5, 500))
            if (targets.isNotEmpty()) {
                sink.onLog("tls probing ${targets.size} endpoints · sni=${params.warpSni}")
                mapInParallel(targets, 12) { r ->
                    val bytes = IpText.literalToBytes(r.ip) ?: return@mapInParallel null
                    val res = ExactIpHttps.tlsProbe(
                        bytes, r.port, params.warpSni,
                        connectTimeoutMs = params.tcpTimeoutMs.coerceAtLeast(1500),
                        readTimeoutMs = 6000,
                    )
                    // WARP: some ports accept TCP but not TLS — that is still a
                    // usable endpoint, so the failure is downgraded to a note.
                    val soft = params.mode == ScanMode.WARP
                    r.copy(
                        tlsSuccess = res.ok,
                        tlsHandshakeMs = res.handshakeMs,
                        error = when {
                            res.ok -> null
                            soft && r.alive -> "tcp-only · tls n/a on :${r.port}"
                            else -> res.error
                        },
                    )
                }
            }
        }

        // ---- exact-IP HTTPS speed test ----
        // WARP mode always measures on :443 — every WARP IP is also a normal CF
        // edge there, while speed.cloudflare.com is never served on the WARP ports.
        if (params.speedTest) {
            sink.onPhase(ScanPhase.RANKING)
            val pool = sink.snapshot().filter { it.alive }
                .sortedBy { it.latencyMs ?: Double.MAX_VALUE }
                .take(params.speedTopN.coerceIn(5, 500))
            sink.onPhase(ScanPhase.SPEED)
            if (pool.isNotEmpty()) {
                val speedPort = params.speedPort
                sink.onLog(
                    "speed testing ${pool.size} endpoints · ${params.downloadMbLabel} MB via ${params.speedSni}" +
                        if (params.mode == ScanMode.WARP) " on :443" else " on :$speedPort"
                )
                mapInParallel(pool, params.speedConcurrency.coerceIn(1, 16)) { r ->
                    val bytes = IpText.literalToBytes(r.ip) ?: return@mapInParallel null
                    val d = ExactIpHttps.download(
                        bytes, speedPort, params.speedSni,
                        bytes = params.downloadBytes,
                        connectTimeoutMs = params.tcpTimeoutMs.coerceAtLeast(2000),
                        readTimeoutMs = 8000,
                        maxDurationMs = 15000,
                    )
                    val mbps = if (d.httpStatus == 200 && d.bytes > 0 && d.error == null) {
                        d.bytes * 8.0 / 1000.0 / d.durationMs
                    } else null
                    r.copy(
                        speedMbps = mbps,
                        downloadedBytes = d.bytes,
                        tlsSuccess = d.tlsOk || r.tlsSuccess,
                        tlsHandshakeMs = d.handshakeMs ?: r.tlsHandshakeMs,
                        httpStatus = d.httpStatus,
                        error = if (mbps == null) d.error ?: "no measurable throughput" else null,
                    )
                }
            }
        }

        sink.onPhase(ScanPhase.DONE)
    }

    /**
     * Runs [transform] over [items] with bounded parallelism on Dispatchers.IO and
     * feeds every non-null partial result into the collector channel (which drives
     * the sink on a single confined thread). Structured + cancellable.
     */
    private suspend fun mapInParallel(
        items: List<ScanResult>,
        parallelism: Int,
        transform: suspend (ScanResult) -> ScanResult?,
    ) = coroutineScope {
        val sem = Semaphore(parallelism)
        val ch = Channel<ScanResult>(Channel.UNLIMITED)
        val collector = launch(Dispatchers.Default) {
            for (r in ch) sinkHolder.onResult(r)
        }
        val jobs = ArrayList<Job>(items.size)
        for (item in items) {
            jobs.add(launch(Dispatchers.IO) {
                sem.withPermit {
                    val r = runCatching { transform(item) }.getOrNull()
                    if (r != null) ch.send(r)
                }
            })
        }
        jobs.joinAll()
        ch.close()
        collector.join()
    }

    private val sinkHolder: ScanSink get() = requireNotNull(_sink) { "engine not started" }
    private var _sink: ScanSink? = null

    private suspend fun probeTcp(cand: Candidate, port: Int, attempts: Int, params: ScanParams): ScanResult {
        val t = TcpProbe.probe(cand.bytes, port, attempts, params.tcpTimeoutMs)
        val lat = t.latenciesMs
        val total = lat.size + t.failures
        val loss = if (total == 0) 1.0 else t.failures.toDouble() / total
        return ScanResult(
            ip = cand.text,
            protocol = cand.protocol,
            port = port,
            latencyMs = lat.minOrNull(),
            jitterMs = TcpProbe.jitterOf(lat),
            packetLoss = loss,
            tcpAttempts = total,
            successfulAttempts = lat.size,
            error = if (lat.isEmpty()) (t.lastError ?: "unreachable") else null,
            mode = params.mode,
        )
    }
}
