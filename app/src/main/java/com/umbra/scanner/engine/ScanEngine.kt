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
import com.umbra.scanner.net.UdpNoiseConfig
import com.umbra.scanner.net.WarpAccount
import com.umbra.scanner.net.WarpProbe
import com.umbra.scanner.net.WarpRegistration
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
 * Phase 2  register   — WARP mode only: fresh account from api.cloudflareclient.com
 * Phase 3  probe storm — WARP: full WireGuard handshake + in-tunnel ICMP ping (UDP);
 *                        EDGE/CUSTOM: TCP handshake latency + jitter + loss
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

        // ---- WARP identity: one registration per scan (BPB warp.go flow) ----
        var account: WarpAccount? = null
        if (params.mode == ScanMode.WARP) {
            sink.onPhase(ScanPhase.REGISTER)
            sink.onLog("registering WARP identity · api.cloudflareclient.com")
            account = try {
                val acc = WarpRegistration.register()
                sink.onLog(
                    "warp identity ready · reserved ${acc.reserved.joinToString(".")} · v6 ${acc.v6}"
                )
                acc
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                sink.onLog("registration failed — ${e.message ?: "cloudflare unreachable"}")
                null
            }
            if (account == null) {
                sink.onLog("real validation needs a registered identity — scan aborted " +
                    "(results from a TCP-only scan would not work in WireGuard anyway)")
                sink.onPhase(ScanPhase.DONE)
                return@coroutineScope
            }
        }

        // ---- probe storm: every (candidate, port) pair ----
        val isWarp = params.mode == ScanMode.WARP && account != null
        sink.onPhase(if (isWarp) ScanPhase.WG else ScanPhase.TCP)
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
                            if (isWarp) {
                                // sweeping hits many ports per IP — keep the loss
                                // statistics honest without tripling wall time
                                val attempts = if (ports.size > 1) params.warpAttempts.coerceAtMost(2) else params.warpAttempts
                                stormCh.send(probeWarp(account!!, cand, p, attempts, params))
                            } else {
                                val attempts = if (ports.size > 1 && params.tcpAttempts > 3) 3 else params.tcpAttempts
                                stormCh.send(probeTcp(cand, p, attempts, params))
                            }
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
        val tcpAlive = sink.snapshot().count { it.tcpAlive }
        sink.onLog(
            if (isWarp) "wg probe storm done · ${sink.snapshot().count { it.alive }} verified of $pairCount" +
                " (handshake + in-tunnel ping)"
            else "tcp storm done · $tcpAlive tcp-alive of $pairCount → tls verification next"
        )

        // ---- TLS verification (EDGE/CUSTOM): the REAL aliveness filter ----
        // A TCP connect proves nothing on networks where DPI middleboxes
        // fake-accept every handshake (Iran/Russia/etc). Only a full TLS
        // handshake whose certificate validates for a real Cloudflare host
        // proves the endpoint is a genuine, usable edge.
        if (params.needsTlsPhase) {
            sink.onPhase(ScanPhase.PROBE)
            val pool = sink.snapshot().filter { it.tcpAlive }
            // Natural (arrival) order — deliberately NOT latency-sorted: on
            // censored networks fake-DPI endpoints win every latency race and
            // would crowd the real ones out of a sorted top-N.
            val targets = pool.take(params.verifyTopN.coerceIn(50, 2000))
            if (targets.isNotEmpty()) {
                sink.onLog(
                    "tls verifying ${targets.size}/${pool.size} tcp-alive · sni=${params.speedSni} · " +
                        "dpi-fake endpoints are discarded here"
                )
                mapInParallel(targets, 48) { r ->
                    val bytes = IpText.literalToBytes(r.ip) ?: return@mapInParallel null
                    val res = ExactIpHttps.tlsProbe(
                        bytes, r.port, params.speedSni,
                        connectTimeoutMs = params.tcpTimeoutMs.coerceAtLeast(1500),
                        readTimeoutMs = 6000,
                    )
                    r.copy(
                        tlsSuccess = res.ok,
                        tlsHandshakeMs = res.handshakeMs,
                        error = if (res.ok) null else res.error ?: "tls failed",
                    )
                }
                val verified = sink.snapshot().count { it.alive }
                val skipped = pool.size - targets.size
                sink.onLog(
                    "tls verify done · $verified real of ${pool.size} tcp-alive" +
                        (if (skipped > 0) " · $skipped skipped (cap ${params.verifyTopN})" else "")
                )
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
                        // v3.1 fix: WARP endpoints ride the speed test on a
                        // DIFFERENT port (:443) than the one they were proven on —
                        // a failed bonus measurement must never taint an endpoint
                        // that already passed handshake + in-tunnel ping.
                        error = if (mbps == null && params.mode != ScanMode.WARP) {
                            d.error ?: "no measurable throughput"
                        } else null,
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
            tlsSkipped = !params.tlsVerify,
            mode = params.mode,
        )
    }

    /**
     * REAL WARP validation: noise → WireGuard handshake → ICMP echo inside the
     * tunnel. An endpoint is alive only when data actually flows — the same
     * guarantee BPB-Warp-Scanner gives (its HTTP test rides a real xray tunnel).
     */
    private suspend fun probeWarp(
        account: WarpAccount,
        cand: Candidate,
        port: Int,
        attempts: Int,
        params: ScanParams,
    ): ScanResult {
        val probe = WarpProbe(
            account,
            noise = UdpNoiseConfig(enabled = params.udpNoise, count = params.noiseCount),
        )
        val t = probe.probe(
            cand.bytes,
            port,
            attempts = attempts.coerceIn(1, 7),
            timeoutMs = params.tcpTimeoutMs.coerceAtLeast(2000),
            interAttemptDelayMs = 200,
        )
        return ScanResult(
            ip = cand.text,
            protocol = cand.protocol,
            port = port,
            latencyMs = t.avgPingMs,
            jitterMs = t.jitterMs,
            packetLoss = t.loss,
            tcpAttempts = t.attempts,
            successfulAttempts = t.pings,
            wgHandshakes = t.handshakes,
            error = if (t.pings == 0) {
                when {
                    t.handshakes > 0 -> t.lastError ?: "handshake ok · no data plane"
                    t.cookieReplies > 0 -> "cookie reply · endpoint alive under load"
                    else -> t.lastError ?: "no handshake"
                }
            } else null,
            mode = params.mode,
        )
    }
}
