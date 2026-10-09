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
 * v3.6: buckets one probe outcome into a short failure class for the
 * zero-result diagnosis line. null = success (nothing to tally).
 * Pure function — unit-tested directly.
 */
internal fun classifyWarpProbe(
    handshakes: Int,
    pings: Int,
    cookieReplies: Int,
    lastError: String?,
): String? = when {
    pings > 0 -> null
    handshakes > 0 -> "handshake ok · no data plane"
    cookieReplies > 0 -> "cookie reply (alive under load)"
    else -> when (val e = lastError) {
        null -> "no handshake"
        else -> when {
            e.contains("timeout") -> "handshake timeout"
            e.contains("PortUnreachable") -> "icmp port-unreachable"
            e.contains("send refused") -> "udp send blocked"
            else -> e
        }
    }
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

    companion object {
        /** v3.4: upper bound on simultaneously-live storm coroutines (the
         *  memory valve — the semaphore in [ScanParams.concurrency] remains
         *  the actual probing valve). */
        private const val LAUNCH_WINDOW = 2048

        /** v3.6: pairs ceiling for scans whose port list was REWRITTEN by the
         *  pre-flight gate (a 16-port adaptation on default sampling would
         *  otherwise queue a ~17-minute storm on an already degraded network). */
        private const val ADAPTED_PROBE_CAP = 24_000
    }

    /** v3.6: per-scan tally of WHY warp probes failed — a zero-result scan
     *  now explains itself ("handshake timeout ×4210 · icmp port-unreachable
     *  ×388") instead of looking silently broken. */
    private val warpFailures = java.util.concurrent.ConcurrentHashMap<String, Int>()

    suspend fun run(params: ScanParams, sink: ScanSink) = coroutineScope {
        _sink = sink
        warpFailures.clear()
        sink.onPhase(ScanPhase.GENERATING)
        // v3.6.2: var — the pre-flight gate's IPv6 adaptation can regenerate
        // the pool on a proven family (see Outcome.AdaptFamily).
        var candidates = if (params.mode == ScanMode.WARP) {
            // WARP endpoints: v4 pool + v4-embedded v6 (d0/d1) — uniform /48
            // sampling can never hit the real 2606:4700:d0::a29f:xxxx pattern.
            IpGenerator.generateWarp(params.family, params.samplesPerPrefix, random)
        } else {
            IpGenerator.generate(params.cidrs, params.family, params.samplesPerPrefix, random)
        }
        var ports = params.effectivePorts
        var pairCount = candidates.size * ports.size
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
            val licenseKey = params.warpLicenseKey.trim()
            sink.onLog(
                "registering WARP identity · api.cloudflareclient.com" +
                    if (licenseKey.isNotEmpty()) " · warp+ key" else ""
            )
            account = try {
                val acc = registrationProvider(licenseKey.ifBlank { null })
                sink.onLog(
                    "warp identity ready · v6 ${acc.v6} · wg handshake mode (reserved=0, live-verified)" +
                        // v3.4: the WARP+ outcome is stated plainly — a placebo
                        // toggle is worse than no toggle.
                        when {
                            licenseKey.isEmpty() -> ""
                            acc.licenseApplied -> " · warp+ license applied"
                            else -> " · warp+ license NOT applied (key rejected or api blocked) — free warp tier"
                        }
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

        // ---- v3.6: pre-flight gate (WARP only) ----
        // Prove the path + identity + port in seconds BEFORE the storm; a
        // blocked network or stale identity aborts/adapts immediately instead
        // of burning the full scan duration and reporting "0 verified". See
        // WarpGate.kt for the decision tree.
        var adaptedByGate = false
        // v3.6.1: the gate could not prove the identity (API blocked + no
        // answer anywhere) — a zero-result scan then gets the identity-expiry
        // hint appended to its diagnosis line.
        var gateUnverifiable = false
        if (params.mode == ScanMode.WARP && account != null) {
            // v3.6.2: "scan anyway" — the gate can be disabled after a
            // Blocked verdict; the scan then runs to completion and the
            // zero-result tally line explains itself.
            if (!runCatching { WarpGate.gateEnabled() }.getOrDefault(true)) {
                sink.onLog("pre-flight gate disabled — scanning anyway (a blocked verdict will take the full scan)")
            } else {
            val gateTimeout = maxOf(2500, params.tcpTimeoutMs)
            when (val gate = WarpGate.check(account!!, params.port, gateTimeout) { sink.onLog(it) }) {
                is WarpGate.Outcome.Ok -> {
                    account = gate.account
                    sink.onLog(gate.note)
                }
                is WarpGate.Outcome.Adapt -> {
                    account = gate.account
                    ports = gate.ports
                    adaptedByGate = true
                    pairCount = candidates.size * ports.size
                    sink.onGenerated(pairCount)
                    sink.onLog(gate.note)
                }
                is WarpGate.Outcome.AdaptFamily -> {
                    // v3.6.2: v4 WARP is filtered but the gate PROVED v6
                    // answers — regenerate the candidate pool on v6 instead
                    // of scanning a mostly-dead v4 storm.
                    account = gate.account
                    candidates = IpGenerator.generateWarp(gate.family, params.samplesPerPrefix, random)
                    adaptedByGate = true
                    pairCount = candidates.size * ports.size
                    sink.onGenerated(pairCount)
                    sink.onLog("${gate.note} · ${candidates.size} ipv6 candidates × ${ports.size} port(s)")
                }
                is WarpGate.Outcome.Blocked -> {
                    sink.onLog(gate.note)
                    sink.onPhase(ScanPhase.DONE)
                    return@coroutineScope
                }
                is WarpGate.Outcome.Unverifiable -> {
                    account = gate.account
                    gateUnverifiable = true
                    sink.onLog(gate.note)
                }
            }
            }
        }

        // v3.3 guard: extreme settings (sweep × huge samples) could silently
        // queue hundreds of thousands of multi-second UDP probes — an
        // overnight "scan" that looks exactly like a hang. Cap the workload
        // at a sane ceiling, keep the verified ordering, and say so in the log.
        // (v3.6: runs AFTER the gate so an adapted port list is budgeted with
        // the tighter ADAPTED_PROBE_CAP — a 16-port adaptation must not queue
        // a ~17-minute storm on an already degraded network.)
        val PROBE_CAP = if (adaptedByGate) ADAPTED_PROBE_CAP else 120_000
        val effectiveCandidates: List<Candidate>
        if (pairCount > PROBE_CAP) {
            // v3.4 fix: trim in RANDOM order — the generator emits blocks
            // sequentially (all v4 blocks first, then v6), so take(N) silently
            // biased every capped mega-sweep toward the first few 162.159.x
            // blocks and starved the newer 8.x ranges + v6 entirely.
            effectiveCandidates = candidates.shuffled(random)
                .take((PROBE_CAP / ports.size).coerceAtLeast(1))
            pairCount = effectiveCandidates.size * ports.size
            sink.onLog(
                "probe budget capped · ${PROBE_CAP} pairs max — candidates trimmed to ${effectiveCandidates.size}"
            )
        } else {
            effectiveCandidates = candidates
        }
        sink.onGenerated(pairCount)

        // ---- probe storm: every (candidate, port) pair ----
        val isWarp = params.mode == ScanMode.WARP && account != null
        sink.onPhase(if (isWarp) ScanPhase.WG else ScanPhase.TCP)
        val active = AtomicInteger(0)
        val stormSem = Semaphore(params.concurrency.coerceIn(4, 500))
        val stormCh = Channel<ScanResult>(Channel.UNLIMITED)
        val stormCollector = launch(Dispatchers.Default) {
            for (r in stormCh) sink.onResult(r)
        }
        val jobs = ArrayList<Job>(LAUNCH_WINDOW)
        // v3.4 fix (OOM): a capped mega-sweep used to materialize ALL pair
        // coroutines up front — 120k suspended jobs plus a 120k-entry result
        // map was a guaranteed low-memory kill before the first probe even
        // answered. The launch window below keeps live jobs ≈ 2048; completed
        // jobs are compacted out of the list so the references stay bounded.
        val launchWindow = Semaphore(LAUNCH_WINDOW)
        for (cand in effectiveCandidates) {
            for (p in ports) {
                launchWindow.acquire()
                if (jobs.size >= LAUNCH_WINDOW) {
                    jobs.removeAll { it.isCompleted }
                }
                jobs.add(launch(Dispatchers.IO) {
                    try {
                        stormSem.withPermit {
                            active.incrementAndGet(); sink.onActive(1)
                            try {
                                // v3.3 fix (WARP crash, engine side): probeWarp/probeTcp
                                // used to be invoked bare — any exception they leaked
                                // (e.g. a SocketException from socket creation under fd
                                // pressure) cancelled the WHOLE coroutine scope and the
                                // scan died with "engine failure". Now a failed probe
                                // returns a dead-endpoint result and the storm rolls on.
                                if (isWarp) {
                                    // sweeping hits many ports per IP — keep the loss
                                    // statistics honest without tripling wall time
                                    val attempts = if (ports.size > 1) params.warpAttempts.coerceAtMost(2) else params.warpAttempts
                                    stormCh.send(runCatching { probeWarp(account!!, cand, p, attempts, params) }
                                        .getOrElse { deadProbe(cand, p, params, it) })
                                } else {
                                    val attempts = if (ports.size > 1 && params.tcpAttempts > 3) 3 else params.tcpAttempts
                                    stormCh.send(runCatching { probeTcp(cand, p, attempts, params) }
                                        .getOrElse { deadProbe(cand, p, params, it) })
                                }
                            } finally {
                                active.decrementAndGet(); sink.onActive(-1)
                            }
                        }
                    } finally {
                        launchWindow.release()
                    }
                })
            }
        }
        jobs.joinAll()
        stormCh.close()
        stormCollector.join()
        val tcpAlive = sink.snapshot().count { it.tcpAlive }
        if (isWarp) {
            val verified = sink.snapshot().count { it.alive }
            var line = "wg probe storm done · $verified verified of $pairCount (handshake + in-tunnel ping)"
            // v3.6: a zero-result WARP scan now says WHY — the top probe
            // failure classes are tallied live during the storm.
            if (verified == 0 && warpFailures.isNotEmpty()) {
                val reasons = warpFailures.entries.sortedByDescending { it.value }
                    .take(3).joinToString(" · ") { "${it.key} ×${it.value}" }
                line += " — $reasons"
            }
            // v3.6.1: a zero-result scan on an unverifiable identity points at
            // the identity itself — live-verified: WARP responders drop
            // unknown keys SILENTLY, so "all handshake timeout" is exactly
            // what an expired identity looks like from the outside.
            if (verified == 0 && gateUnverifiable) {
                line += " · stored identity may be expired — warp drops unknown keys " +
                    "without any reply; retry where the registration api is reachable"
            }
            sink.onLog(line)
        } else {
            sink.onLog("tcp storm done · $tcpAlive tcp-alive of $pairCount → tls verification next")
        }

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

        // ---- v3.6: persist the anti-replay timestamp high-water mark for
        // the identity this scan used — a restarted process that reuses the
        // disk identity then continues ABOVE the server's stored mark instead
        // of silently replaying (the "warp finds nothing after restart" bug).
        if (params.mode == ScanMode.WARP && account != null) {
            runCatching { WarpRegistration.persistTimestampMark() }
        }

        sink.onPhase(ScanPhase.DONE)
    }

    /** v3.6: registration seam — production registers via the real Cloudflare
     * API; tests inject an identity so engine-level gate flows run offline. */
    internal var registrationProvider: suspend (licenseKey: String?) -> WarpAccount =
        { key -> WarpRegistration.register(key) }

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

    /** Fallback result for a probe whose machinery itself threw — counted as a
     * dead endpoint so statistics stay honest while the scan keeps running. */
    private fun deadProbe(
        cand: Candidate,
        port: Int,
        params: ScanParams,
        e: Throwable,
    ): ScanResult = ScanResult(
        ip = cand.text,
        protocol = cand.protocol,
        port = port,
        packetLoss = 1.0,
        tcpAttempts = 1,
        successfulAttempts = 0,
        error = "probe ${e.javaClass.simpleName}",
        tlsSkipped = !params.tlsVerify,
        mode = params.mode,
    )

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
        classifyWarpProbe(t.handshakes, t.pings, t.cookieReplies, t.lastError)
            ?.let { key -> warpFailures.merge(key, 1, Int::plus) }
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
