package com.umbra.scanner.engine

import com.umbra.scanner.core.Candidate
import com.umbra.scanner.core.EndpointPair
import com.umbra.scanner.core.IpGenerator
import com.umbra.scanner.core.IpProtocol
import com.umbra.scanner.core.IpText
import com.umbra.scanner.core.Presets
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.core.ScanPhase
import com.umbra.scanner.core.ScanResult
import com.umbra.scanner.net.ExactIpHttps
import com.umbra.scanner.net.TcpProbe
import com.umbra.scanner.net.UdpEvidence
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
 * Phase 1  generate   — random candidates per CIDR (never full enumeration of big blocks);
 *                       ENDPOINT: BPB-style random ip:port pairs from the WARP ranges
 *                       (+ a handful of census-verified seed endpoints)
 * Phase 2  register   — ENDPOINT only: a SILENT WARP identity from
 *                       api.cloudflareclient.com. The identity is the handshake
 *                       KEY — internal plumbing, never a user-facing "WARP
 *                       section" (v3.8 removed that section entirely).
 * Phase 3  probe storm — ENDPOINT: a REAL WireGuard handshake per ip:port pair
 *                        over UDP (+ in-tunnel ping), ranked by RTT — the
 *                        BPB-Warp-Scanner method. A TCP connect proves nothing
 *                        on Cloudflare anycast (the v3.7 "fake endpoints"
 *                        lesson: every CF edge answers TCP :443 whether or
 *                        not it serves WARP on that port);
 *                        EDGE/CUSTOM: TCP handshake latency + jitter + loss
 * Phase 4  verify     — EDGE/CUSTOM: TLS cert verification (the DPI-fake filter)
 * Phase 5  speed      — exact-IP HTTPS download (SNI/Host = speed.cloudflare.com)
 *
 * Fully cooperative-cancellable: runInterruptible sockets abort on stop().
 */
class ScanEngine(private val random: Random = Random(System.nanoTime())) {

    companion object {
        /** v3.4: upper bound on simultaneously-live storm coroutines (the
         *  memory valve — the semaphore in [ScanParams.concurrency] remains
         *  the actual probing valve). */
        private const val LAUNCH_WINDOW = 2048

        /** v3.3 guard: extreme settings (deep endpoint count × retries) could
         *  silently queue a multi-hour UDP storm that looks exactly like a
         *  hang. */
        private const val PROBE_CAP = 120_000
    }

    /** v3.6: per-scan tally of WHY warp probes failed — a zero-result scan
     *  now explains itself ("handshake timeout ×4210 · icmp port-unreachable
     *  ×388") instead of looking silently broken. */
    private val warpFailures = java.util.concurrent.ConcurrentHashMap<String, Int>()

    /** v3.8 seam: independent UDP-egress evidence for the zero-result
     *  diagnosis. Tests inject outcomes without sockets; production gathers
     *  real NTP witnesses (see UdpEvidence). */
    internal var evidenceGatherer: suspend (Int) -> UdpEvidence.Evidence? =
        { t -> runCatching { UdpEvidence.gather(t) }.getOrNull() }

    suspend fun run(params: ScanParams, sink: ScanSink) = coroutineScope {
        _sink = sink
        warpFailures.clear()
        sink.onPhase(ScanPhase.GENERATING)
        // v3.8: ENDPOINT mode generates random ip:port PAIRS (BPB behavior),
        // prepended with a handful of census-verified seed endpoints so a
        // healthy network sees validated results within the first seconds.
        var endpointPairs: List<EndpointPair>? = null
        val candidates = if (params.mode == ScanMode.ENDPOINT) {
            val drawn = IpGenerator.generateEndpoints(
                params.family, params.endpointsCount, params.port, random,
            )
            val seeds = Presets.WARP_SEED_ENDPOINTS.mapNotNull { (ip, p) ->
                IpText.literalToBytes(ip)?.let { EndpointPair(Candidate(it), p) }
            }
            endpointPairs = seeds + drawn
            emptyList()
        } else {
            IpGenerator.generate(params.cidrs, params.family, params.samplesPerPrefix, random)
        }
        val ports = params.effectivePorts
        var pairCount = endpointPairs?.size ?: candidates.size * ports.size
        sink.onGenerated(pairCount)
        if (endpointPairs != null) {
            val v4 = endpointPairs.count { it.candidate.protocol == IpProtocol.IPv4 }
            val v6 = endpointPairs.size - v4
            sink.onLog(
                "generated ${endpointPairs.size} endpoints · v4 $v4 · v6 $v6 · " +
                    "${Presets.WARP_SEED_ENDPOINTS.size} live-verified seeds + " +
                    "${endpointPairs.size - Presets.WARP_SEED_ENDPOINTS.size} random" +
                    (if (params.port > 0) " · port ${params.port}" else " · random port each · ×${Presets.warpPortsCount()}")
            )
            if (endpointPairs.isEmpty()) {
                sink.onLog("no endpoints — raise the endpoint count")
                sink.onPhase(ScanPhase.DONE)
                return@coroutineScope
            }
        } else {
            sink.onLog(
                "generated ${candidates.size} candidates × ${ports.size} port(s) = $pairCount probes · port ${params.port}"
            )
            if (candidates.isEmpty() || ports.isEmpty()) {
                sink.onLog("no valid candidates — check CIDR list / port selection")
                sink.onPhase(ScanPhase.DONE)
                return@coroutineScope
            }
        }

        // ---- v3.8: ENDPOINT identity — one SILENT registration per scan ----
        // The WireGuard handshake needs a registered key (WARP responders drop
        // unknown keys without any reply — live-verified v3.6.1). This is
        // internal machinery: the account registers/reuses itself, the user
        // never sees a "WARP" section. Failure is honest and terminal — a
        // TCP-only fallback would produce exactly the fake endpoints v3.7
        // was reported for ("هیچ کدوم از اندپویت‌ها کار نمیکنن").
        var account: WarpAccount? = null
        if (params.mode == ScanMode.ENDPOINT) {
            sink.onPhase(ScanPhase.REGISTER)
            sink.onLog("warp identity · api.cloudflareclient.com (silent · reused 15 min · disk fallback)")
            account = try {
                registrationProvider(null)
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                sink.onLog("identity failed — ${e.message ?: "cloudflare unreachable"}")
                null
            }
            if (account == null) {
                sink.onLog(
                    "cannot validate endpoints without a warp identity — registration api " +
                        "unreachable and no stored identity · a tcp-only scan would produce " +
                        "endpoints that never work in wireguard (the v3.7 bug) · scan aborted"
                )
                sink.onPhase(ScanPhase.DONE)
                return@coroutineScope
            }
            sink.onLog("warp identity ready · handshake validation live")
        }

        // v3.3 guard: extreme settings (deep endpoint counts × retries) could
        // silently queue a multi-hour UDP storm. Cap the workload at a sane
        // ceiling and say so in the log.
        var trimmedByCap = false
        val effectiveCandidates: List<Candidate> = if (pairCount > PROBE_CAP) {
            trimmedByCap = true
            if (endpointPairs != null) {
                // endpoint pairs are trimmed directly — each pair is its own probe
                endpointPairs = endpointPairs.shuffled(random).take(PROBE_CAP)
                pairCount = endpointPairs.size
                emptyList()
            } else {
                // v3.4 fix: trim in RANDOM order — the generator emits blocks
                // sequentially (all v4 blocks first, then v6), so take(N) silently
                // biased every capped mega-sweep toward the first few 162.159.x
                // blocks and starved the newer 8.x ranges + v6 entirely.
                val trimmed = candidates.shuffled(random)
                    .take((PROBE_CAP / ports.size).coerceAtLeast(1))
                pairCount = trimmed.size * ports.size
                trimmed
            }
        } else {
            candidates
        }
        if (trimmedByCap) {
            sink.onLog("probe budget capped · $PROBE_CAP pairs max — trimmed to $pairCount")
        }
        sink.onGenerated(pairCount)

        // ---- probe storm: WG handshakes (ENDPOINT) or TCP (EDGE/CUSTOM) ----
        val isWg = params.mode == ScanMode.ENDPOINT && account != null
        sink.onPhase(if (isWg) ScanPhase.WG else ScanPhase.TCP)
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
        // one spawn path shared by cartesian scans (candidate × ports)
        // and BPB-style endpoint scans (pre-generated ip:port pairs).
        val spawn: suspend (Candidate, Int) -> Unit = { cand, p ->
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
                            if (isWg) {
                                stormCh.send(runCatching { probeWarp(account!!, cand, p, params) }
                                    .getOrElse { deadProbe(cand, p, params, it) })
                            } else {
                                stormCh.send(runCatching { probeTcp(cand, p, params) }
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
        val pairs = endpointPairs
        if (pairs != null) {
            for ((c, p) in pairs) spawn(c, p)
        } else {
            for (cand in effectiveCandidates) {
                for (p in ports) {
                    spawn(cand, p)
                }
            }
        }
        jobs.joinAll()
        stormCh.close()
        stormCollector.join()
        if (isWg) {
            // v3.8: the ENDPOINT completion line — v4/v6 split + handshake
            // totals tell the story at a glance, and a ZERO-result scan
            // diagnoses itself (probe failure classes + independent UDP
            // witnesses + VPN sensor) instead of looking silently broken.
            val snap = sink.snapshot()
            val alive4 = snap.count { it.alive && it.protocol == IpProtocol.IPv4 }
            val alive6 = snap.count { it.alive && it.protocol == IpProtocol.IPv6 }
            val handshakes = snap.sumOf { it.wgHandshakes }
            val pings = snap.sumOf { it.successfulAttempts }
            var line = "endpoint scan done · ${alive4 + alive6} validated of $pairCount " +
                "(v4 $alive4 · v6 $alive6 · handshakes $handshakes · in-tunnel pings $pings)"
            if (alive4 + alive6 == 0) {
                if (warpFailures.isNotEmpty()) {
                    val reasons = warpFailures.entries.sortedByDescending { it.value }
                        .take(3).joinToString(" · ") { "${it.key} ×${it.value}" }
                    line += " — $reasons"
                }
                line += evidenceDiagnosis(maxOf(1200, params.tcpTimeoutMs))
            }
            sink.onLog(line)
        } else {
            val tcpAlive = sink.snapshot().count { it.tcpAlive }
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
        // ENDPOINT mode always measures on :443 — every WARP IP is also a
        // normal CF edge there, while speed.cloudflare.com is never served on
        // the WARP ports. (Opt-in for endpoint mode; it is a bonus edge
        // measurement, not the validation itself.)
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
                        if (params.mode == ScanMode.ENDPOINT) " on :443 (edge bonus)" else " on :$speedPort"
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
                        // v3.1 fix: ENDPOINT endpoints ride the speed test on a
                        // DIFFERENT port (:443) than the one they were proven on —
                        // a failed bonus measurement must never taint an endpoint
                        // that already passed its own mode's alive proof.
                        error = if (mbps == null && params.mode != ScanMode.ENDPOINT) {
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
        if (params.mode == ScanMode.ENDPOINT && account != null) {
            runCatching { WarpRegistration.persistTimestampMark() }
        }

        sink.onPhase(ScanPhase.DONE)
    }

    /**
     * v3.8: zero-result ENDPOINT diagnosis — independent NTP witnesses
     * separate "no UDP at all" (VPN / ISP) from "Cloudflare filtered" from
     * "WARP-specific filtering"; an active system VPN hint rides along. Runs
     * ONLY on a zero-result scan, never on healthy ones.
     */
    private suspend fun evidenceDiagnosis(timeoutMs: Int): String {
        val parts = ArrayList<String>(2)
        val evidence = runCatching { evidenceGatherer(timeoutMs) }.getOrNull()
        if (evidence != null) parts.add(UdpEvidence.describe(evidence))
        VpnSensor.hint()?.let { parts.add(it.trim()) }
        return if (parts.isEmpty()) "" else parts.joinToString(" · ", prefix = " · ")
    }

    /** v3.6: registration seam — production registers via the real Cloudflare
     * API; tests inject an identity so engine-level flows run offline. */
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

    private suspend fun probeTcp(cand: Candidate, port: Int, params: ScanParams): ScanResult {
        val t = TcpProbe.probe(cand.bytes, port, params.tcpAttempts, params.tcpTimeoutMs)
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
     * REAL WARP endpoint validation (v3.8: THE endpoint probe): anti-DPI noise
     * burst → full WireGuard handshake → ICMP echo INSIDE the tunnel. A
     * handshake response alone proves the endpoint speaks WARP on this exact
     * port over UDP (alive); the in-tunnel ping is the bonus data-plane proof.
     * Latency = average ping RTT, falling back to average handshake RTT.
     */
    private suspend fun probeWarp(
        account: WarpAccount,
        cand: Candidate,
        port: Int,
        params: ScanParams,
    ): ScanResult {
        val probe = WarpProbe(
            account,
            noise = UdpNoiseConfig(enabled = params.udpNoise, count = params.noiseCount),
        )
        val t = probe.probe(
            cand.bytes,
            port,
            attempts = params.warpAttempts.coerceIn(1, 7),
            timeoutMs = params.tcpTimeoutMs.coerceAtLeast(2000),
            interAttemptDelayMs = 200,
        )
        classifyWarpProbe(t.handshakes, t.pings, t.cookieReplies, t.lastError)
            ?.let { key -> warpFailures.merge(key, 1, Int::plus) }
        return ScanResult(
            ip = cand.text,
            protocol = cand.protocol,
            port = port,
            latencyMs = t.avgPingMs ?: t.avgHandshakeMs,
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
