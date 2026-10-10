package com.umbra.scanner.engine

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
import kotlinx.coroutines.delay
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
 * v3.8.1: the ENDPOINT probe pool — the census-verified seeds first, then the
 * random draw with any seed pair that the draw happened to reproduce REMOVED
 * (the draw deduplicates against itself, but a pinned-port 500-endpoint scan
 * over the 4064-host v4 pool collides with a seed pair about half the time).
 * A duplicate pair would be probed twice while the result store deduplicates
 * by ip:port — the tested counter could then never reach the announced
 * candidate count (progress stuck under 100%) and the completion line
 * overcounted the pool. Pure function — unit-tested directly.
 */
internal fun assembleEndpointPool(
    seeds: List<EndpointPair>,
    drawn: List<EndpointPair>,
): List<EndpointPair> {
    if (seeds.isEmpty()) return drawn
    val seedIds = HashSet<String>(seeds.size * 2)
    for (s in seeds) seedIds.add("${s.candidate.text}:${s.port}")
    return seeds + drawn.filter { "${it.candidate.text}:${it.port}" !in seedIds }
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

        /** v3.9: pre-flight witness budget — one short round against the
         *  census seeds + random pool pairs. Handshake RTTs on live paths
         *  are well under a second (live census); 2 s leaves headroom for
         *  high-latency radios while keeping the whole gate under ~3 s. */
        internal const val WITNESS_TIMEOUT_MS = 2000

        /** v3.9: witness pool size — the 4 census seeds + this many random
         *  pool pairs. Small enough to be instant, large enough that a
         *  healthy-but-lossy path answers SOMETHING. */
        private const val WITNESS_RANDOM = 12

        /** v3.10: recovery-sweep budget per probe. The sweep's job is path
         *  DISCOVERY ("does ANY port on ANY known-good ip answer?"), not
         *  RTT measurement — 1.5 s is 3× a high-latency mobile round trip
         *  and keeps the worst-case ladder (witness + identity + witness +
         *  v4 sweep + v6 sweep) inside ~15 s. */
        internal const val SWEEP_TIMEOUT_MS = 1500

        /** v3.10: how many drawn pool IPs ride the sweep alongside the census
         *  seeds — spreads the sweep over more /24s so per-block filtering
         *  is distinguishable from per-port filtering. */
        internal const val SWEEP_EXTRA_POOL_IPS = 2
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
            // v3.8.1 fix: the random draw is deduplicated against ITSELF but
            // never against the seeds prepended here. With a pinned port the
            // drawn pool can contain a seed pair (a 500-endpoint scan on the
            // 4064-host v4 pool hits a seed pair ~50% of the time): the pair
            // was then probed TWICE, the duplicate result merged into the
            // first, and `tested` (unique ids) could never reach the announced
            // `candidates` — progress stuck at 99.8% and the completion line
            // overcounted the pool. Dedup on the pair id, seeds first.
            endpointPairs = assembleEndpointPool(seeds, drawn)
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
                registrationProvider(null, false)
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

        // ---- v3.9: pre-flight UDP witness gate (ENDPOINT only) ----
        // THE frozen-scan lesson, restated as a gate: v3.8 removed the WARP
        // mode and with it the v3.6.1 environment gate — on a network where
        // WARP UDP is filtered (the app's core audience runs exactly such
        // networks), the scan ground through the WHOLE pool with zero
        // feedback: 0/N tested · 0.0/s for minutes, the exact screen the
        // user screenshotted. The witness round answers the environment
        // question in ONE short budget: 16 mixed endpoints (the 4 census
        // seeds + 12 random pool pairs, v4 AND v6), single attempt, ~2 s —
        // if ANY of them answers (handshake or cookie), the path is live and
        // the storm rolls; if ALL stay silent, a fresh identity is tried once
        // (a server-side-dead key is silently dropped by every responder —
        // the v3.6.1 ghost-key census).
        //
        // v3.10 (THE "0 ALIVE on a filtered network" fix): silence after the
        // identity round no longer aborts. The v3.9 gate had two blind spots
        // that both false-aborted recoverable networks —
        //   1. the witness tail drew only from the FRONT of the pool, which
        //      is 100% IPv4 (the v6 pairs sit at the END of the generated
        //      list): on the classic Iranian mobile pattern "v4 WARP DPI-
        //      killed, v6 passes" the gate NEVER probed a single v6 pair.
        //   2. the configured port set was never widened: a pinned :2408
        //      scan on a port-filtering ISP died with "try: random ports"
        //      advice the user had to act on MANUALLY — the exact "بازم
        //      مشکل داره" loop.
        // The witness pool is now family-balanced, and after identity-round
        // silence the RECOVERY LADDER runs: a full-port sweep (every
        // canonical WARP port × census + pool IPs, v4 first, then the v6
        // twins) — any answering ip:port is a PROVEN path, the pool is
        // re-aimed onto the winning ports/family, and the storm rolls. Only
        // a network where nothing anywhere answers still aborts, and the
        // verdict then names the sweep coverage that proved it.
        if (params.mode == ScanMode.ENDPOINT && account != null && endpointPairs != null) {
            val witnessPairs = buildWitnessPool(endpointPairs)
            val witnessBudget = WITNESS_TIMEOUT_MS
            sink.onLog(
                "pre-flight witness · ${witnessPairs.size} mixed endpoints (v4+v6) · " +
                    "1 attempt × ${witnessBudget} ms"
            )
            var identity = account
            var answered = runCatching {
                witnessProber(identity, witnessPairs, witnessBudget)
            }.getOrDefault(0)
            if (answered > 0) {
                sink.onLog("pre-flight witness · $answered/${witnessPairs.size} answered · udp path live")
            } else {
                sink.onLog(
                    "pre-flight witness · 0/${witnessPairs.size} answered (seeds included) — " +
                        "re-registering a fresh identity to rule out a stale key"
                )
                val fresh = try {
                    registrationProvider(null, true)
                } catch (e: kotlinx.coroutines.CancellationException) {
                    throw e
                } catch (_: Exception) {
                    null
                }
                if (fresh != null) {
                    identity = fresh
                    answered = runCatching {
                        witnessProber(identity, witnessPairs, witnessBudget)
                    }.getOrDefault(0)
                }
                if (answered > 0) {
                    sink.onLog("pre-flight witness · fresh identity · $answered/${witnessPairs.size} answered · udp path live")
                    account = identity
                } else {
                    account = identity
                    // ---- v3.10: the recovery ladder (port sweep, v4 then v6) ----
                    // Runs with the FRESHEST identity available — even the
                    // stored one when the registration API is unreachable: a
                    // sweep that answers also proves that key is alive, which
                    // the witness alone could not.
                    val sweepV4 = buildSweepPool(endpointPairs, v6 = false)
                    val sweepV6 = buildSweepPool(endpointPairs, v6 = true)
                    var hits = runSweepRound(identity, sweepV4, "v4 · full port grid", sink)
                    if (hits.isEmpty()) {
                        hits = runSweepRound(identity, sweepV6, "v6 twins · full port grid", sink)
                    }
                    if (hits.isNotEmpty()) {
                        // a PROVEN path exists on this network — re-aim the
                        // scan onto it and roll the storm
                        val v4Hit = hits.any { it.pair.candidate.protocol == IpProtocol.IPv4 }
                        val v6Hit = hits.any { it.pair.candidate.protocol == IpProtocol.IPv6 }
                        val winningPorts = hits.map { it.pair.port }.distinct().sorted()
                        val reAimed = reAimPool(pairCount, hits, params.family, random)
                        endpointPairs = reAimed
                        pairCount = reAimed.size
                        sink.onGenerated(pairCount)
                        if (fresh == null) {
                            sink.onLog(
                                "recovery sweep answered with the STORED identity — the key is " +
                                    "alive, the scan's configured path was the filtered part"
                            )
                        }
                        sink.onLog(
                            "scan re-aimed · ${hits.size} proven ${if (v4Hit && v6Hit) "v4+v6" else if (v6Hit) "ipv6" else "v4"} " +
                                "path(s) → ${reAimed.size} pairs on winning port(s) " +
                                "${winningPorts.joinToString("/")} · storm rolling"
                        )
                    } else {
                        val sweepIps = sweepV4.map { it.candidate.text }.distinct().size +
                            sweepV6.map { it.candidate.text }.distinct().size
                        val why = if (fresh == null) {
                            "identity may be expired and the registration api is unreachable — " +
                                "a stored identity is the only one available on this network"
                        } else {
                            "warp udp is silent on this network even with a fresh identity"
                        }
                        sink.onLog("witness verdict · $why")
                        sink.onLog(evidenceDiagnosis(witnessBudget))
                        sink.onLog(
                            "endpoint scan aborted — ${pairCount} dead probes would only repeat " +
                                "this verdict · recovery sweep already covered " +
                                "${Presets.warpPortsCount()} ports × $sweepIps ips on v4+v6 · " +
                                "try: another network/isp · disconnect any active vpn"
                        )
                        sink.onPhase(ScanPhase.DONE)
                        return@coroutineScope
                    }
                }
            }
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
        // v3.9 (THE frozen-scan fix, engine side): the WG storm gets ELASTIC
        // probe lanes. Every probe coroutine is launched on this view and
        // every blocking socket call inside WarpProbe is dispatched through
        // it too — Dispatchers.IO.limitedParallelism(n) is the one kotlinx
        // dispatcher whose views grow BEYOND the default 64 threads, so a
        // concurrency-320 storm really gets 320 blocking lanes instead of
        // queueing every receive() behind 64 threads held for their full
        // timeout (the serialized 0/504 · 0.0/s screen). The TCP storm keeps
        // the plain IO pool: its per-probe blocking budget is one short
        // connect, not attempts × 2 × timeout.
        val lanes = params.concurrency.coerceIn(4, 500)
        val probeDispatcher = Dispatchers.IO.limitedParallelism(lanes)
        val stormSem = Semaphore(lanes)
        val stormCh = Channel<ScanResult>(Channel.UNLIMITED)
        val stormCollector = launch(Dispatchers.Default) {
            for (r in stormCh) sink.onResult(r)
        }
        val jobs = ArrayList<Job>(LAUNCH_WINDOW)
        // v3.9: WG storm heartbeat — while the storm grinds (all-dead pools
        // under big per-endpoint budgets), the stats card's tested/rate stay
        // at 0 UNTIL the first probe lands; the user saw exactly that as a
        // frozen app. The heartbeat line lands in the visible log every 10 s
        // while nothing has landed yet (and every 30 s afterwards), proving
        // liveness with real numbers: probes completed + lanes busy.
        val probed = AtomicInteger(0)
        val heartbeatJob = if (isWg) launch {
            var beat = 0
            while (true) {
                delay(10_000)
                beat++
                if (probed.get() == 0 || beat % 3 == 0) {
                    sink.onLog(
                        "wg storm · ${probed.get()}/$pairCount probed · " +
                            "${active.get()} lanes busy"
                    )
                }
            }
        } else null
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
            jobs.add(launch(probeDispatcher) {
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
                                stormCh.send(runCatching { probeWarp(account!!, cand, p, params, probeDispatcher) }
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
                if (isWg) probed.incrementAndGet()
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
        heartbeatJob?.cancel()
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

    /** v3.6 registration seam — production registers via the real Cloudflare
     * API; tests inject an identity so engine-level flows run offline.
     * v3.9: [fresh] forwards to [WarpRegistration.register]'s fresh flag so
     * the witness gate can self-heal a server-side-dead (stale) key. */
    internal var registrationProvider: suspend (licenseKey: String?, fresh: Boolean) -> WarpAccount =
        { key, fresh -> WarpRegistration.register(key, fresh = fresh) }

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
        probeDispatcher: kotlinx.coroutines.CoroutineDispatcher,
    ): ScanResult {
        val probe = WarpProbe(
            account,
            noise = UdpNoiseConfig(enabled = params.udpNoise, count = params.noiseCount),
            dispatcher = probeDispatcher,
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

    // ------------------------------------------------- v3.9/v3.10 witness --

    /**
     * The witness pool: the census-verified seeds FIRST (a healthy network
     * answers them within one RTT), then [WITNESS_RANDOM] pairs from the
     * scan's own random pool — family-balanced (v3.10): the generated pool
     * is ordered v4-block-then-v6-block, so the v3.9 `pool.take(16)` tail
     * was 100% IPv4 and the gate NEVER probed a v6 pair on a dual-stack
     * scan — exactly the "v4 WARP filtered · v6 passes" networks the gate
     * exists for. Pure function — unit-tested directly.
     */
    internal fun buildWitnessPool(pool: List<EndpointPair>): List<EndpointPair> {
        val seedCount = Presets.WARP_SEED_ENDPOINTS.size
        val seeds = pool.take(seedCount)
        val rest = pool.drop(seedCount)
        val v4 = rest.filter { it.candidate.protocol == IpProtocol.IPv4 }
        val v6 = rest.filter { it.candidate.protocol == IpProtocol.IPv6 }
        return when {
            v4.isEmpty() -> seeds + v6.take(WITNESS_RANDOM)
            v6.isEmpty() -> seeds + v4.take(WITNESS_RANDOM)
            else -> seeds +
                v4.take(WITNESS_RANDOM / 2) +
                v6.take(WITNESS_RANDOM - WITNESS_RANDOM / 2)
        }
    }

    /**
     * v3.10: one answering witness/sweep probe — the pair plus its measured
     * round-trip (handshake RTT when one completed; cookie replies carry no
     * latency, sort last).
     */
    data class WitnessHit(val pair: EndpointPair, val rttMs: Double)

    /**
     * v3.9 witness seam — production probes the pairs for real with the
     * elastic dispatcher (single attempt, short budget); tests inject the
     * answered count so the gate logic runs offline.
     */
    internal var witnessProber: suspend (WarpAccount, List<EndpointPair>, Int) -> Int =
        { acc, pairs, budgetMs -> runWitnessRoundDetailed(acc, pairs, budgetMs).size }

    /**
     * v3.10 sweep seam — production probes the sweep grid for real and
     * returns the ANSWERING pairs with RTTs; tests inject winners so the
     * re-aim flow runs offline.
     */
    internal var sweepProber: suspend (WarpAccount, List<EndpointPair>, Int) -> List<WitnessHit> =
        { acc, pairs, budgetMs -> runWitnessRoundDetailed(acc, pairs, budgetMs) }

    /**
     * v3.10: the recovery sweep grid — pure function. The census seed IPs
     * (spread across two /16s) plus [SWEEP_EXTRA_POOL_IPS] drawn pool IPs,
     * each crossed with EVERY canonical WARP port ([Presets.WARP_PORTS_FULL]).
     * [v6] selects the v4-embedded twins (2606:4700:d0::x) of the same IPs —
     * the live-verified v6 pattern. Deduplicated on ip:port.
     */
    internal fun buildSweepPool(pool: List<EndpointPair>, v6: Boolean): List<EndpointPair> {
        val seedIps = Presets.WARP_SEED_V4.mapNotNull { IpText.literalToBytes(it) }
        val seedTexts = seedIps.map { IpText.format(it) }.toHashSet()
        val poolIps = pool.drop(Presets.WARP_SEED_ENDPOINTS.size)
            .filter { it.candidate.protocol == IpProtocol.IPv4 }
            .map { it.candidate.text to it.candidate.bytes }
            .filter { (text, _) -> text !in seedTexts }
            .distinctBy { (text, _) -> text }
            .take(SWEEP_EXTRA_POOL_IPS)
            .map { (_, bytes) -> bytes }
        val ips = seedIps + poolIps
        val ports = Presets.WARP_PORTS_FULL
        val out = ArrayList<EndpointPair>(ips.size * ports.size)
        val seen = HashSet<String>(ips.size * ports.size * 2)
        for (ip in ips) {
            val cand = if (v6) {
                val bytes = IpGenerator.v6Embedded(Presets.WARP_V6_PREFIX_D0, ip) ?: continue
                Candidate(bytes)
            } else {
                Candidate(ip)
            }
            for (p in ports) {
                if (seen.add("${cand.text}:$p")) out.add(EndpointPair(cand, p))
            }
        }
        return out
    }

    /**
     * v3.10: rebuilds the scan pool onto a PROVEN path — pure function.
     * The sweep winners lead the pool (they are guaranteed answers on THIS
     * network, so validated results stream within the first seconds), the
     * rest is re-drawn randomly on the winning ports only — the family
     * follows what actually answered (a v4-configured scan whose only
     * answering path is v6 flips to v6; that is the recovery, logged by
     * the caller). Never returns fewer pairs than the winners themselves.
     */
    internal fun reAimPool(
        targetSize: Int,
        hits: List<WitnessHit>,
        configuredFamily: NetFamily,
        random: Random,
    ): List<EndpointPair> {
        val winners = hits.map { it.pair }
            .distinctBy { "${it.candidate.text}:${it.port}" }
        val winningPorts = hits.sortedBy { it.rttMs }
            .map { it.pair.port }
            .distinct()
            .ifEmpty { Presets.WARP_PORTS_FULL }
        val v4Won = winners.any { it.candidate.protocol == IpProtocol.IPv4 }
        val v6Won = winners.any { it.candidate.protocol == IpProtocol.IPv6 }
        val targetFamily = when {
            v4Won && v6Won -> NetFamily.BOTH
            v6Won -> NetFamily.V6
            else -> NetFamily.V4
        }
        // both families answered and the user asked for both — keep BOTH
        // halves; a one-sided answer overrides the configured family (that
        // IS the recovery) but never DOWNGRADES a both-family win.
        val family = if (v4Won && v6Won) configuredFamily else targetFamily
        val need = (targetSize - winners.size).coerceAtLeast(0)
        val drawn = IpGenerator.generateEndpoints(family, need, winningPorts, random)
        val winnerIds = winners.map { "${it.candidate.text}:${it.port}" }.toHashSet()
        return winners + drawn.filter { "${it.candidate.text}:${it.port}" !in winnerIds }
    }

    /** One sweep round, logged end-to-end — returns the answering pairs. */
    private suspend fun runSweepRound(
        identity: WarpAccount,
        pairs: List<EndpointPair>,
        label: String,
        sink: ScanSink,
    ): List<WitnessHit> {
        if (pairs.isEmpty()) return emptyList()
        sink.onLog(
            "recovery sweep · $label · ${pairs.map { it.candidate.text }.distinct().size} ips × " +
                "${pairs.map { it.port }.distinct().size} ports · 1 attempt × $SWEEP_TIMEOUT_MS ms"
        )
        val hits = runCatching { sweepProber(identity, pairs, SWEEP_TIMEOUT_MS) }
            .getOrDefault(emptyList())
        if (hits.isEmpty()) {
            sink.onLog("recovery sweep · $label · 0/${pairs.size} answered")
        } else {
            val best = hits.take(3).joinToString(" · ") {
                "${it.pair.candidate.text}:${it.pair.port}" +
                    (if (it.rttMs < Double.MAX_VALUE) " ${"%.0f".format(it.rttMs)}ms" else "")
            }
            sink.onLog("recovery sweep · $label · ${hits.size}/${pairs.size} answered · $best")
        }
        return hits
    }

    /**
     * One real witness/sweep round — returns the answering pairs (handshake
     * OR cookie-reply, the witness aliveness contract) sorted by RTT.
     */
    private suspend fun runWitnessRoundDetailed(
        acc: WarpAccount,
        pairs: List<EndpointPair>,
        budgetMs: Int,
    ): List<WitnessHit> = coroutineScope {
        // v3.10: up to 128 lanes — the sweep grid (up to ~300 pairs) must not
        // queue behind a small pool of 2-second receive() lanes, or the
        // recovery ladder itself becomes the frozen screen it exists to fix.
        val witnessDispatcher = Dispatchers.IO.limitedParallelism(pairs.size.coerceIn(4, 128))
        // A small always-on noise burst keeps the witness's traffic shape in
        // line with what the storm itself sends — a noise-less witness could
        // false-ABORT exactly the DPI-shaped networks the storm is tuned for
        // (false-pass is self-correcting: the storm just runs; false-abort
        // is the harmful direction).
        val witnessProbe = WarpProbe(
            acc,
            noise = UdpNoiseConfig(enabled = true, count = 3),
            dispatcher = witnessDispatcher,
        )
        val hits = java.util.concurrent.ConcurrentLinkedQueue<WitnessHit>()
        val jobs = pairs.map { pair ->
            launch(witnessDispatcher) {
                val st = runCatching {
                    witnessProbe.probe(
                        pair.candidate.bytes, pair.port,
                        attempts = 1, timeoutMs = budgetMs, interAttemptDelayMs = 0,
                    )
                }.getOrNull()
                if (st != null && (st.handshakes > 0 || st.cookieReplies > 0)) {
                    val rtt = st.handshakeLatenciesMs.firstOrNull()
                        ?: st.pingLatenciesMs.firstOrNull()
                        ?: Double.MAX_VALUE
                    hits.add(WitnessHit(pair, rtt))
                }
            }
        }
        jobs.joinAll()
        hits.sortedBy { it.rttMs }
    }
}
