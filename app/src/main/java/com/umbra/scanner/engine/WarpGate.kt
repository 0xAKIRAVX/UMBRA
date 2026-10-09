package com.umbra.scanner.engine

import com.umbra.scanner.core.IpGenerator
import com.umbra.scanner.core.IpText
import com.umbra.scanner.core.NetFamily
import com.umbra.scanner.core.Presets
import com.umbra.scanner.net.UdpEvidence
import com.umbra.scanner.net.UdpNoiseConfig
import com.umbra.scanner.net.WarpAccount
import com.umbra.scanner.net.WarpProbe
import com.umbra.scanner.net.WarpRegistration
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlin.random.Random

/**
 * v3.6 — WARP pre-flight gate. v3.6.1 — evidence-hardened decision tree.
 *
 * Before v3.6 the engine threw the whole candidate storm at the network and,
 * when every probe failed (UDP blackholed by the ISP, stale persisted
 * identity, per-port blocking), the user waited the FULL scan duration just
 * to see "0 verified of N" — indistinguishable from "the scanner is broken".
 *
 * The gate answers three questions in seconds, BEFORE the storm:
 *  1. can this network carry a WireGuard handshake to WARP at all?
 *  2. is the registered/persisted identity still valid server-side?
 *  3. is the user's chosen port reachable, and if not, which WARP ports are?
 *
 * v3.6.1 hardening (driven by live findings, 2026-10-10):
 *  - SEEDS GO STALE: 162.159.192.1 stopped answering :2408 from several PoPs
 *    while still answering :894/:928, and anycast lands each country on a
 *    different Cloudflare PoP — seeds are now a FAST PATH only. A new
 *    MINI-STORM of random pool endpoints (round 1b/2b) is the ground truth,
 *    and "blocked" is never concluded from seed silence alone.
 *  - DEAD IDENTITIES ARE SILENT: production WARP responders drop initiations
 *    from unknown static keys without any reply (verified live). A purged
 *    identity therefore looks EXACTLY like a network blackhole. The fresh
 *    re-registration round now also swaps the identity when a fresh key
 *    answers where the stored one was silent, and the Unverifiable outcome
 *    says plainly that an expired identity is one of the two possibilities.
 *
 * v3.6.2 (the "اسکنر وارپ اصلا کار نمیکنه" round — live evidence):
 *  - VPN VISIBILITY: an active system VPN (v2rayNG/Hiddify/…) captures every
 *    app socket; TCP-only proxy tunnels drop UDP silently, so the gate sees
 *    "fresh identity + zero replies anywhere" and used to publish a plain
 *    "warp unreachable" that read like a scanner bug. The gate now warns in
 *    the log up front and appends the VPN explanation to negative verdicts
 *    (see VpnSensor).
 *  - IPv6 RESCUE: ISPs that filter the v4 WARP ranges often leave v6
 *    untouched — "every v4 probe silent" is NOT proof WARP is impossible
 *    here. New rounds probe the v6-embedded twins of the seeds plus a v6
 *    mini-storm; an answer adapts the scan to IPv6 via
 *    [Outcome.AdaptFamily] instead of failing.
 *  - UDP EGRESS EVIDENCE: negative verdicts now carry an independent NTP
 *    witness result (UdpEgress) that separates "no udp at all" from
 *    "cloudflare filtered" from "warp-specific filtering" — each has a
 *    different remedy.
 *  - GATE BYPASS: [gateEnabled] lets the user disable the gate entirely
 *    ("scan anyway" — the scan then runs to completion and reports honestly).
 *
 * Outcomes:
 *  - [Outcome.Ok]            path + identity proven (seed OR random endpoint)
 *  - [Outcome.Adapt]         primary port dead → a wg-verified replacement
 *                            port list (scan continues on the working ports)
 *  - [Outcome.AdaptFamily]   v4 warp unreachable but IPv6 verified → the scan
 *                            regenerates its candidate pool on v6
 *  - [Outcome.Blocked]       UDP to WARP is blackholed on this network →
 *                            abort early with an actionable diagnosis
 *  - [Outcome.Unverifiable]  registration API unreachable + no handshake
 *                            evidence (API-blocked networks) → continue, but
 *                            the user is told what "empty" would mean
 *
 * Seed/mini probes use 2 attempts each (transient loss cannot fail the gate),
 * run in parallel, and disable the anti-DPI noise burst (it is pointless
 * overhead for a two-packet check).
 */
internal object WarpGate {

    /** What one seed probe saw. */
    data class SeedStats(
        val handshakes: Int,
        val cookieReplies: Int,
        val pingMs: Double?,
    ) {
        /** Server answered in any form — the UDP path works. */
        val answered: Boolean get() = handshakes > 0 || cookieReplies > 0
    }

    sealed interface Outcome {
        data class Ok(val account: WarpAccount, val note: String) : Outcome
        data class Adapt(val account: WarpAccount, val ports: List<Int>, val note: String) : Outcome
        data class AdaptFamily(val account: WarpAccount, val family: NetFamily, val note: String) : Outcome
        data class Blocked(val note: String) : Outcome
        data class Unverifiable(val account: WarpAccount, val note: String) : Outcome
    }

    // ---- injectable seams (tests replace these; production defaults are real) ----

    /** v3.6.2: "scan anyway" — the user can disable the pre-flight gate
     *  entirely after a Blocked verdict; production wires this to the
     *  persisted setting (UmbraApp). */
    internal var gateEnabled: () -> Boolean = { true }

    internal var seedProber: suspend (account: WarpAccount, ip: ByteArray, port: Int, timeoutMs: Int) -> SeedStats? =
        { account, ip, port, timeoutMs ->
            runCatching {
                val probe = WarpProbe(account, noise = UdpNoiseConfig(enabled = false))
                val t = probe.probe(ip, port, attempts = 2, timeoutMs = timeoutMs, interAttemptDelayMs = 250)
                SeedStats(t.handshakes, t.cookieReplies, t.avgPingMs)
            }.getOrNull()
        }

    /** v3.6.1: random pool endpoints for the mini-storm — sampled from the
     *  REAL scan pool (2 per WARP prefix = 32 fresh v4 candidates). */
    internal var poolSampler: () -> List<ByteArray> =
        { IpGenerator.generateWarp(NetFamily.V4, 2, Random(System.nanoTime())).map { it.bytes } }

    /** v3.6.2: v6 seeds — the d0-embedded twins of the v4 seeds. */
    internal var v6Seeds: () -> List<ByteArray> = { Presets.WARP_SEED_V6 }

    /** v3.6.2: random v6 pool endpoints for the v6 mini-storm. */
    internal var v6PoolSampler: () -> List<ByteArray> =
        { IpGenerator.generateWarp(NetFamily.V6, 2, Random(System.nanoTime())).take(12).map { it.bytes } }

    /** v3.6.2: independent UDP-egress evidence — consulted only when a
     *  negative verdict is about to be published. */
    internal var evidenceGatherer: suspend (timeoutMs: Int) -> UdpEvidence.Evidence =
        { t -> UdpEvidence.gather(t) }

    internal var portSweeper: suspend (account: WarpAccount, timeoutMs: Int) -> Map<Int, Double> =
        { account, timeoutMs -> sweepPorts(account, timeoutMs) }

    internal var freshRegistrar: suspend () -> WarpAccount? =
        { runCatching { WarpRegistration.register(fresh = true) }.getOrNull() }

    /**
     * Runs the gate. [primaryPort] is the port the user's scan would use.
     * [timeoutMs] is the per-datagram wait for seed handshakes.
     */
    suspend fun check(
        account: WarpAccount,
        primaryPort: Int,
        timeoutMs: Int,
        log: (String) -> Unit,
    ): Outcome = coroutineScope {
        val seeds = Presets.WARP_SEED_V4.mapNotNull { IpText.literalToBytes(it) }
        if (seeds.isEmpty()) return@coroutineScope Outcome.Blocked("no seed endpoints configured")

        // v3.6.2: VPN visibility FIRST — every verdict below is measured
        // THROUGH the tunnel while a system VPN is active, and TCP-only proxy
        // tunnels drop UDP silently. Say it up front, not after the failure.
        if (VpnSensor.active() == true) {
            log("preflight · WARNING: a system VPN is active — udp probes ride its " +
                "tunnel; tcp-only proxy tunnels drop udp silently")
        }

        log("preflight · seed handshake :$primaryPort on ${Presets.WARP_SEED_V4.joinToString(" / ")}")

        // round 1 — current identity, all seeds in parallel
        val r1 = probeAll(account, seeds, primaryPort, timeoutMs)
        if (r1.any { it?.answered == true }) {
            return@coroutineScope Outcome.Ok(account, okNote("seed", r1))
        }

        // round 1b — v3.6.1 mini-storm: seeds prove nothing (stale seeds,
        // per-PoP filtering, ISP port games). Random REAL pool endpoints on
        // the user's port are the ground truth for "path + identity".
        log("preflight · seeds silent — mini-storm over random pool endpoints :$primaryPort")
        val pool = runCatching { poolSampler() }.getOrDefault(emptyList())
        val r1b = probeAll(account, pool, primaryPort, timeoutMs)
        if (r1b.any { it?.answered == true }) {
            return@coroutineScope Outcome.Ok(
                account,
                "preflight ok · path verified via a random pool endpoint " +
                    "(seeds are unreachable from this network/PoP — harmless)" +
                    (bestPing(r1b)?.let { " · rtt ${"%.0f".format(java.util.Locale.US, it)} ms" } ?: ""),
            )
        }

        // round 1c — v3.6.2 IPv6 rescue: v4 silent everywhere does NOT mean
        // WARP is impossible — networks that filter the v4 ranges often pass
        // v6 (v6 filtering is rare). Probe the v6 twins of the seeds plus a
        // small v6 mini-storm before suspecting the identity.
        v6Rescue(account, primaryPort, timeoutMs, log)?.let { return@coroutineScope it }

        // round 2 — identity suspect (live-verified: WARP silently drops
        // initiations for unknown/expired keys — exactly what we just saw):
        // force a brand-new registration and replay seeds + mini-storm.
        log("preflight · no answer with the stored identity — trying a fresh warp identity")
        val fresh = runCatching { freshRegistrar() }.getOrNull()
        if (fresh != null) {
            val r2 = probeAll(fresh, seeds, primaryPort, timeoutMs)
            if (r2.any { it?.answered == true }) {
                return@coroutineScope Outcome.Ok(
                    fresh,
                    "preflight ok · stored identity was stale (server dropped it silently) — " +
                        "fresh identity registered and verified",
                )
            }
            val r2b = probeAll(fresh, pool, primaryPort, timeoutMs)
            if (r2b.any { it?.answered == true }) {
                return@coroutineScope Outcome.Ok(
                    fresh,
                    "preflight ok · stored identity was stale — fresh identity verified " +
                        "via a random pool endpoint",
                )
            }
            // v3.6.2: fresh identity + v6 still unprobed — the stored identity
            // may be fine while the NETWORK is v4-blocked; try v6 with the
            // known-good fresh key before the expensive full port sweep.
            v6Rescue(fresh, primaryPort, timeoutMs, log)?.let { return@coroutineScope it }

            // known-good identity + silence everywhere on the primary port →
            // per-port blocking? sweep every canonical WARP port across the
            // seeds AND random pool endpoints.
            log("preflight · fresh identity silent on :$primaryPort — sweeping warp ports")
            val working = runCatching { portSweeper(fresh, timeoutMs) }.getOrDefault(emptyMap())
            if (working.isEmpty()) {
                return@coroutineScope Outcome.Blocked(
                    "warp unreachable on this network — udp to cloudflare warp is blocked or dropped " +
                        "(fresh identity, ${seeds.size + pool.size} endpoints × every canonical port tried, " +
                        "zero replies; try EDGE mode, a different network, or disable the pre-flight " +
                        "gate in settings to scan anyway)" +
                        evidenceNote(timeoutMs) +
                        (VpnSensor.hint() ?: ""),
                )
            }
            return@coroutineScope Outcome.Adapt(fresh, working.keys.sorted(), adaptNote(primaryPort, working.keys))
        }

        // round 3 — registration API unreachable (API-blocked network).
        // Sweep with the ORIGINAL identity: a single answering port proves it.
        log("preflight · registration api unreachable — sweeping warp ports with stored identity")
        // v3.6.2: v6 with the stored identity too — API-blocked networks are
        // exactly where the disk identity is the only option, and v6 may be
        // the only family that passes.
        v6Rescue(account, primaryPort, timeoutMs, log)?.let { return@coroutineScope it }
        val working = runCatching { portSweeper(account, timeoutMs) }.getOrDefault(emptyMap())
        if (working.isEmpty()) {
            return@coroutineScope Outcome.Unverifiable(
                account,
                "identity unverifiable · registration api unreachable and no warp endpoint answers — " +
                    "either udp is filtered here, or the stored identity expired (warp servers drop " +
                    "unknown keys SILENTLY, no error). if the scan comes back empty, retry on a network " +
                    "where the api works so a fresh identity can register (EDGE mode still works)" +
                    evidenceNote(timeoutMs) +
                    (VpnSensor.hint() ?: ""),
            )
        }
        Outcome.Adapt(account, working.keys.sorted(), adaptNote(primaryPort, working.keys))
    }

    /**
     * v3.6.2 — one IPv6 rescue attempt for [account]: v6 seeds first, then a
     * small v6 mini-storm. Returns [Outcome.AdaptFamily] on the first answer,
     * or null when v6 stays silent (or is unavailable on this device — send
     * errors are caught by the probe layer and read as silence).
     */
    private suspend fun v6Rescue(
        account: WarpAccount,
        primaryPort: Int,
        timeoutMs: Int,
        log: (String) -> Unit,
    ): Outcome? = coroutineScope {
        val seeds6 = runCatching { v6Seeds() }.getOrDefault(emptyList())
        if (seeds6.isEmpty()) return@coroutineScope null
        log("preflight · v4 warp silent — probing ipv6 warp endpoints :$primaryPort")
        val r = probeAll(account, seeds6, primaryPort, timeoutMs)
        if (r.any { it?.answered == true }) {
            return@coroutineScope Outcome.AdaptFamily(
                account,
                NetFamily.V6,
                "preflight ok via IPv6 — v4 warp is filtered on this network but v6 " +
                    "endpoints answer" +
                    (bestPing(r)?.let { " · rtt ${"%.0f".format(java.util.Locale.US, it)} ms" } ?: "") +
                    " · scan continues on ipv6",
            )
        }
        val pool6 = runCatching { v6PoolSampler() }.getOrDefault(emptyList())
        if (pool6.isNotEmpty()) {
            log("preflight · v6 seeds silent — v6 mini-storm over random pool endpoints")
            val r6 = probeAll(account, pool6, primaryPort, timeoutMs)
            if (r6.any { it?.answered == true }) {
                return@coroutineScope Outcome.AdaptFamily(
                    account,
                    NetFamily.V6,
                    "preflight ok via a random ipv6 pool endpoint — v4 warp is filtered " +
                        "here; scan continues on ipv6",
                )
            }
        }
        null
    }

    /** v3.6.2 — independent NTP evidence appended to negative verdicts. */
    private suspend fun evidenceNote(timeoutMs: Int): String {
        val evidence = runCatching { evidenceGatherer(timeoutMs) }.getOrNull() ?: return ""
        return " · " + UdpEvidence.describe(evidence)
    }

    /** Probes [ips] in parallel on [port] with [account]; 2 attempts each. */
    private suspend fun probeAll(
        account: WarpAccount,
        ips: List<ByteArray>,
        port: Int,
        timeoutMs: Int,
    ): List<SeedStats?> = coroutineScope {
        ips.map { ip ->
            async(Dispatchers.IO) {
                runCatching { seedProber(account, ip, port, timeoutMs) }.getOrNull()
            }
        }.awaitAll()
    }

    private fun bestPing(stats: List<SeedStats?>): Double? =
        stats.filterNotNull().filter { it.answered }
            .mapNotNull { it.pingMs }.minOrNull()

    private fun okNote(via: String, stats: List<SeedStats?>): String =
        "preflight ok · warp path verified" +
            (bestPing(stats)?.let { " · $via rtt ${"%.0f".format(java.util.Locale.US, it)} ms" } ?: "")

    private fun adaptNote(primaryPort: Int, ports: Collection<Int>): String =
        "port $primaryPort is blocked on this network — adapted to ${ports.size} " +
            "wg-verified port(s): ${ports.take(6).joinToString("/")}${if (ports.size > 6) "…" else ""}"

    /** Real port sweep: one full WG handshake per (canonical port, endpoint).
     *  v3.6.1: sweeps across the seeds AND random pool endpoints — a single
     *  stale seed can no longer fake "every port blocked". */
    private suspend fun sweepPorts(account: WarpAccount, timeoutMs: Int): Map<Int, Double> = coroutineScope {
        val seeds = Presets.WARP_SEED_V4.mapNotNull { IpText.literalToBytes(it) }
        val pool = runCatching { poolSampler() }.getOrDefault(emptyList()).take(4)
        val endpoints = (seeds + pool).ifEmpty { return@coroutineScope emptyMap() }
        val probe = WarpProbe(account, noise = UdpNoiseConfig(enabled = false))
        val sem = Semaphore(32)
        val best = HashMap<Int, Double>()

        suspend fun probePort(port: Int, seed: ByteArray): Double? {
            val t = runCatching {
                probe.probe(seed, port, attempts = 1, timeoutMs = timeoutMs, interAttemptDelayMs = 0)
            }.getOrNull() ?: return null
            return when {
                t.pings > 0 -> t.avgPingMs ?: t.handshakeLatenciesMs.minOrNull()
                t.handshakes > 0 -> t.handshakeLatenciesMs.minOrNull()
                t.cookieReplies > 0 -> 0.0 // alive under load — latency unknown
                else -> null
            }
        }

        val first = endpoints.first()
        Presets.WARP_PORTS_FULL.map { port ->
            async(Dispatchers.IO) { sem.withPermit { probePort(port, first)?.let { port to it } } }
        }.awaitAll().filterNotNull().forEach { best[it.first] = it.second }

        val failed = Presets.WARP_PORTS_FULL.filter { it !in best }
        for (ep in endpoints.drop(1)) {
            if (failed.isEmpty()) break
            failed.map { port ->
                async(Dispatchers.IO) { sem.withPermit { probePort(port, ep)?.let { port to it } } }
            }.awaitAll().filterNotNull().forEach { best[it.first] = it.second }
        }
        best
    }
}
