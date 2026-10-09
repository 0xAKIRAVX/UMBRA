package com.umbra.scanner.engine

import com.umbra.scanner.core.IpGenerator
import com.umbra.scanner.core.IpText
import com.umbra.scanner.core.NetFamily
import com.umbra.scanner.core.Presets
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
 * Outcomes:
 *  - [Outcome.Ok]            path + identity proven (seed OR random endpoint)
 *  - [Outcome.Adapt]         primary port dead → a wg-verified replacement
 *                            port list (scan continues on the working ports)
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
        data class Blocked(val note: String) : Outcome
        data class Unverifiable(val account: WarpAccount, val note: String) : Outcome
    }

    // ---- injectable seams (tests replace these; production defaults are real) ----

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
            // known-good identity + silence everywhere on the primary port →
            // per-port blocking? sweep every canonical WARP port across the
            // seeds AND random pool endpoints.
            log("preflight · fresh identity silent on :$primaryPort — sweeping warp ports")
            val working = runCatching { portSweeper(fresh, timeoutMs) }.getOrDefault(emptyMap())
            if (working.isEmpty()) {
                return@coroutineScope Outcome.Blocked(
                    "warp unreachable on this network — udp to cloudflare warp is blocked or dropped " +
                        "(fresh identity, ${seeds.size + pool.size} endpoints × every canonical port tried, " +
                        "zero replies; try EDGE mode or a different network)",
                )
            }
            return@coroutineScope Outcome.Adapt(fresh, working.keys.sorted(), adaptNote(primaryPort, working.keys))
        }

        // round 3 — registration API unreachable (API-blocked network).
        // Sweep with the ORIGINAL identity: a single answering port proves it.
        log("preflight · registration api unreachable — sweeping warp ports with stored identity")
        val working = runCatching { portSweeper(account, timeoutMs) }.getOrDefault(emptyMap())
        if (working.isEmpty()) {
            return@coroutineScope Outcome.Unverifiable(
                account,
                "identity unverifiable · registration api unreachable and no warp endpoint answers — " +
                    "either udp is filtered here, or the stored identity expired (warp servers drop " +
                    "unknown keys SILENTLY, no error). if the scan comes back empty, retry on a network " +
                    "where the api works so a fresh identity can register (EDGE mode still works)",
            )
        }
        Outcome.Adapt(account, working.keys.sorted(), adaptNote(primaryPort, working.keys))
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
