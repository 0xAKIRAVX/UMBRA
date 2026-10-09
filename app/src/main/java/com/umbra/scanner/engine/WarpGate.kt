package com.umbra.scanner.engine

import com.umbra.scanner.core.IpText
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

/**
 * v3.6 — WARP pre-flight gate.
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
 * Outcomes:
 *  - [Outcome.Ok]            path + identity proven on the primary port
 *  - [Outcome.Adapt]         primary port dead → a wg-verified replacement
 *                            port list (scan continues on the working ports)
 *  - [Outcome.Blocked]       UDP to WARP is blackholed on this network →
 *                            abort early with an actionable diagnosis
 *  - [Outcome.Unverifiable]  registration API unreachable + no handshake
 *                            evidence (API-blocked networks) → continue, but
 *                            the user is told what "empty" would mean
 *
 * Seed probes use 2 attempts each against two independent anycast seeds
 * (transient loss cannot fail the gate), run in parallel, and disable the
 * anti-DPI noise burst (it is pointless overhead for a two-packet check).
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

        // round 1 — current identity, both seeds in parallel
        val r1 = seeds.map { seed ->
            async(Dispatchers.IO) {
                runCatching { seedProber(account, seed, primaryPort, timeoutMs) }.getOrNull()
            }
        }.awaitAll()
        if (r1.any { it?.answered == true }) {
            val best = r1.filterNotNull().filter { it.answered }
                .minByOrNull { it.pingMs ?: Double.MAX_VALUE }
            return@coroutineScope Outcome.Ok(
                account,
                "preflight ok · warp path verified" +
                    (best?.pingMs?.let { " · seed rtt ${"%.0f".format(java.util.Locale.US, it)} ms" } ?: ""),
            )
        }

        // round 2 — identity suspect: force a brand-new registration
        log("preflight · seeds silent — trying a fresh warp identity")
        val fresh = runCatching { freshRegistrar() }.getOrNull()
        if (fresh != null) {
            val r2 = seeds.map { seed ->
                async(Dispatchers.IO) {
                    runCatching { seedProber(fresh, seed, primaryPort, timeoutMs) }.getOrNull()
                }
            }.awaitAll()
            if (r2.any { it?.answered == true }) {
                return@coroutineScope Outcome.Ok(
                    fresh,
                    "preflight ok · stored identity was stale — fresh identity registered",
                )
            }
            // known-good identity + silent seeds on the primary port →
            // per-port blocking? sweep every canonical WARP port.
            log("preflight · fresh identity silent on :$primaryPort — sweeping warp ports")
            val working = runCatching { portSweeper(fresh, timeoutMs) }.getOrDefault(emptyMap())
            if (working.isEmpty()) {
                return@coroutineScope Outcome.Blocked(
                    "warp unreachable on this network — udp to cloudflare warp is blocked or dropped " +
                        "(fresh identity, every canonical port tried; try EDGE mode or a different network)",
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
                "identity unverifiable · registration api unreachable and no warp port answers — " +
                    "if udp is filtered on this network the scan will come back empty (EDGE mode still works)",
            )
        }
        Outcome.Adapt(account, working.keys.sorted(), adaptNote(primaryPort, working.keys))
    }

    private fun adaptNote(primaryPort: Int, ports: Collection<Int>): String =
        "port $primaryPort is blocked on this network — adapted to ${ports.size} " +
            "wg-verified port(s): ${ports.take(6).joinToString("/")}${if (ports.size > 6) "…" else ""}"

    /** Real port sweep: one full WG handshake per (canonical port, seed). */
    private suspend fun sweepPorts(account: WarpAccount, timeoutMs: Int): Map<Int, Double> = coroutineScope {
        val seeds = Presets.WARP_SEED_V4.mapNotNull { IpText.literalToBytes(it) }
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

        val first = seeds.firstOrNull() ?: return@coroutineScope emptyMap()
        Presets.WARP_PORTS_FULL.map { port ->
            async(Dispatchers.IO) { sem.withPermit { probePort(port, first)?.let { port to it } } }
        }.awaitAll().filterNotNull().forEach { best[it.first] = it.second }

        val failed = Presets.WARP_PORTS_FULL.filter { it !in best }
        if (failed.isNotEmpty() && seeds.size > 1) {
            val second = seeds[1]
            failed.map { port ->
                async(Dispatchers.IO) { sem.withPermit { probePort(port, second)?.let { port to it } } }
            }.awaitAll().filterNotNull().forEach { best[it.first] = it.second }
        }
        best
    }
}
