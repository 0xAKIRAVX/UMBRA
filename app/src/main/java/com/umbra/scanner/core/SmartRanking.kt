package com.umbra.scanner.core

import com.umbra.scanner.net.NetGrade
import com.umbra.scanner.net.NetworkProfile
import kotlin.math.exp
import kotlin.math.ln

/**
 * SMART RANKING — endpoints scored for the user's OWN line.
 *
 * The fixed classic score (Ranking.scoreOf) treats every network the same.
 * This engine adapts to the measured [NetworkProfile]:
 *
 *   · baseline-relative latency — an endpoint 350 ms away is excellent for a
 *     300 ms Iranian line and terrible for a 40 ms European one, so ping is
 *     scored RELATIVE to the measured baseline, not against a fixed ruler.
 *   · grade-adaptive weights — excellent line → raw throughput dominates
 *     (everything is stable, speed is the differentiator); poor line →
 *     stability + low ping dominate (speed measurements on a lossy line are
 *     noise, and what the user actually needs is something that holds).
 */
object SmartRanking {

    data class Weights(
        val latency: Double,
        val stability: Double,
        val speed: Double,
    ) {
        init { require(latency + stability + speed > 0.0) }
    }

    /** Neutral profile ≈ the classic fixed weighting. */
    val NEUTRAL = Weights(0.34, 0.36, 0.30)

    fun weightsFor(profile: NetworkProfile?): Weights = when (profile?.grade) {
        null -> NEUTRAL
        NetGrade.EXCELLENT -> Weights(0.30, 0.20, 0.50)
        NetGrade.GOOD -> Weights(0.35, 0.25, 0.40)
        NetGrade.FAIR -> Weights(0.40, 0.35, 0.25)
        NetGrade.POOR -> Weights(0.45, 0.45, 0.10)
    }

    // ------------------------------------------------------- sub-scores ----

    /** 0..1 — latency relative to the user's measured baseline when known. */
    fun latencyScore(r: ScanResult, baselineMs: Double?): Double {
        val lat = r.latencyMs ?: return 0.0
        return if (baselineMs != null && baselineMs > 0.0) {
            val rel = lat / baselineMs
            // 1.0 at baseline, e^-0.55 ≈ 0.58 at 1.25×, e^-2.2 ≈ 0.11 at 2×
            exp(-2.2 * (rel - 1.0)).coerceIn(0.0, 1.0)
        } else {
            1.0 / (1.0 + lat / 100.0)
        }
    }

    /** 0..1 — loss dominates, jitter refines. Unknown jitter ≈ moderate. */
    fun stabilityScore(r: ScanResult): Double {
        val lossS = 1.0 - r.packetLoss.coerceIn(0.0, 1.0)
        val jit = r.jitterMs ?: 20.0
        val jitS = 1.0 / (1.0 + jit / 50.0)
        return 0.6 * lossS + 0.4 * jitS
    }

    /** 0..1 — logarithmic in Mbps (1 Mbps → 0.10 · 10 → 0.34 · 100 → 0.67 · 1000 → 1). */
    fun speedScore(r: ScanResult): Double {
        val spd = r.speedMbps ?: return 0.30
        if (spd <= 0.0) return 0.30
        return (ln(1.0 + spd) / ln(1001.0)).coerceAtMost(1.0)
    }

    // ------------------------------------------------------------- score ----

    /** 0..110 composite — adaptive weights + relative latency + TLS bonus. */
    fun score(r: ScanResult, profile: NetworkProfile?): Double {
        if (!r.alive) return 0.0
        val w = weightsFor(profile)
        val base = 100.0 * (
            w.latency * latencyScore(r, profile?.latencyMs) +
                w.stability * stabilityScore(r) +
                w.speed * speedScore(r)
            )
        return base + if (r.tlsSuccess) 10.0 else 0.0
    }

    /** Sort by the adaptive smart score (descending). */
    fun sort(results: List<ScanResult>, profile: NetworkProfile?): List<ScanResult> =
        results.sortedByDescending { score(it, profile) }

    // ------------------------------------------------------------- picks ----

    enum class PickKind { BEST, PING, STABLE, FAST }

    data class Picks(
        val best: ScanResult?,
        val ping: ScanResult?,
        val stable: ScanResult?,
        val fast: ScanResult?,
    ) {
        fun of(kind: PickKind): ScanResult? = when (kind) {
            PickKind.BEST -> best
            PickKind.PING -> ping
            PickKind.STABLE -> stable
            PickKind.FAST -> fast
        }
    }

    /**
     * The three askings of the user — پرسرعت‌ترین · پایدارترین · کمترین پینگ —
     * plus the adaptive best-overall, from one result set.
     */
    fun picks(results: List<ScanResult>, profile: NetworkProfile?): Picks {
        val alive = results.filter { it.alive }
        val best = alive.maxByOrNull { score(it, profile) }
        val ping = alive.asSequence()
            .filter { it.latencyMs != null }
            .minByOrNull { it.latencyMs!! }
        val stable = alive.sortedWith(
            compareBy(
                { it.jitterMs ?: Double.MAX_VALUE },
                { it.packetLoss },
                { it.latencyMs ?: Double.MAX_VALUE },
            )
        ).firstOrNull()
        val fast = alive.asSequence()
            .filter { (it.speedMbps ?: 0.0) > 0.0 }
            .maxByOrNull { it.speedMbps!! }
        return Picks(best, ping, stable, fast)
    }

    /** Verdict chip on a pick row: why THIS endpoint for THIS network. */
    fun reasonFor(kind: PickKind, profile: NetworkProfile?): ReasonKind = when (kind) {
        PickKind.BEST -> when (profile?.grade) {
            null -> ReasonKind.BEST_NEUTRAL
            NetGrade.EXCELLENT, NetGrade.GOOD -> ReasonKind.BEST_SPEEDY_LINE
            NetGrade.FAIR, NetGrade.POOR -> ReasonKind.BEST_ROUGH_LINE
        }
        PickKind.PING -> ReasonKind.LOW_PING
        PickKind.STABLE -> ReasonKind.STABLE
        PickKind.FAST -> ReasonKind.FAST
    }

    enum class ReasonKind { BEST_NEUTRAL, BEST_SPEEDY_LINE, BEST_ROUGH_LINE, LOW_PING, STABLE, FAST }
}
