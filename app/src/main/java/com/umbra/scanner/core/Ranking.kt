package com.umbra.scanner.core

import kotlin.math.ln

object Ranking {

    /**
     * 0..100 composite quality score.
     * latency 34% · loss 26% · speed 20% · jitter 10% + TLS bonus 10.
     */
    fun scoreOf(r: ScanResult): Double {
        if (!r.alive) return 0.0
        val lat = r.latencyMs ?: return 0.0
        val latScore = 1.0 / (1.0 + lat / 100.0)
        val lossScore = 1.0 - r.packetLoss.coerceIn(0.0, 1.0)
        val jitScore = 1.0 / (1.0 + (r.jitterMs ?: 0.0) / 50.0)
        val spd = r.speedMbps
        val speedScore = if (spd == null || spd <= 0.0) 0.30
        else (ln(1.0 + spd) / ln(1001.0)).coerceAtMost(1.0)
        val base = 100.0 * (0.34 * latScore + 0.26 * lossScore + 0.20 * speedScore + 0.10 * jitScore)
        return base + if (r.tlsSuccess) 10.0 else 0.0
    }

    fun sort(results: List<ScanResult>, key: SortKey): List<ScanResult> = when (key) {
        SortKey.SCORE -> results.sortedByDescending { scoreOf(it) }
        SortKey.LATENCY -> results.filter { it.latencyMs != null }.sortedBy { it.latencyMs ?: Double.MAX_VALUE }
        SortKey.JITTER -> results.filter { it.jitterMs != null }.sortedBy { it.jitterMs ?: Double.MAX_VALUE }
        SortKey.LOSS -> results.filter { it.alive }.sortedBy { it.packetLoss }
        SortKey.SPEED -> results.filter { it.speedMbps != null }.sortedByDescending { it.speedMbps ?: 0.0 }
    }
}
