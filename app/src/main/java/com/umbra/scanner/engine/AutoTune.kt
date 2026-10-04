package com.umbra.scanner.engine

import android.app.ActivityManager
import android.content.Context
import com.umbra.scanner.core.IpText
import com.umbra.scanner.core.NetFamily
import com.umbra.scanner.core.Presets
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.net.ExactIpHttps
import com.umbra.scanner.net.TcpProbe
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.math.roundToInt

/**
 * AUTO-TUNE — one-tap calibration that measures the live network and the device,
 * then picks the best advanced settings for the current scan mode.
 *
 * Probes (all against literal IPs, DNS never involved):
 *  1. baseline RTT      — TCP :443 handshake to 1.1.1.1 / 162.159.192.1 / 104.16.1.1
 *  2. IPv6 availability — TCP :443 to 2606:4700:4700::1111 and the WARP v6 seed
 *  3. WARP port sweep   — every canonical WARP port against 2 live seed endpoints
 *  4. link capacity     — small exact-IP HTTPS download (speed.cloudflare.com SNI)
 *  5. device class      — CPU cores + low-RAM flag
 */
object AutoTune {

    /** Raw measurements taken from the live network + device. */
    data class Calibration(
        val rttMs: Double? = null,
        val v6Ok: Boolean = false,
        /** working WARP port → best latency over the seed endpoints (ms) */
        val warpPortLatency: Map<Int, Double> = emptyMap(),
        val linkMbps: Double? = null,
        val cores: Int = 4,
        val lowRam: Boolean = false,
    )

    /** The chosen configuration, ready to be applied to the scan setup. */
    data class TuneResult(
        val mode: ScanMode,
        val family: NetFamily,
        val port: Int,
        val portSweep: Boolean,
        val sweepPorts: List<Int>,
        val samplesPerPrefix: Int,
        val tcpAttempts: Int,
        val tcpTimeoutMs: Int,
        val concurrency: Int,
        val tlsVerify: Boolean,
        val verifyTopN: Int,
        val speedTest: Boolean,
        val speedTopN: Int,
        val speedConcurrency: Int,
        val downloadBytes: Long,
        val notes: List<String>,
    ) {
        val downloadMb: Int get() = (downloadBytes / (1024L * 1024L)).toInt()
    }

    private val SEED_V6 = listOf(
        "2606:4700:4700::1111",          // 1.1.1.1 v6
        "2606:4700:d0::a29f:c001",       // WARP v6 seed (== 162.159.192.1)
    )

    private val RTT_SEEDS = listOf(
        "1.1.1.1",
        "162.159.192.1",
        "104.16.1.1",
        "188.114.96.1",
    )

    /**
     * Runs the full calibration. [onStep] receives short progress lines so the UI
     * can stream what is happening. Total wall time is roughly 3–6 seconds.
     */
    suspend fun calibrate(
        context: Context,
        mode: ScanMode,
        onStep: (String) -> Unit = {},
    ): TuneResult = coroutineScope {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
        val cores = Runtime.getRuntime().availableProcessors().coerceAtLeast(2)
        val lowRam = am?.isLowRamDevice == true

        onStep("probing baseline rtt · 4 edge seeds :443")
        val rtt = measureRtt()

        onStep("checking ipv6 route · 2 seeds :443")
        val v6 = probeV6()

        val warpPorts: Map<Int, Double> = if (mode == ScanMode.WARP) {
            onStep("sweeping ${Presets.WARP_PORTS_FULL.size} warp ports × 2 seeds")
            sweepWarpPorts(rtt)
        } else emptyMap()

        onStep("measuring link capacity · 1 mb exact-ip sample")
        val mbps = measureLink(v6)

        val calibration = Calibration(
            rttMs = rtt,
            v6Ok = v6,
            warpPortLatency = warpPorts,
            linkMbps = mbps,
            cores = cores,
            lowRam = lowRam,
        )
        decide(calibration, mode)
    }

    // ---------------------------------------------------------------- probes

    private suspend fun measureRtt(): Double? = coroutineScope {
        val results = RTT_SEEDS.map { seed ->
            async(Dispatchers.IO) {
                val bytes = IpText.literalToBytes(seed) ?: return@async null
                val t = runCatching {
                    withTimeoutOrNull(2500) { TcpProbe.probe(bytes, 443, 2, 1800) }
                }.getOrNull()
                t?.latenciesMs?.minOrNull()
            }
        }.awaitAll()
        results.filterNotNull().minOrNull()
    }

    private suspend fun probeV6(): Boolean = coroutineScope {
        SEED_V6.map { seed ->
            async(Dispatchers.IO) {
                val bytes = IpText.literalToBytes(seed) ?: return@async false
                runCatching {
                    withTimeoutOrNull(2200) { TcpProbe.probe(bytes, 443, 1, 2000) }
                }.getOrNull()?.success == true
            }
        }.awaitAll().any { it }
    }

    /**
     * Probes every canonical WARP port against two seed endpoints. The first
     * round hits 162.159.192.1; ports that fail there retry against
     * 188.114.96.1, so per-ISP port blocking is detected per port.
     */
    private suspend fun sweepWarpPorts(rttMs: Double?): Map<Int, Double> = coroutineScope {
        val timeout = ((rttMs ?: 300.0) * 5.0).coerceIn(900.0, 2400.0).roundToInt()
        val seeds = Presets.WARP_SEED_V4.mapNotNull { IpText.literalToBytes(it) }
        val sem = Semaphore(48)
        val first = seeds.firstOrNull() ?: return@coroutineScope emptyMap()

        suspend fun probePort(port: Int, seed: ByteArray): Double? {
            val t = runCatching {
                withTimeoutOrNull((timeout + 400).toLong()) {
                    TcpProbe.probe(seed, port, 1, timeout)
                }
            }.getOrNull()
            return t?.latenciesMs?.minOrNull()
        }

        val best = HashMap<Int, Double>()
        val deferred = Presets.WARP_PORTS_FULL.map { port ->
            async(Dispatchers.IO) {
                sem.withPermit {
                    val lat = probePort(port, first)
                    if (lat != null) port to lat else null
                }
            }
        }
        for (pair in deferred.awaitAll()) {
            if (pair != null) best[pair.first] = pair.second
        }

        // retry failures against the second seed (partial per-ISP blocking)
        val failed = Presets.WARP_PORTS_FULL.filter { it !in best }
        if (failed.isNotEmpty() && seeds.size > 1) {
            val second = seeds[1]
            val retry = failed.map { port ->
                async(Dispatchers.IO) {
                    sem.withPermit {
                        val lat = probePort(port, second)
                        if (lat != null) port to lat else null
                    }
                }
            }
            for (pair in retry.awaitAll()) {
                if (pair != null) best[pair.first] = pair.second
            }
        }
        best
    }

    private suspend fun measureLink(v6Ok: Boolean): Double? {
        val seedText = if (v6Ok) "2606:4700:d0::a29f:c001" else "162.159.192.1"
        val bytes = IpText.literalToBytes(seedText) ?: return null
        val d = runCatching {
            withTimeoutOrNull(6500) {
                ExactIpHttps.download(
                    bytes, 443, "speed.cloudflare.com",
                    bytes = 512L * 1024,
                    connectTimeoutMs = 2200,
                    readTimeoutMs = 4500,
                    maxDurationMs = 4500,
                )
            }
        }.getOrNull() ?: return null
        return if (d.httpStatus == 200 && d.bytes > 0 && d.error == null && d.durationMs > 0) {
            d.bytes * 8.0 / 1000.0 / d.durationMs
        } else null
    }

    // --------------------------------------------------------------- decision

    /** Pure decision function — fully unit-testable without a network. */
    fun decide(c: Calibration, mode: ScanMode): TuneResult {
        val notes = ArrayList<String>(8)

        // ---- family ----
        val family = if (c.v6Ok) NetFamily.BOTH else NetFamily.V4
        notes.add(if (c.v6Ok) "ipv6 route live · scanning both families" else "no ipv6 route · ipv4 only")

        // ---- timeout ----
        val rtt = c.rttMs
        val timeout = when {
            rtt == null -> 1500
            else -> (rtt * 4.0).roundToInt().coerceIn(700, 2600)
        }.let { t -> ((t + 99) / 100) * 100 } // round up to 100ms
        notes.add(if (rtt != null) "rtt ${rtt.roundToInt()}ms → timeout ${timeout}ms" else "rtt unknown → timeout ${timeout}ms")

        // ---- ports (WARP only) ----
        var port = Presets.defaultPort(mode)
        var sweep = false
        var sweepPorts: List<Int> = emptyList()
        if (mode == ScanMode.WARP) {
            val working = c.warpPortLatency.entries
                .sortedWith(compareBy({ it.value }, { it.key }))
                .map { it.key }
            when {
                working.isEmpty() -> {
                    port = 443
                    notes.add("all warp ports blocked → :443 fallback (tcp-verified)")
                }
                2408 in working -> {
                    port = 2408
                    sweep = working.size >= 4
                    if (sweep) {
                        sweepPorts = (listOf(2408) + working.filter { it != 2408 }).take(12)
                        notes.add("port 2408 open · sweeping ${sweepPorts.size} live ports for backup options")
                    } else {
                        notes.add("port 2408 open · single-port lock")
                    }
                }
                else -> {
                    sweep = true
                    sweepPorts = (working + 443).distinct().take(16)
                    port = sweepPorts.first()
                    notes.add("port 2408 blocked → sweep ${sweepPorts.size} open ports (${sweepPorts.take(4).joinToString("/")}${if (sweepPorts.size > 4) "…" else ""})")
                }
            }
        }

        // ---- concurrency (cpu + ram + link aware) ----
        var concurrency = if (c.lowRam) c.cores * 25 else c.cores * 45
        if (c.linkMbps != null && c.linkMbps < 2.0) concurrency = minOf(concurrency, 128)
        concurrency = concurrency.coerceIn(if (c.lowRam) 48 else 96, if (c.lowRam) 160 else 320)
        notes.add(
            "${c.cores} cores · ${if (c.lowRam) "low-ram" else "standard"} device → concurrency $concurrency"
        )

        // ---- sampling ----
        val samples = when {
            sweep -> if (c.lowRam) 64 else 96
            mode == ScanMode.WARP && family == NetFamily.BOTH -> 400
            else -> 450
        }

        // ---- speed test ----
        val mbps = c.linkMbps
        val downloadMb = when {
            mbps == null -> 10
            mbps < 3.0 -> 5
            mbps < 15.0 -> 10
            else -> 20
        }
        val speedTest = true
        val speedConcurrency = if (c.lowRam) 2 else if (mbps != null && mbps < 2.0) 3 else 4
        notes.add(
            if (mbps != null) "link ≈ ${"%.1f".format(mbps)} mbps → ${downloadMb}mb sample · ${speedConcurrency}× speed lanes"
            else "link unknown → ${downloadMb}mb sample"
        )
        if (mode == ScanMode.WARP) notes.add("warp speed is measured on :443 — warp ports never serve the speed endpoint")

        return TuneResult(
            mode = mode,
            family = family,
            port = port,
            portSweep = sweep,
            sweepPorts = sweepPorts,
            samplesPerPrefix = samples,
            tcpAttempts = 3,
            tcpTimeoutMs = timeout,
            concurrency = concurrency,
            tlsVerify = true,
            verifyTopN = if (c.lowRam) 48 else 80,
            speedTest = speedTest,
            speedTopN = if (c.lowRam) 20 else 40,
            speedConcurrency = speedConcurrency,
            downloadBytes = downloadMb.toLong() * 1024 * 1024,
            notes = notes,
        )
    }
}
