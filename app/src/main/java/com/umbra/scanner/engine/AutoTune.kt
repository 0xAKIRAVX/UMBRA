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
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.math.roundToInt

/**
 * AUTO-TUNE — one-tap calibration that measures the live network and the device,
 * then picks the best advanced settings for the current scan mode.
 *
 * Probes (all against literal IPs, DNS never involved):
 *  1. baseline RTT      — TCP :443 handshake to 1.1.1.1 / 162.159.192.1 / 104.16.1.1
 *  2. IPv6 availability — TCP :443 to 2606:4700:4700::1111 and the WARP v6 seed
 *  3. link capacity     — small exact-IP HTTPS download (speed.cloudflare.com SNI)
 *  4. device class      — CPU cores + low-RAM flag
 *
 * v3.8: the WARP-mode port sweep is gone with the mode itself. ENDPOINT tuning
 * now follows the BPB ladder: wireguard retries 3/5/7 by network quality, the
 * endpoint count scaled by latency, and a timeout floor of 2000 ms (a WireGuard
 * handshake round-trip needs more headroom than a bare TCP connect).
 */
object AutoTune {

    /** Raw measurements taken from the live network + device. */
    data class Calibration(
        val rttMs: Double? = null,
        val v6Ok: Boolean = false,
        val linkMbps: Double? = null,
        val cores: Int = 4,
        val lowRam: Boolean = false,
    )

    /** The chosen configuration, ready to be applied to the scan setup. */
    data class TuneResult(
        val mode: ScanMode,
        val family: NetFamily,
        val port: Int,
        val samplesPerPrefix: Int,
        /** v3.7: ENDPOINT-mode knob — ignored by every other mode. */
        val endpointsCount: Int = 500,
        val tcpAttempts: Int,
        /** ENDPOINT only: WireGuard handshake rounds per endpoint (3/5/7). */
        val warpAttempts: Int,
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

        onStep("measuring link capacity · 1 mb exact-ip sample")
        val mbps = measureLink(v6)

        val calibration = Calibration(
            rttMs = rtt,
            v6Ok = v6,
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

    private suspend fun measureLink(v6Ok: Boolean): Double? {
        val seedText = if (v6Ok) "2606:4700:d0::a29f:c001" else "162.159.192.1"
        val bytes = IpText.literalToBytes(seedText) ?: return null
        val d = runCatching {
            // v3.2 fix: the download is blocking socket IO — dispatch it to IO so
            // the main thread never freezes (was a 6.7s ANR window) and the
            // timeout below can actually preempt the work.
            withTimeoutOrNull(6500) {
                withContext(Dispatchers.IO) {
                    ExactIpHttps.download(
                        bytes, 443, "speed.cloudflare.com",
                        bytes = 512L * 1024,
                        connectTimeoutMs = 2200,
                        readTimeoutMs = 4500,
                        maxDurationMs = 4500,
                    )
                }
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
        // v3.8: ENDPOINT needs a WireGuard handshake round-trip, not a bare
        // TCP connect — keep a 2000 ms floor so slow-radio networks (EDGE
        // class) can still complete handshakes.
        val rtt = c.rttMs
        val endpointMode = mode == ScanMode.ENDPOINT
        val timeout = when {
            rtt == null -> 1500
            else -> (rtt * 4.0).roundToInt().coerceIn(700, 2600)
        }.let { t -> ((t + 99) / 100) * 100 } // round up to 100ms
            .let { t -> if (endpointMode) maxOf(t, 2000) else t }
        notes.add(
            (if (rtt != null) "rtt ${rtt.roundToInt()}ms" else "rtt unknown") +
                " → timeout ${timeout}ms" + if (endpointMode) " (wg floor 2000)" else ""
        )

        // ---- ports ----
        val port = Presets.defaultPort(mode)
        if (endpointMode) {
            notes.add("random port per endpoint from the ${Presets.warpPortsCount()} canonical warp ports")
        }

        // ---- concurrency (cpu + ram + link aware) ----
        var concurrency = if (c.lowRam) c.cores * 25 else c.cores * 45
        if (c.linkMbps != null && c.linkMbps < 2.0) concurrency = minOf(concurrency, 128)
        concurrency = concurrency.coerceIn(if (c.lowRam) 48 else 96, if (c.lowRam) 160 else 320)
        notes.add(
            "${c.cores} cores · ${if (c.lowRam) "low-ram" else "standard"} device → concurrency $concurrency"
        )

        // ---- sampling ----
        val samples = if (c.lowRam) 64 else 96

        // ---- speed test ----
        val mbps = c.linkMbps
        val downloadMb = when {
            mbps == null -> 10
            mbps < 3.0 -> 5
            mbps < 15.0 -> 10
            else -> 20
        }
        // v3.7: endpoint mode ships as a pure latency scan (BPB parity) —
        // no TLS phase exists there and the throughput pass stays opt-in.
        val speedTest = !endpointMode
        val tlsVerify = !endpointMode
        val speedConcurrency = if (c.lowRam) 2 else if (mbps != null && mbps < 2.0) 3 else 4
        notes.add(
            if (mbps != null) "link ≈ ${"%.1f".format(java.util.Locale.US, mbps)} mbps → ${downloadMb}mb sample · ${speedConcurrency}× speed lanes"
            else "link unknown → ${downloadMb}mb sample"
        )

        // ---- attempts ----
        // BPB ladder (network.go: poor → 7, moderate → 5, good → 3). For
        // ENDPOINT these are WireGuard handshake rounds per endpoint; for
        // EDGE/CUSTOM they are plain TCP attempts.
        val attempts = when {
            rtt == null -> 5
            rtt >= 200.0 -> 7
            rtt >= 100.0 -> 5
            else -> 3
        }
        val tcpAttempts = attempts
        val warpAttempts = attempts
        var endpointsCount = 500
        if (endpointMode) {
            endpointsCount = when {
                rtt == null -> 400
                rtt >= 200.0 -> 300
                rtt >= 100.0 -> 500
                else -> 700
            }
            notes.add(
                (if (rtt != null) "rtt ${rtt.roundToInt()}ms" else "rtt unknown") +
                    " → $warpAttempts wireguard retries per endpoint"
            )
            notes.add(
                "every endpoint is proven by a real wireguard handshake — tcp-alive " +
                    "endpoints are never reported (they do not work in wireguard)"
            )
        } else {
            notes.add("every result is tls-cert-verified — dpi fake endpoints are discarded")
        }

        return TuneResult(
            mode = mode,
            family = family,
            port = port,
            samplesPerPrefix = samples,
            endpointsCount = endpointsCount,
            tcpAttempts = tcpAttempts,
            warpAttempts = warpAttempts,
            tcpTimeoutMs = timeout,
            concurrency = concurrency,
            tlsVerify = tlsVerify,
            verifyTopN = if (c.lowRam) 800 else 1200,
            speedTest = speedTest,
            speedTopN = if (c.lowRam) 20 else 40,
            speedConcurrency = speedConcurrency,
            downloadBytes = downloadMb.toLong() * 1024 * 1024,
            notes = notes,
        )
    }
}
