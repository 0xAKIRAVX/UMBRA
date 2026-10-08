package com.umbra.scanner.core

import androidx.compose.runtime.Immutable

enum class IpProtocol(val label: String) {
    IPv4("IPv4"), IPv6("IPv6");
}

enum class NetFamily(val label: String) {
    BOTH("ALL"), V4("IPv4"), V6("IPv6");
}

enum class WarpFlavor(val label: String) {
    WARP("WARP"), WARP_PLUS("WARP+");
}

enum class ScanMode(val label: String, val tagline: String) {
    CF_EDGE("EDGE", "Cloudflare edge · speed.cloudflare.com"),
    WARP("WARP", "WARP / WARP+ · real WireGuard handshake + in-tunnel ping"),
    CUSTOM("CUSTOM", "Your own CIDR list");
}

enum class ScanPhase(val label: String, val order: Int) {
    IDLE("IDLE", 0),
    GENERATING("GENERATE", 1),
    REGISTER("WARP REG", 2),
    TCP("TCP STORM", 2),
    WG("WG PROBE", 3),
    PROBE("TLS PROBE", 3),
    RANKING("RANKING", 4),
    SPEED("SPEED TEST", 5),
    DONE("COMPLETE", 6);
}

enum class SortKey(val label: String) {
    SCORE("SCORE"), LATENCY("LATENCY"), JITTER("JITTER"), LOSS("LOSS"), SPEED("SPEED");
}

@Immutable
data class ScanParams(
    val mode: ScanMode = ScanMode.CF_EDGE,
    val cidrs: List<String> = emptyList(),
    val family: NetFamily = NetFamily.BOTH,
    val port: Int = 443,
    val samplesPerPrefix: Int = 96,
    val tcpAttempts: Int = 3,
    val tcpTimeoutMs: Int = 2000,
    val concurrency: Int = 150,
    val tlsVerify: Boolean = true,
    /** EDGE/CUSTOM: how many TCP-alive endpoints get full TLS verification.
     *  This is the REAL alive filter — a bare TCP connect proves nothing on
     *  networks with DPI middleboxes that fake-accept every handshake. */
    val verifyTopN: Int = 400,
    val speedTest: Boolean = true,
    val speedTopN: Int = 50,
    val speedConcurrency: Int = 4,
    val downloadBytes: Long = 20L * 1024 * 1024,
    val warpFlavor: WarpFlavor = WarpFlavor.WARP,
    /** WARP only: probe the full canonical port list instead of a single port. */
    val portSweep: Boolean = false,
    /** Ports to probe in sweep mode (defaults to the full WARP list). */
    val sweepPorts: List<Int> = emptyList(),
    /** WARP only: full probe rounds per endpoint (BPB-style retries: 3/5/7). */
    val warpAttempts: Int = 3,
    /** WARP only: anti-DPI UDP noise burst before each handshake (xray `noises`). */
    val udpNoise: Boolean = true,
    /** WARP only: noise packets per burst. */
    val noiseCount: Int = 5,
) {
    val edgeSni: String get() = "speed.cloudflare.com"
    val warpSni: String get() = "engage.cloudflareclient.com"
    val speedSni: String get() = "speed.cloudflare.com"

    /** WARP endpoints never serve speed.cloudflare.com on their scan port — the
     *  throughput check always rides 443, where every WARP IP is a normal edge. */
    val speedPort: Int get() = if (mode == ScanMode.WARP) 443 else port

    /** EDGE/CUSTOM scans ALWAYS TLS-verify their TCP-alive candidates: on
     *  heavily-filtered networks (e.g. Iran) DPI boxes complete the TCP
     *  handshake for any destination, so TCP-alive alone means nothing. Only
     *  an IP serving a valid certificate for a real Cloudflare host is real. */
    val needsTlsPhase: Boolean get() = tlsVerify && mode != ScanMode.WARP
    val downloadMbLabel: Int get() = (downloadBytes / (1024 * 1024)).toInt()

    /** Every (ip, port) pair the TCP storm will probe. */
    val effectivePorts: List<Int>
        get() = if (mode == ScanMode.WARP && portSweep) {
            (if (sweepPorts.isEmpty()) Presets.WARP_PORTS_FULL else sweepPorts).distinct().sorted()
        } else {
            listOf(port)
        }
}

@Immutable
data class ScanResult(
    val ip: String,
    val protocol: IpProtocol,
    val port: Int,
    val latencyMs: Double? = null,
    val jitterMs: Double? = null,
    val packetLoss: Double = 0.0,
    val speedMbps: Double? = null,
    val downloadedBytes: Long = 0L,
    val tcpAttempts: Int = 0,
    val successfulAttempts: Int = 0,
    val tlsSuccess: Boolean = false,
    val tlsHandshakeMs: Double? = null,
    val httpStatus: Int? = null,
    /** WARP mode: completed WireGuard handshakes (data-plane pings counted in
     *  successfulAttempts). */
    val wgHandshakes: Int = 0,
    val error: String? = null,
    val mode: ScanMode = ScanMode.CF_EDGE,
) {
    /**
     * An endpoint is alive only when it was PROVEN real:
     *  - WARP: data actually flowed through the tunnel (in-tunnel ICMP ping)
     *  - EDGE/CUSTOM: a full TLS handshake with a valid certificate for
     *    speed.cloudflare.com (or an HTTP 200 from the speed endpoint)
     * A bare TCP connect is NOT aliveness — DPI middleboxes fake it.
     */
    val alive: Boolean
        get() = when (mode) {
            ScanMode.WARP -> successfulAttempts > 0
            else -> tlsSuccess || httpStatus == 200
        }

    /** TCP-level reachability only (pre-filter, not proof). */
    val tcpAlive: Boolean get() = successfulAttempts > 0

    val id: String get() = "$ip:$port"
    val lossPct: Int get() = (packetLoss * 100).toInt()

    fun merge(newer: ScanResult): ScanResult = ScanResult(
        ip = ip,
        protocol = protocol,
        port = port,
        latencyMs = newer.latencyMs ?: latencyMs,
        jitterMs = newer.jitterMs ?: jitterMs,
        packetLoss = newer.packetLoss,
        speedMbps = newer.speedMbps ?: speedMbps,
        downloadedBytes = maxOf(downloadedBytes, newer.downloadedBytes),
        tcpAttempts = newer.tcpAttempts,
        successfulAttempts = newer.successfulAttempts,
        tlsSuccess = tlsSuccess || newer.tlsSuccess,
        tlsHandshakeMs = newer.tlsHandshakeMs ?: tlsHandshakeMs,
        httpStatus = newer.httpStatus ?: httpStatus,
        wgHandshakes = maxOf(wgHandshakes, newer.wgHandshakes),
        error = newer.error ?: error,
        mode = mode,
    )
}

@Immutable
data class ScanStats(
    val phase: ScanPhase = ScanPhase.IDLE,
    val candidates: Int = 0,
    val tested: Int = 0,
    val alive: Int = 0,
    val tlsOk: Int = 0,
    val speedTested: Int = 0,
    val active: Int = 0,
    val elapsedMs: Long = 0L,
    val ratePerSec: Double = 0.0,
    val etaSec: Double? = null,
) {
    val progress: Float
        get() = if (candidates == 0) 0f else (tested.toFloat() / candidates).coerceIn(0f, 1f)
}

@Immutable
data class ScanSummary(
    val cancelled: Boolean,
    val candidates: Int,
    val tested: Int,
    val alive: Int,
    val best: ScanResult?,
    val elapsedMs: Long,
    val params: ScanParams,
    val finishedAt: Long = System.currentTimeMillis(),
)

sealed interface ScanUi {
    data object Idle : ScanUi
    data class Running(val params: ScanParams, val startedAt: Long) : ScanUi
    data class Done(val summary: ScanSummary) : ScanUi
}
