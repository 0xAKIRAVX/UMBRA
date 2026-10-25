package com.umbra.scanner.core

import androidx.compose.runtime.Immutable

enum class IpProtocol(val label: String) {
    IPv4("IPv4"), IPv6("IPv6");
}

enum class NetFamily(val label: String) {
    BOTH("ALL"), V4("IPv4"), V6("IPv6");
}

/**
 * v3.8: the standalone WARP mode is GONE — the user asked for its removal and
 * its job is fully absorbed by ENDPOINT. Ordinals were remapped
 * (CF_EDGE=0, CUSTOM=1, ENDPOINT=2) and every persisted p_mode value is
 * migrated through [UmbraSettings] (old WARP(1) and ENDPOINT(3) → ENDPOINT,
 * old CUSTOM(2) → CUSTOM).
 * v4.1: AKAMAI is APPENDED as ordinal 3 — the persisted 0..2 keep their
 * meaning, so no stored mode shifts; the pre-v3.8 bridge above still maps
 * raw 3 → ENDPOINT for installs that predate this member entirely.
 */
enum class ScanMode(val label: String, val tagline: String) {
    CF_EDGE("CLEAN IP", "Cloudflare clean-IP · go engine · real TLS + speed"),
    CUSTOM("CUSTOM", "Your own CIDR list"),
    /** BPB-Warp-Scanner equivalent: random ip:port endpoints drawn from the
     *  WARP ranges (IPv4 + IPv6), each validated by a REAL WireGuard
     *  handshake over UDP and ranked by round-trip time. This is the only
     *  honest definition of "endpoint works" — a TCP connect proves
     *  nothing (v3.7's fake-endpoint lesson). */
    ENDPOINT("ENDPOINT", "WARP ranges · random ip:port · IPv4 + IPv6 · real WireGuard handshake"),
    /** v4.1: Akamai CDN scanner — samples Akamai's published edge ranges,
     *  storms TCP :443, then TLS-verifies on the KOTLIN core (the Go
     *  clean-ip engine is CF-bound: its verify phase demands a 200 from
     *  /cdn-cgi/trace, which Akamai edges can never answer — a
     *  trace-hardcoded filter would kill every real Akamai IP).
     *  v4.2 (THE "fake Akamai IPs" fix): the probe SNI is www.bing.com —
     *  chosen by a LIVE 5-SNI matrix census against real edges (2026-10-25):
     *  9/9 census edges served a valid www.bing.com certificate AND HTTP 200
     *  with ~78 KB bodies, while www.akamai.com only answered with a 1.7 KB
     *  403 stub (no measurable body) and www.microsoft.com /
     *  www.tesla.com / download.microsoft.com were NOT served from every
     *  edge (tlsv1 alert internal error). Akamai's shared edge routes
     *  STRICTLY by SNI, so only IPs genuinely serving the probed property
     *  pass — DPI fake-accepts and non-serving IPs die at the TLS filter.
     *  v4.2 also added the DEEP MEASURE phase (multi-sample ping/jitter/loss)
     *  and a REAL throughput measure: repeated bing page fetches, counting
     *  only body-transfer time — the mode finally delivers on «پرسرعت‌ترین
     *  آیپی‌های آکامای». */
    AKAMAI("AKAMAI", "Akamai CDN · cert-verified TLS · deep measure · real throughput");

    companion object {
        /** v3.8 persistence bridge: maps a PRE-v3.8 stored p_mode ordinal
         *  (0=CF_EDGE, 1=WARP, 2=CUSTOM, 3=ENDPOINT) onto the new enum.
         *  Pure function — unit-tested directly. */
        fun fromLegacyOrdinal(raw: Int): ScanMode = when (raw) {
            0 -> CF_EDGE
            1, 3 -> ENDPOINT
            2 -> CUSTOM
            else -> ENDPOINT
        }
    }
}

enum class ScanPhase(val label: String, val order: Int) {
    IDLE("IDLE", 0),
    GENERATING("GENERATE", 1),
    // v3.8: ENDPOINT registers a WARP identity silently (it is the probe key,
    // never a user-facing "WARP section") — relabeled from "WARP REG".
    REGISTER("IDENTITY", 2),
    TCP("TCP STORM", 2),
    WG("WG PROBE", 3),
    PROBE("TLS PROBE", 3),
    /** v4.2: the deep-measure phase — the top validated endpoints are
     *  re-probed with MANY spaced samples so the reported ping / jitter /
     *  loss are REAL numbers measured over time, not one lucky round trip.
     *  This is the direct answer to «برنامه سریع آیپی‌ها رو پیدا می‌کنه و
     *  اصلاً فرصت نمی‌کنه تا واقعی بسنجه‌شون». */
    CALIBRATE("DEEP MEASURE", 4),
    RANKING("RANKING", 5),
    SPEED("SPEED TEST", 6),
    DONE("COMPLETE", 7);
}

enum class SortKey(val label: String) {
    SMART("SMART"), SCORE("SCORE"), LATENCY("LATENCY"), JITTER("JITTER"), LOSS("LOSS"), SPEED("SPEED");
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
    /** v3.7 ENDPOINT only: how many random ip:port endpoints to test (the
     *  BPB "EndpointCount" knob — quick 100 / normal 1000 / deep 10000).
     *  Ignored by every other mode. */
    val endpointsCount: Int = 500,
    /** ENDPOINT only: full WireGuard probe rounds per endpoint (BPB-style
     *  retries by network quality: 3 / 5 / 7). */
    val warpAttempts: Int = 3,
    /** ENDPOINT only: anti-DPI UDP noise burst before each handshake
     *  (xray `noises` semantics — random destinations, never the target). */
    val udpNoise: Boolean = true,
    /** ENDPOINT only: noise packets per burst. */
    val noiseCount: Int = 5,
    /** v4.2: the deep-measure phase — after aliveness is proven, the top
     *  [deepTopN] endpoints are re-probed with [deepSamples] spaced samples
     *  each, and the REPORTED ping / jitter / loss / ranking all come from
     *  that multi-sample measurement. A single handshake or one TLS round
     *  trip is a discovery signal, not a measurement (the exact complaint:
     *  «برنامه سریع آیپی‌ها رو پیدا می‌کنه و اصلاً فرصت نمی‌کنه تا واقعی
     *  بسنجه‌شون — پینگ و سرعت و پایداری»). */
    val deepMeasure: Boolean = true,
    /** v4.2: how many verified endpoints get the deep measurement. */
    val deepTopN: Int = 30,
    /** v4.2: spaced samples per deep-measured endpoint (each sample is a
     *  full fresh TCP + TLS round trip with the mode's SNI — or, in ENDPOINT
     *  mode, a fresh WireGuard handshake + in-tunnel ping). */
    val deepSamples: Int = 8,
) {
    /** v4.2: the probe/validation host for AKAMAI is www.bing.com — the
     *  live-census winner (9/9 edges, valid cert + HTTP 200 + ~78 KB real
     *  bodies per fetch; www.akamai.com answers everywhere but only with a
     *  1.7 KB 403 stub, and the microsoft/tesla properties are not served
     *  from every edge). Same host for validation, deep samples AND the
     *  repeated-fetch throughput measure — one proven path end-to-end. */
    val edgeSni: String get() = if (mode == ScanMode.AKAMAI) Presets.AKAMAI_SNI else "speed.cloudflare.com"
    val warpSni: String get() = "engage.cloudflareclient.com"
    val speedSni: String get() = if (mode == ScanMode.AKAMAI) Presets.AKAMAI_SNI else "speed.cloudflare.com"

    /** WARP endpoints never serve speed.cloudflare.com on their scan port — the
     *  throughput check always rides 443, where every WARP IP is a normal edge.
     *  A port of 0 (= RANDOM) is never a connectable port. */
    val speedPort: Int get() = when {
        mode == ScanMode.ENDPOINT -> 443
        port == 0 -> 443
        else -> port
    }

    /** EDGE/CUSTOM/AKAMAI scans ALWAYS TLS-verify their TCP-alive candidates: on
     *  heavily-filtered networks (e.g. Iran) DPI boxes complete the TCP
     *  handshake for any destination, so TCP-alive alone means nothing. Only
     *  an IP serving a valid certificate for a real CDN host (speed.cloudflare.com
     *  / www.bing.com) is real.
     *  v3.8: ENDPOINT needs no TLS phase — its proof is the WireGuard
     *  handshake itself.
     *  v4.2: AKAMAI runs its throughput measure on REPEATED REAL-PAGE FETCHES
     *  (bing serves a full body on every census edge) — no CF-style metered
     *  endpoint is needed, so the speed phase runs in every mode now. */
    val needsTlsPhase: Boolean get() = tlsVerify && mode != ScanMode.ENDPOINT

    /** v4.2: every mode runs the speed phase — AKAMAI measures throughput on
     *  repeated real-page fetches (ExactIpHttps.downloadRepeated) instead of
     *  CF's metered /__down endpoint. The v4.1 "akamai has no metered
     *  endpoint" limitation is gone. */
    val runsSpeedPhase: Boolean get() = true
    val downloadMbLabel: Int get() = (downloadBytes / (1024 * 1024)).toInt()

    /** Every (ip, port) pair the TCP storm will probe (v3.8: the WARP port
     *  sweep is gone with the WARP mode — one port per scan). */
    val effectivePorts: List<Int> get() = listOf(port)
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
    /** EDGE/CUSTOM only: TLS verification was disabled by the user, so
     *  tcp-alive results stay alive (marked) instead of being dropped —
     *  v3.2 fix for the "TLS verify off → zero results" bug. */
    val tlsSkipped: Boolean = false,
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
            // v3.8: an ENDPOINT is alive only when a real WireGuard handshake
            // ANSWERED — the BPB definition. A TCP connect (the v3.7 contract)
            // proved nothing: Cloudflare's anycast edge accepts TCP on :443
            // regardless of WARP, so those "endpoints" never worked in
            // WireGuard/v2rayNG configs. The handshake response is the only
            // on-device proof that this ip:port actually speaks WARP.
            ScanMode.ENDPOINT -> wgHandshakes > 0
            else -> tlsSuccess || httpStatus == 200 || (tlsSkipped && tcpAlive)
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
        // v3.1.1 fix: a stale failure must not haunt a now-verified endpoint —
        // once the newer state is alive (and carries no fresh error) the old
        // "timeout"/"unreachable" note from an earlier phase is cleared
        error = newer.error ?: if (newer.alive) null else error,
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
    /** v3.3: when a scan produces ZERO alive endpoints, the most likely
     * engine-level reason (last engine log line) — shown in the Done panel so
     * "no results" is explainable instead of looking like a silent failure. */
    val error: String? = null,
)

sealed interface ScanUi {
    data object Idle : ScanUi
    data class Running(val params: ScanParams, val startedAt: Long) : ScanUi
    data class Done(val summary: ScanSummary) : ScanUi
}
