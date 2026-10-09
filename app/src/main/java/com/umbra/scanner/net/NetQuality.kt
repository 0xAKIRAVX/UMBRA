package com.umbra.scanner.net

import com.umbra.scanner.core.IpText
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject
import kotlin.math.sqrt
import kotlin.math.roundToInt

/**
 * NETSENSE — the user's own line, measured.
 *
 * Latency / jitter / packet-loss from repeated TCP handshakes to Cloudflare
 * seed IPs (no DNS), a REAL TLS round-trip (immune to DPI fake-accepts that
 * make TCP-only probes look impossibly fast on filtered networks), an exact-IP
 * HTTPS download and upload, and an IPv6 route probe.
 *
 * The resulting [NetworkProfile] drives the adaptive SmartRanking weights: on
 * a poor, lossy line stability + low ping dominate; on an excellent line raw
 * throughput dominates. Endpoints are then scored RELATIVE to the user's own
 * measured baseline — "بهترین برای نت من".
 */
enum class NetGrade { EXCELLENT, GOOD, FAIR, POOR }

data class NetworkProfile(
    /** Best TCP-connect RTT to the CF seeds (ms) — null when unreachable. */
    val latencyMs: Double? = null,
    /** Std-dev of the successful RTT samples (ms). */
    val jitterMs: Double? = null,
    /** Failed probes / total ping probes (0..1). */
    val packetLoss: Double = 0.0,
    /** Real TLS handshake RTT (ms) — cannot be faked by DPI middleboxes. */
    val tlsRttMs: Double? = null,
    /** TCP answers but TLS never completes → the ISP's DPI is fake-accepting. */
    val dpiSuspected: Boolean = false,
    val downloadMbps: Double? = null,
    val uploadMbps: Double? = null,
    val v6Ok: Boolean = false,
    val measuredAt: Long = System.currentTimeMillis(),
) {
    val grade: NetGrade
        get() {
            val g = NetQuality.gradeOf(latencyMs, jitterMs, packetLoss, downloadMbps)
            // v3.1.1: a line where TCP answers but real TLS never completes is
            // under DPI fake-accept — its flawless TCP numbers must not grade
            // EXCELLENT (that would tilt the smart weights toward raw speed on
            // a line that cannot even complete a real handshake)
            return if (dpiSuspected && g == NetGrade.EXCELLENT) NetGrade.GOOD else g
        }

    /** Age of this measurement in minutes (>= 1). */
    val ageMinutes: Long
        get() = ((System.currentTimeMillis() - measuredAt) / 60_000L).coerceAtLeast(1L)

    val hasData: Boolean get() = latencyMs != null || downloadMbps != null || tlsRttMs != null
}

object NetQuality {

    private val PING_SEEDS = listOf(
        "1.1.1.1",
        "162.159.192.1",
        "104.16.1.1",
        "188.114.96.1",
    )

    private val TLS_SEEDS = listOf(
        "162.159.192.1",
        "104.16.1.1",
    )

    private val V6_SEEDS = listOf(
        "2606:4700:4700::1111",        // 1.1.1.1 v6
        "2606:4700:d0::a29f:c001",     // WARP v6 seed
    )

    /** Download sample for the line check (1 MB — quick but meaningful). */
    private const val DOWNLOAD_BYTES = 1L * 1024 * 1024
    private const val UPLOAD_BYTES = 512L * 1024

    /**
     * Full measurement, ~6–10 s wall time. Steps stream to [onStep] for the UI.
     * Never throws — unreachable seeds simply produce null fields and the
     * profile grades itself POOR / blocked accordingly.
     */
    suspend fun measure(onStep: (String) -> Unit = {}): NetworkProfile = coroutineScope {
        onStep("pinging cloudflare seeds · 4 × 3 rounds")
        val pings = pingSamples()

        onStep("checking ipv6 route · 2 seeds")
        val v6 = probeV6()

        onStep("real tls round-trips · dpi-proof")
        val tls = tlsRtt()

        onStep("measuring download · 1 mb exact-ip")
        val down = downloadMbps(v6)

        onStep("measuring upload · 512 kb exact-ip")
        val up = uploadMbps(v6)

        NetworkProfile(
            latencyMs = pings.first,
            jitterMs = pings.second,
            packetLoss = pings.third,
            tlsRttMs = tls,
            dpiSuspected = pings.first != null && tls == null,
            downloadMbps = down,
            uploadMbps = up,
            v6Ok = v6,
        )
    }

    // ------------------------------------------------------------- probes ----

    /**
     * (best latency, jitter, loss) over 12 interleaved TCP handshakes.
     *
     * v3.2 fix: jitter and loss are now computed PER SEED and aggregated from
     * the most responsive seed. The seeds are 4 distinct anycast endpoints that
     * legitimately sit 20-50ms apart — pooling their samples inflated "jitter"
     * with inter-seed RTT spread and counted a single blocked seed as 25% line
     * loss, dragging an EXCELLENT line down to FAIR and selecting the wrong
     * adaptive ranking weights.
     */
    private suspend fun pingSamples(): Triple<Double?, Double?, Double> = coroutineScope {
        val perSeed = HashMap<String, MutableList<Double>>()
        val failures = HashMap<String, Int>()
        val sem = Semaphore(4)
        repeat(3) { round ->
            val deferred = PING_SEEDS.map { seed ->
                async(Dispatchers.IO) {
                    val bytes = IpText.literalToBytes(seed) ?: return@async null
                    sem.withPermit {
                        runCatching {
                            withTimeoutOrNull(2200) { TcpProbe.probe(bytes, 443, 1, 2000) }
                        }.getOrNull()?.latenciesMs?.firstOrNull()
                    }
                }
            }
            PING_SEEDS.forEachIndexed { i, seed ->
                val r = deferred[i].await()
                if (r != null) perSeed.getOrPut(seed) { ArrayList(3) }.add(r)
                else failures[seed] = (failures[seed] ?: 0) + 1
            }
            if (round < 2) delay(140)
        }
        val lat = perSeed.values.flatten().minOrNull()
        // the most responsive seed (tie → lowest median) is the line's honest witness
        val bestSeed = perSeed.entries
            .sortedWith(compareByDescending<Map.Entry<String, MutableList<Double>>> { it.value.size }
                .thenBy { median(it.value) })
            .firstOrNull()
        val jit = bestSeed?.let { (_, samples) ->
            if (samples.size >= 2) {
                val mean = samples.average()
                sqrt(samples.sumOf { (it - mean) * (it - mean) } / samples.size)
            } else null
        }
        // loss = the best seed's failure rate, not pooled across seeds
        val rounds = 3
        val loss = bestSeed?.let { (seed, samples) ->
            val fails = failures[seed] ?: 0
            (fails + samples.size).let { total -> if (total == 0) 1.0 else fails.toDouble() / total }
        } ?: 1.0
        Triple(lat, jit, loss)
    }

    private fun median(values: List<Double>): Double {
        val sorted = values.sorted()
        val n = sorted.size
        return if (n % 2 == 1) sorted[n / 2] else (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    }

    private suspend fun probeV6(): Boolean = coroutineScope {
        V6_SEEDS.map { seed ->
            async(Dispatchers.IO) {
                val bytes = IpText.literalToBytes(seed) ?: return@async false
                runCatching {
                    withTimeoutOrNull(2200) { TcpProbe.probe(bytes, 443, 1, 2000) }
                }.getOrNull()?.success == true
            }
        }.awaitAll().any { it }
    }

    /** Best real TLS handshake time over the seeds; null when none completes. */
    private suspend fun tlsRtt(): Double? = coroutineScope {
        TLS_SEEDS.map { seed ->
            async(Dispatchers.IO) {
                val bytes = IpText.literalToBytes(seed) ?: return@async null
                val res = runCatching {
                    withTimeoutOrNull(5000) {
                        ExactIpHttps.tlsProbe(
                            bytes, 443, "speed.cloudflare.com",
                            connectTimeoutMs = 2500,
                            readTimeoutMs = 4000,
                        )
                    }
                }.getOrNull() ?: return@async null
                if (res.ok) res.handshakeMs else null
            }
        }.awaitAll().filterNotNull().minOrNull()
    }

    private suspend fun downloadMbps(v6Ok: Boolean): Double? {
        val seed = if (v6Ok) "2606:4700:d0::a29f:c001" else "162.159.192.1"
        val bytes = IpText.literalToBytes(seed) ?: return null
        val d = runCatching {
            withTimeoutOrNull(9000) {
                ExactIpHttps.download(
                    bytes, 443, "speed.cloudflare.com",
                    bytes = DOWNLOAD_BYTES,
                    connectTimeoutMs = 2500,
                    readTimeoutMs = 6000,
                    maxDurationMs = 7000,
                )
            }
        }.getOrNull() ?: return null
        return if (d.httpStatus == 200 && d.bytes > 0 && d.error == null && d.durationMs > 0) {
            d.bytes * 8.0 / 1000.0 / d.durationMs
        } else null
    }

    private suspend fun uploadMbps(v6Ok: Boolean): Double? {
        // v3.1.1 fix: 2606:4700:4700::1111 (1.1.1.1 v6) is the resolver anycast —
        // it does not reliably serve the speed.cloudflare.com SNI, which silently
        // nulled the upload metric on every v6-capable line. The WARP v6 edge
        // (same address download uses) serves both.
        val seed = if (v6Ok) "2606:4700:d0::a29f:c001" else "104.16.1.1"
        val bytes = IpText.literalToBytes(seed) ?: return null
        val u = runCatching {
            withTimeoutOrNull(9000) {
                ExactIpHttps.upload(
                    bytes, 443, "speed.cloudflare.com",
                    bytes = UPLOAD_BYTES,
                    connectTimeoutMs = 2500,
                    readTimeoutMs = 6000,
                    maxDurationMs = 7000,
                )
            }
        }.getOrNull() ?: return null
        return if (u.httpStatus == 200 && u.bytes > 0 && u.durationMs > 0) {
            u.bytes * 8.0 / 1000.0 / u.durationMs
        } else null
    }

    // ------------------------------------------------------ grading logic ----

    /**
     * Pure grading function (unit-tested): 4 dimensions → 0..4 points → grade.
     *  latency   <60 / <120 / <250 ms
     *  jitter    <10 / <25  / <60  ms
     *  loss      ≤1% / <5%  / <15%
     *  download  >20 / >8   / >2   Mbps
     */
    fun gradeOf(
        latencyMs: Double?,
        jitterMs: Double?,
        packetLoss: Double,
        downloadMbps: Double?,
    ): NetGrade {
        if (latencyMs == null) return NetGrade.POOR
        var points = 0.0
        points += when {
            latencyMs < 60 -> 1.0
            latencyMs < 120 -> 0.75
            latencyMs < 250 -> 0.45
            else -> 0.0
        }
        points += when {
            jitterMs == null -> 0.25
            jitterMs < 10 -> 1.0
            jitterMs < 25 -> 0.75
            jitterMs < 60 -> 0.40
            else -> 0.0
        }
        points += when {
            packetLoss <= 0.01 -> 1.0
            packetLoss < 0.05 -> 0.70
            packetLoss < 0.15 -> 0.35
            else -> 0.0
        }
        points += when {
            downloadMbps == null -> 0.30
            downloadMbps > 20 -> 1.0
            downloadMbps > 8 -> 0.75
            downloadMbps > 2 -> 0.40
            else -> 0.0
        }
        return when {
            points >= 3.5 -> NetGrade.EXCELLENT
            points >= 2.4 -> NetGrade.GOOD
            points >= 1.4 -> NetGrade.FAIR
            else -> NetGrade.POOR
        }
    }

    // -------------------------------------------------------------- codec ----

    fun profileToJson(p: NetworkProfile): String {
        val o = JSONObject()
        o.put("latencyMs", p.latencyMs ?: JSONObject.NULL)
        o.put("jitterMs", p.jitterMs ?: JSONObject.NULL)
        o.put("packetLoss", p.packetLoss)
        o.put("tlsRttMs", p.tlsRttMs ?: JSONObject.NULL)
        o.put("dpiSuspected", p.dpiSuspected)
        o.put("downloadMbps", p.downloadMbps ?: JSONObject.NULL)
        o.put("uploadMbps", p.uploadMbps ?: JSONObject.NULL)
        o.put("v6Ok", p.v6Ok)
        o.put("measuredAt", p.measuredAt)
        return o.toString()
    }

    fun profileFromJson(text: String?): NetworkProfile? {
        if (text.isNullOrBlank()) return null
        return runCatching {
            val o = JSONObject(text)
            NetworkProfile(
                latencyMs = if (o.isNull("latencyMs")) null else o.optDouble("latencyMs"),
                jitterMs = if (o.isNull("jitterMs")) null else o.optDouble("jitterMs"),
                packetLoss = o.optDouble("packetLoss", 0.0),
                tlsRttMs = if (o.isNull("tlsRttMs")) null else o.optDouble("tlsRttMs"),
                dpiSuspected = o.optBoolean("dpiSuspected", false),
                downloadMbps = if (o.isNull("downloadMbps")) null else o.optDouble("downloadMbps"),
                uploadMbps = if (o.isNull("uploadMbps")) null else o.optDouble("uploadMbps"),
                v6Ok = o.optBoolean("v6Ok", false),
                measuredAt = o.optLong("measuredAt", System.currentTimeMillis()),
            )
        }.getOrNull()
    }

    /** Human label helper for logs. */
    fun describe(p: NetworkProfile): String = buildString {
        append("net ")
        append(
            when (p.grade) {
                NetGrade.EXCELLENT -> "excellent"
                NetGrade.GOOD -> "good"
                NetGrade.FAIR -> "fair"
                NetGrade.POOR -> "poor"
            }
        )
        p.latencyMs?.let { append(" · ping ${it.roundToInt()}ms") }
        p.downloadMbps?.let { append(" · down ${"%.1f".format(java.util.Locale.US, it)}mbps") }
        if (p.dpiSuspected) append(" · dpi fake-accept suspected")
    }
}
