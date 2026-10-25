package com.umbra.scanner

import com.umbra.scanner.core.CidrBlock
import com.umbra.scanner.core.IpGenerator
import com.umbra.scanner.core.IpProtocol
import com.umbra.scanner.core.NetFamily
import com.umbra.scanner.core.Presets
import com.umbra.scanner.core.ResultCodec
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.core.ScanResult
import com.umbra.scanner.core.SmartRanking
import com.umbra.scanner.engine.AutoTune
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.math.BigInteger
import kotlin.random.Random

/**
 * v4.1 AKAMAI mode — the fastest-Akamai-IP scanner (user request:
 * «CDN آکامای رو اسکن کن و پرسرعت‌ترین IPها رو بده»). Pins the mode's
 * CONTRACTS before any network is involved:
 *
 *  - presets: 29 v4 (v4.2: +10 census-verified regional blocks) + 3 v6
 *    Akamai edge blocks, all parseable, v4 non-overlapping, family
 *    filtering + estimate + the single :443 port
 *  - routing (v4.2): TLS verification targets SNI=www.bing.com — the
 *    LIVE-CENSUS host (9/9 census edges: valid cert + HTTP 200 + a real
 *    ~78 KB body; www.akamai.com answers everywhere but only with a 403
 *    stub); the throughput phase RUNS (repeated real-page fetches — the
 *    "no metered Akamai endpoint" limitation is gone)
 *  - aliveness: a TLS-cert-verified edge is alive; a bare TCP connect is
 *    NOT (the v3.7 fake-endpoint lesson applied to a second CDN)
 *  - generation: every drawn candidate lands inside the Akamai ranges
 *  - auto-tune + codec + smart-ranking keep the same contracts for the new mode
 *
 * Runs on Robolectric (org.json is not mocked in the plain JUnit runner — the
 * same lesson the v3.7 round recorded for ResultCodecTest).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class AkamaiModeTest {

    // ── presets ─────────────────────────────────────────────────────

    @Test
    fun `akamai pool is parseable and v4 blocks do not overlap`() {
        // v4.2: 29 blocks — the v4.1 list of 19 plus the 10 census-verified
        // regional blocks (59.151.128.0/18 … 125.252.192.0/18).
        check(Presets.AKAMAI_V4.size == 29) { "expected 29 v4 blocks, got ${Presets.AKAMAI_V4.size}" }
        check(Presets.AKAMAI_V6.size == 3) { "expected 3 v6 blocks, got ${Presets.AKAMAI_V6.size}" }
        val v4 = Presets.AKAMAI_V4.mapNotNull { CidrBlock.parse(it) }
        val v6 = Presets.AKAMAI_V6.mapNotNull { CidrBlock.parse(it) }
        check(v4.size == 29 && v6.size == 3) { "every block must parse: ${Presets.AKAMAI_V4 + Presets.AKAMAI_V6}" }
        check(v4.all { it.family == IpProtocol.IPv4 } && v6.all { it.family == IpProtocol.IPv6 })
        // overlap check: sort by base; each block must start at or after the
        // previous block's end (no containment, no intersection — overlapping
        // blocks would double-sample the same address space).
        val sorted = v4.sortedBy { it.base }
        var prevEnd: BigInteger? = null
        for (b in sorted) {
            val start = b.base
            val end = b.base.add(b.size).subtract(BigInteger.ONE)
            prevEnd?.let { p ->
                check(start > p) { "akamai v4 blocks overlap around ${b.text} (prev end $p)" }
            }
            prevEnd = end
        }
    }

    @Test
    fun `cidrsFor akamai follows the family and never mixes CDNs`() {
        val both = Presets.cidrsFor(ScanMode.AKAMAI, NetFamily.BOTH)
        check(both == Presets.AKAMAI_V4 + Presets.AKAMAI_V6)
        check(Presets.cidrsFor(ScanMode.AKAMAI, NetFamily.V4) == Presets.AKAMAI_V4)
        check(Presets.cidrsFor(ScanMode.AKAMAI, NetFamily.V6) == Presets.AKAMAI_V6)
        // the Akamai pool shares no prefix with the Cloudflare pools — an
        // accidental copy-paste would scan the wrong CDN under the new name.
        val cf = Presets.CF_EDGE_V4.toSet() + Presets.WARP_V4.toSet()
        check(Presets.AKAMAI_V4.none { it in cf }) { "akamai v4 pool must not contain CF/WARP prefixes" }
    }

    @Test
    fun `akamai scan pins the single tls port`() {
        check(Presets.defaultPort(ScanMode.AKAMAI) == 443)
        check(Presets.portsFor(ScanMode.AKAMAI) == listOf(443)) {
            "akamai edges are TLS-proven on :443 only — got ${Presets.portsFor(ScanMode.AKAMAI)}"
        }
    }

    @Test
    fun `estimate matches the per-prefix sampling contract`() {
        val both = Presets.cidrsFor(ScanMode.AKAMAI, NetFamily.BOTH)
        // every akamai block is wider than a /22, so each contributes exactly
        // `samples` candidates — the same estimate law as CF_EDGE.
        // v4.2: 29 v4 + 3 v6 = 32 blocks.
        check(IpGenerator.estimate(both, NetFamily.BOTH, 96) == 32 * 96)
        check(IpGenerator.estimate(both, NetFamily.V4, 50) == 29 * 50)
        check(IpGenerator.estimate(both, NetFamily.V6, 50) == 3 * 50)
    }

    // ── routing ─────────────────────────────────────────────────────

    @Test
    fun `akamai params route tls to the census-proven bing sni and run the real speed phase`() {
        val p = ScanParams(mode = ScanMode.AKAMAI)
        // v4.2 (the "fake Akamai IPs" fix): the probe SNI moved to
        // www.bing.com — served by EVERY census edge with HTTP 200 and a real
        // body (www.akamai.com answers everywhere but only with a 403 stub,
        // which made throughput unmeasurable and left users with IPs they
        // could not use).
        check(p.edgeSni == "www.bing.com") { "akamai TLS must verify www.bing.com, got ${p.edgeSni}" }
        check(p.speedSni == "www.bing.com")
        check(p.needsTlsPhase) { "TLS verification is the akamai alive filter" }
        // v4.2: the speed phase RUNS — repeated real-page fetches measure
        // real throughput (the «پرسرعت‌ترین» ask).
        check(p.runsSpeedPhase) { "akamai scans now measure real throughput" }
        check(p.speedPort == 443)
        // the other modes keep their own routing — regression pin
        val edge = ScanParams(mode = ScanMode.CF_EDGE)
        check(edge.edgeSni == "speed.cloudflare.com" && edge.runsSpeedPhase)
        val endpoint = ScanParams(mode = ScanMode.ENDPOINT)
        check(endpoint.speedSni == "speed.cloudflare.com" && endpoint.speedPort == 443)
        // v4.2: the deep-measure defaults ship ON
        check(p.deepMeasure && p.deepTopN == 30 && p.deepSamples == 8) {
            "deep measure ships ON with census-calibrated defaults"
        }
    }

    // ── aliveness ───────────────────────────────────────────────────

    @Test
    fun `akamai alive means tls-cert-verified — a bare tcp connect is not alive`() {
        val verified = ScanResult(
            ip = "23.13.59.120", protocol = IpProtocol.IPv4, port = 443,
            latencyMs = 40.0, successfulAttempts = 3, tlsSuccess = true,
            tlsHandshakeMs = 120.0, mode = ScanMode.AKAMAI,
        )
        check(verified.alive) { "a TLS-verified akamai edge is alive" }
        val tcpOnly = ScanResult(
            ip = "23.197.122.85", protocol = IpProtocol.IPv4, port = 443,
            latencyMs = 30.0, successfulAttempts = 3, tlsSuccess = false,
            error = "TLS: certificate does not match www.bing.com",
            mode = ScanMode.AKAMAI,
        )
        check(!tcpOnly.alive) { "tcp-alive alone proves nothing (dpi fake-accept) — the v3.7 lesson" }
        // honest escape hatch: tlsVerify OFF marks rows TCP-ONLY instead of
        // silently dropping them (the v3.2 contract, unchanged for akamai)
        val skipped = tcpOnly.copy(tlsSkipped = true, error = null)
        check(skipped.alive && skipped.tcpAlive)
    }

    // ── generation ──────────────────────────────────────────────────

    @Test
    fun `a pinned v4 single-address block generates its one address — not zero candidates`() {
        // v4.1 live-run fix: the old net/broadcast guard swallowed every v4
        // /32 whole — a CUSTOM-mode user pasting exact IPs (or the live test
        // pinning a verified edge) got ZERO candidates with no hint why.
        val one = IpGenerator.generate(listOf("23.13.59.120/32"), NetFamily.V4, 10, Random(7))
        check(one.size == 1 && one[0].text == "23.13.59.120") { "got ${one.map { it.text }}" }
        val pair = IpGenerator.generate(listOf("104.16.1.0/31"), NetFamily.V4, 10, Random(7))
        check(pair.size == 2) { "a /31 must enumerate both in-octet addresses" }
        // a /24 still skips the net/broadcast style edges (hostBits >= 8)
        val block = IpGenerator.generate(listOf("104.16.1.0/24"), NetFamily.V4, 512, Random(7))
        check(block.size == 254) { "24-bit host enumeration keeps 254 of 256, got ${block.size}" }
        check(block.none { it.text.endsWith(".0") || it.text.endsWith(".255") })
        // the estimate now agrees with what generation actually emits for a /32
        check(IpGenerator.estimate(listOf("23.13.59.120/32"), NetFamily.V4, 10) == 1)
    }

    @Test
    fun `drawn akamai candidates land inside the akamai pool`() {
        val v4Blocks = CidrBlock.parseAll(Presets.AKAMAI_V4)
        val v6Blocks = CidrBlock.parseAll(Presets.AKAMAI_V6)
        val v4 = IpGenerator.generate(Presets.AKAMAI_V4, NetFamily.V4, 7, Random(1))
        val v6 = IpGenerator.generate(Presets.AKAMAI_V6, NetFamily.V6, 7, Random(2))
        check(v4.size == 29 * 7 && v6.size == 3 * 7)
        check(v4.all { it.protocol == IpProtocol.IPv4 } && v6.all { it.protocol == IpProtocol.IPv6 })
        fun inside(cands: List<com.umbra.scanner.core.Candidate>, blocks: List<CidrBlock>) =
            cands.all { c ->
                val v = BigInteger(1, c.bytes)
                blocks.any { v >= it.base && v < it.base.add(it.size) }
            }
        check(inside(v4, v4Blocks)) { "a v4 draw escaped the akamai pool" }
        check(inside(v6, v6Blocks)) { "a v6 draw escaped the akamai pool" }
        // family filtering on the BOTH list keeps families separated
        val both = IpGenerator.generate(
            Presets.cidrsFor(ScanMode.AKAMAI, NetFamily.BOTH), NetFamily.V6, 3, Random(3),
        )
        check(both.all { it.protocol == IpProtocol.IPv6 })
    }

    // ── auto-tune / codec / ranking ─────────────────────────────────

    @Test
    fun `auto-tune keeps akamai tls-verified with the real throughput pass`() {
        val tune = AutoTune.decide(
            AutoTune.Calibration(rttMs = 60.0, v6Ok = true, linkMbps = 20.0, cores = 8, lowRam = false),
            ScanMode.AKAMAI,
        )
        // v4.2: akamai now measures real throughput (repeated bing page
        // fetches) — auto-tune keeps the pass ON.
        check(tune.speedTest) { "akamai has a real throughput pass since v4.2" }
        check(tune.tlsVerify) { "TLS verification is the akamai alive filter — never auto-off" }
        check(tune.port == 443)
        check(tune.mode == ScanMode.AKAMAI)
        check(tune.notes.any { it.contains("www.bing.com") }) { "the report names the census-proven akamai SNI" }
        // the other modes' tuning is untouched
        val edge = AutoTune.decide(
            AutoTune.Calibration(rttMs = 60.0, v6Ok = true, linkMbps = 20.0, cores = 8, lowRam = false),
            ScanMode.CF_EDGE,
        )
        check(edge.speedTest && edge.tlsVerify)
    }

    @Test
    fun `akamai rows roundtrip through the codec with mode and proof intact`() {
        val r = ScanResult(
            ip = "184.51.102.209", protocol = IpProtocol.IPv4, port = 443,
            latencyMs = 14.0, jitterMs = 1.2, packetLoss = 0.0,
            successfulAttempts = 3, tcpAttempts = 3, tlsSuccess = true,
            tlsHandshakeMs = 44.0, mode = ScanMode.AKAMAI,
        )
        val back = requireNotNull(ResultCodec.fromJson(ResultCodec.toJson(r))) { "codec roundtrip failed" }
        check(back.mode == ScanMode.AKAMAI)
        check(back.alive && back.tlsSuccess && back.tlsHandshakeMs == 44.0)
        check(back.latencyMs == 14.0)
    }

    @Test
    fun `smart ranking scores live akamai edges above dead ones`() {
        val profile = null // neutral weights — the no-NETSENSE case
        val alive = ScanResult(
            ip = "23.13.59.120", protocol = IpProtocol.IPv4, port = 443,
            latencyMs = 40.0, jitterMs = 2.0, successfulAttempts = 3,
            tlsSuccess = true, mode = ScanMode.AKAMAI,
        )
        val dead = alive.copy(tlsSuccess = false, successfulAttempts = 0, error = "timeout")
        check(SmartRanking.score(alive, profile) > 0.0)
        check(SmartRanking.score(dead, profile) == 0.0)
        // v4.2: akamai rows DO carry real throughput now — the neutral speed
        // sub-score must not turn a null into a crash (rows without a
        // measurement still rank on the other sub-scores)
        check(SmartRanking.speedScore(alive) > 0.0)
    }
}
