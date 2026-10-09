package com.umbra.scanner

import com.umbra.scanner.core.CidrBlock
import com.umbra.scanner.core.IpGenerator
import com.umbra.scanner.core.IpProtocol
import com.umbra.scanner.core.IpText
import com.umbra.scanner.core.NetFamily
import com.umbra.scanner.core.Presets
import com.umbra.scanner.core.Ranking
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.core.ScanResult
import com.umbra.scanner.core.SmartRanking
import org.junit.Test
import kotlin.random.Random

/**
 * v3.7 ENDPOINT mode — the BPB-Warp-Scanner-style endpoint scanner:
 * random ip:port pairs over the WARP ranges, IPv4 + IPv6, pure TCP
 * latency/loss probing. These tests pin the mode's CONTRACTS:
 *
 *  - generation: count honored, BPB family split, ip:port dedup,
 *    canonical-port pool, v4 pool membership, v6 embedded pattern
 *  - model: TCP-alive IS alive (no TLS phase exists in this mode),
 *    speed rides :443, ordinal stability for persisted prefs
 *  - codec + ranking keep working for ENDPOINT rows
 */
class EndpointModeTest {

    // ── enum / persistence safety ──────────────────────────────────

    @Test
    fun `endpoint mode is appended at ordinal 3 so persisted ordinals never shift`() {
        check(ScanMode.ENDPOINT.ordinal == 3) { "ENDPOINT must be ordinal 3" }
        check(ScanMode.CF_EDGE.ordinal == 0)
        check(ScanMode.WARP.ordinal == 1)
        check(ScanMode.CUSTOM.ordinal == 2)
    }

    // ── presets ────────────────────────────────────────────────────

    @Test
    fun `endpoint mode scans the WARP pool with warp quick-pick ports`() {
        check(Presets.cidrsFor(ScanMode.ENDPOINT, NetFamily.BOTH) == Presets.WARP_V4 + Presets.WARP_V6)
        check(Presets.cidrsFor(ScanMode.ENDPOINT, NetFamily.V4) == Presets.WARP_V4)
        check(Presets.cidrsFor(ScanMode.ENDPOINT, NetFamily.V6) == Presets.WARP_V6)
        check(Presets.defaultPort(ScanMode.ENDPOINT) == 0) { "0 = RANDOM sentinel" }
        check(Presets.portsFor(ScanMode.ENDPOINT) == Presets.WARP_PORTS)
    }

    // ── generation ─────────────────────────────────────────────────

    @Test
    fun `generation honors the count and BPB half-half family split`() {
        val pairs = IpGenerator.generateEndpoints(NetFamily.BOTH, 101, 0, Random(7))
        check(pairs.size == 101) { "got ${pairs.size}" }
        val v4 = pairs.count { it.candidate.protocol == IpProtocol.IPv4 }
        val v6 = pairs.count { it.candidate.protocol == IpProtocol.IPv6 }
        // BPB main.go: ipv4Count = count/2, ipv6Count = count - ipv4Count
        check(v4 == 50 && v6 == 51) { "v4=$v4 v6=$v6" }
    }

    @Test
    fun `family v4 only generates exclusively v4 endpoints`() {
        val pairs = IpGenerator.generateEndpoints(NetFamily.V4, 200, 0, Random(9))
        check(pairs.size == 200)
        check(pairs.all { it.candidate.protocol == IpProtocol.IPv4 })
    }

    @Test
    fun `family v6 only generates embedded d0-d1 v6 endpoints`() {
        val pairs = IpGenerator.generateEndpoints(NetFamily.V6, 200, 0, Random(21))
        check(pairs.size == 200)
        check(pairs.all { it.candidate.protocol == IpProtocol.IPv6 })
        // "188.114.99.0/24" → network prefix "188.114.99."
        val poolPrefixes = Presets.WARP_V4.map { it.substringBeforeLast('.') + "." }
        for (p in pairs) {
            val t = p.candidate.text
            check(
                t.startsWith("2606:4700:d0:") || t.startsWith("2606:4700:d1:")
            ) { "v6 outside d0/d1 embedded pattern: $t" }
            // the embedded v4 must be a valid WARP-pool host (last 32 bits)
            val bytes = IpText.literalToBytes(t)!!
            val embedded = "${bytes[12].toInt() and 0xFF}.${bytes[13].toInt() and 0xFF}.${bytes[14].toInt() and 0xFF}.${bytes[15].toInt() and 0xFF}"
            check(poolPrefixes.any { embedded.startsWith(it) }) {
                "embedded v4 $embedded outside the WARP pool"
            }
        }
    }

    @Test
    fun `pinned port mode uses that port on every endpoint`() {
        val pairs = IpGenerator.generateEndpoints(NetFamily.V4, 60, 2408, Random(3))
        check(pairs.size == 60)
        check(pairs.all { it.port == 2408 })
    }

    @Test
    fun `random port mode draws from the canonical WARP port list`() {
        val pairs = IpGenerator.generateEndpoints(NetFamily.BOTH, 400, 0, Random(11))
        check(pairs.isNotEmpty())
        check(pairs.all { it.port in Presets.WARP_PORTS_FULL }) {
            "port outside WARP_PORTS_FULL: ${pairs.firstOrNull { it.port !in Presets.WARP_PORTS_FULL }?.port}"
        }
        check(pairs.map { it.port }.distinct().size > 1) { "randomness never spread across ports" }
    }

    @Test
    fun `endpoints dedup on ip+port while ip reuse across ports is allowed`() {
        // 4000 endpoints from a 4064-IP v4 pool × 55 ports must reuse IPs
        val pairs = IpGenerator.generateEndpoints(NetFamily.V4, 4000, 0, Random(5))
        check(pairs.size == 4000) { "guard gave up early: ${pairs.size}" }
        val ids = pairs.map { "${it.candidate.text}:${it.port}" }
        check(ids.size == ids.distinct().size) { "duplicate endpoints emitted" }
        val distinctIps = pairs.map { it.candidate.text }.distinct().size
        check(distinctIps < 4000) { "expected ip reuse at this density, got $distinctIps distinct ips" }
    }

    @Test
    fun `v4 candidates live inside the WARP pool and skip net-broadcast hosts`() {
        val pairs = IpGenerator.generateEndpoints(NetFamily.V4, 800, 0, Random(13))
        // "188.114.99.0/24" → network prefix "188.114.99."
        val prefixes = Presets.WARP_V4.map { it.substringBeforeLast('.') + "." }
        for (p in pairs) {
            val t = p.candidate.text
            check(!t.endsWith(".0") && !t.endsWith(".255")) { "net/broadcast host emitted: $t" }
            check(prefixes.any { t.startsWith(it) }) { "v4 outside WARP pool: $t" }
        }
    }

    @Test
    fun `zero or negative count generates nothing`() {
        check(IpGenerator.generateEndpoints(NetFamily.BOTH, 0, 0, Random(1)).isEmpty())
        check(IpGenerator.generateEndpoints(NetFamily.V4, -5, 894, Random(1)).isEmpty())
    }

    @Test
    fun `generated addresses parse back to bytes of the right family`() {
        val pairs = IpGenerator.generateEndpoints(NetFamily.BOTH, 100, 0, Random(17))
        for (p in pairs) {
            val bytes = IpText.literalToBytes(p.candidate.text)
            checkNotNull(bytes)
            check(bytes.size == if (p.candidate.protocol == IpProtocol.IPv4) 4 else 16)
        }
    }

    // ── model semantics ────────────────────────────────────────────

    @Test
    fun `endpoint result is alive exactly when TCP answered at least once`() {
        val dead = ScanResult(
            ip = "162.159.192.5", protocol = IpProtocol.IPv4, port = 894,
            tcpAttempts = 3, successfulAttempts = 0,
            error = "TCP timeout", mode = ScanMode.ENDPOINT,
        )
        check(!dead.alive)
        check(!dead.tcpAlive)

        val alive = dead.copy(successfulAttempts = 2, latencyMs = 45.0, error = null)
        check(alive.alive) { "TCP-alive endpoint must be alive in ENDPOINT mode" }
    }

    @Test
    fun `endpoint mode never runs the TLS phase and always speeds on 443`() {
        val p = ScanParams(mode = ScanMode.ENDPOINT, tlsVerify = true, port = 0)
        check(!p.needsTlsPhase) { "ENDPOINT must not TLS-verify (warp ports don't serve the speed host)" }
        check(p.speedPort == 443) { "port 0 (RANDOM) must never become the speed port" }
        check(p.endpointsCount == 500) { "default endpoint count" }

        val pinned = ScanParams(mode = ScanMode.ENDPOINT, port = 2408)
        check(pinned.speedPort == 443) { "endpoint mode always speeds on :443 like WARP mode" }
    }

    @Test
    fun `endpoint merge keeps the alive proof of the newer state`() {
        val base = ScanResult(
            ip = "188.114.97.42", protocol = IpProtocol.IPv4, port = 928,
            tcpAttempts = 3, successfulAttempts = 0, error = "unreachable",
            mode = ScanMode.ENDPOINT,
        )
        val aliveNow = base.copy(
            latencyMs = 51.0, jitterMs = 3.0, packetLoss = 0.0,
            tcpAttempts = 3, successfulAttempts = 3, error = null,
        )
        val merged = base.merge(aliveNow)
        check(merged.alive)
        check(merged.error == null) { "a stale failure must not haunt a now-alive endpoint" }
    }

    // ── ranking + codec ────────────────────────────────────────────

    @Test
    fun `ranking scores and sorts endpoint results by TCP aliveness`() {
        val good = ScanResult(
            ip = "162.159.193.10", protocol = IpProtocol.IPv4, port = 894,
            latencyMs = 40.0, jitterMs = 2.0, packetLoss = 0.0,
            tcpAttempts = 3, successfulAttempts = 3, mode = ScanMode.ENDPOINT,
        )
        val far = good.copy(ip = "188.114.99.77", latencyMs = 140.0)
        val dead = good.copy(ip = "8.6.112.9", latencyMs = null, successfulAttempts = 0)
        check(Ranking.scoreOf(good) > Ranking.scoreOf(far))
        check(Ranking.scoreOf(dead) == 0.0)
        // the app filters to alive rows BEFORE ranking (ScanController.finalize)
        val ranked = SmartRanking.sort(listOf(dead, far, good).filter { it.alive }, null)
        check(ranked.first() == good)
        check(ranked.none { it == dead }) { "dead rows must be filtered out of the final board" }
    }

    @Test
    fun `result codec roundtrips an endpoint-mode row byte for byte`() {
        // org.json needs Robolectric — covered in ResultCodecTest
        // (`v37 endpoint-mode row round-trips with TCP aliveness`).
    }

    @Test
    fun `endpoint cidr blocks parse from the warp presets`() {
        // CidrBlock.parse is used by the endpoint generator — keep it honest
        val blocks = Presets.WARP_V4.map { CidrBlock.parse(it) }
        check(blocks.size == Presets.WARP_V4.size)
        check(blocks.all { it != null && it.family == IpProtocol.IPv4 })
    }
}
