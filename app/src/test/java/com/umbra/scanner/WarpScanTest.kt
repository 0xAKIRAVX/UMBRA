package com.umbra.scanner

import com.umbra.scanner.core.IpGenerator
import com.umbra.scanner.core.IpProtocol
import com.umbra.scanner.core.IpText
import com.umbra.scanner.core.NetFamily
import com.umbra.scanner.core.Presets
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.engine.AutoTune
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * v3.8 — core contracts of the WARP endpoint machinery (all of it now in the
 * service of ENDPOINT mode; the standalone WARP mode is gone):
 *
 *  - v6 endpoint embedding (d0/d1 prefixes carry the v4 pool in the last 32 bits)
 *  - the canonical WARP port list
 *  - speed always riding :443
 *  - the BPB 3/5/7 wireguard-retry ladder in auto-tune
 */
class WarpScanTest {

    // ── WARP v6 endpoint embedding ──────────────────────────────────

    @Test
    fun `warp v6 embeds ipv4 in last 32 bits`() {
        val v4 = IpText.literalToBytes("162.159.192.1")!!
        val v6 = IpGenerator.v6Embedded(Presets.WARP_V6_PREFIX_D0, v4)
        assertNotNull(v6)
        assertEquals(16, v6!!.size)
        assertEquals("2606:4700:d0::a29f:c001", IpText.format(v6))
    }

    @Test
    fun `warp v6 d1 prefix renders correctly`() {
        val v4 = IpText.literalToBytes("188.114.96.1")!!
        val v6 = IpGenerator.v6Embedded(Presets.WARP_V6_PREFIX_D1, v4)
        assertEquals("2606:4700:d1::bc72:6001", IpText.format(v6!!))
    }

    @Test
    fun `embedded v6 embeds the exact v4 tail`() {
        val v4 = IpText.literalToBytes("162.159.192.1")!!
        val v6 = IpGenerator.v6Embedded(Presets.WARP_V6_PREFIX_D0, v4)!!
        assertEquals(4, v4.size)
        for (i in 0..3) assertEquals(v4[i], v6[12 + i])
    }

    @Test
    fun `endpoint v6 pool follows the embedded d0-d1 pattern`() {
        val pairs = IpGenerator.generateEndpoints(NetFamily.V6, 200, 0, kotlin.random.Random(21))
        assertTrue(pairs.isNotEmpty())
        pairs.forEach { p ->
            val t = p.candidate.text
            assertTrue(
                "candidate $t must match d0/d1 embedded pattern",
                t.startsWith("2606:4700:d0:") || t.startsWith("2606:4700:d1:")
            )
        }
    }

    // ── port list ───────────────────────────────────────────────────

    @Test
    fun `warp ports full is sane`() {
        assertEquals(Presets.WARP_PORTS_FULL.size, Presets.WARP_PORTS_FULL.distinct().size)
        assertTrue(Presets.WARP_PORTS_FULL.all { it in 1..65535 })
        assertTrue(2408 in Presets.WARP_PORTS_FULL)
        assertTrue(443 in Presets.WARP_PORTS_FULL)
        assertTrue(Presets.WARP_PORTS_FULL == Presets.WARP_PORTS_FULL.sorted())
    }

    @Test
    fun `endpoint speed always rides 443`() {
        val endpoint = ScanParams(mode = ScanMode.ENDPOINT, port = 2408)
        assertEquals(443, endpoint.speedPort)
        val endpointRandom = ScanParams(mode = ScanMode.ENDPOINT, port = 0)
        assertEquals(443, endpointRandom.speedPort)
        val edge = ScanParams(mode = ScanMode.CF_EDGE, port = 2053)
        assertEquals(2053, edge.speedPort)
    }

    @Test
    fun `endpoint mode never runs a tls phase`() {
        val endpoint = ScanParams(mode = ScanMode.ENDPOINT, tlsVerify = true)
        assertTrue(!endpoint.needsTlsPhase)
        val edge = ScanParams(mode = ScanMode.CF_EDGE, tlsVerify = true)
        assertTrue(edge.needsTlsPhase)
    }

    @Test
    fun `legacy mode ordinals migrate to the new enum`() {
        // v3.8: old persisted p_mode values (0=CF_EDGE, 1=WARP, 2=CUSTOM, 3=ENDPOINT)
        assertEquals(ScanMode.CF_EDGE, ScanMode.fromLegacyOrdinal(0))
        assertEquals(ScanMode.ENDPOINT, ScanMode.fromLegacyOrdinal(1))   // old WARP
        assertEquals(ScanMode.CUSTOM, ScanMode.fromLegacyOrdinal(2))
        assertEquals(ScanMode.ENDPOINT, ScanMode.fromLegacyOrdinal(3))
        assertEquals(ScanMode.ENDPOINT, ScanMode.fromLegacyOrdinal(99))  // garbage → default
        // new-space ordinals are stable
        assertEquals(0, ScanMode.CF_EDGE.ordinal)
        assertEquals(1, ScanMode.CUSTOM.ordinal)
        assertEquals(2, ScanMode.ENDPOINT.ordinal)
    }

    // ── auto-tune decisions (pure function) ─────────────────────────

    @Test
    fun `tune endpoint mode scales retries and count with rtt`() {
        fun endpointTune(rtt: Double?): AutoTune.TuneResult = AutoTune.decide(
            AutoTune.Calibration(rttMs = rtt, v6Ok = false, cores = 8, lowRam = false),
            ScanMode.ENDPOINT,
        )
        val good = endpointTune(45.0)
        assertEquals(3, good.warpAttempts)      // good network → BPB ladder bottom
        assertEquals(3, good.tcpAttempts)       // the ladder mirrors the tcp side
        assertEquals(2000, good.tcpTimeoutMs)   // wg handshake floor
        assertEquals(0, good.port)              // RANDOM ports
        assertEquals(700, good.endpointsCount)
        assertEquals(false, good.speedTest)     // latency-first (BPB parity)
        assertEquals(false, good.tlsVerify)

        val poor = endpointTune(250.0)
        assertEquals(7, poor.warpAttempts)      // poor network → ladder top
        assertEquals(300, poor.endpointsCount)
        assertEquals(2000, poor.tcpTimeoutMs)

        val unknown = endpointTune(null)
        assertEquals(5, unknown.warpAttempts)
        assertEquals(400, unknown.endpointsCount)
    }

    @Test
    fun `tune notes promise handshake validation`() {
        val r = AutoTune.decide(
            AutoTune.Calibration(rttMs = 100.0, v6Ok = false, cores = 8, lowRam = false),
            ScanMode.ENDPOINT,
        )
        assertTrue(r.notes.isNotEmpty())
        assertTrue(r.notes.any { it.contains("wireguard retries") })
        assertTrue(r.notes.any { it.contains("never reported") })
        assertTrue(r.notes.any { it.contains("random port") })
    }

    @Test
    fun `tune edge mode picks family and timeout from rtt`() {
        val r = AutoTune.decide(
            AutoTune.Calibration(rttMs = 45.0, v6Ok = true, linkMbps = 90.0, cores = 8, lowRam = false),
            ScanMode.CF_EDGE,
        )
        assertEquals(443, r.port)
        assertEquals(NetFamily.BOTH, r.family)
        assertEquals(20, r.downloadMb) // fast link → 20mb
        assertEquals(3, r.tcpAttempts)
        assertTrue(r.tcpTimeoutMs < 2000) // no wg floor in edge mode
        assertTrue(r.tlsVerify)
    }
}
