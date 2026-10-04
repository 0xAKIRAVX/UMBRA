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
    fun `generateWarp produces v4 and embedded v6 only`() {
        val candidates = IpGenerator.generateWarp(NetFamily.BOTH, 40)
        assertTrue(candidates.isNotEmpty())
        assertTrue(candidates.any { it.protocol == IpProtocol.IPv4 })
        val v6 = candidates.filter { it.protocol == IpProtocol.IPv6 }
        assertTrue(v6.isNotEmpty())
        // every v6 candidate must carry a real embedded v4 pattern, never a
        // uniformly random /48 address (which is what the old bug produced)
        v6.forEach { c ->
            assertTrue(
                "candidate ${c.text} must match d0/d1 embedded pattern",
                c.text.startsWith("2606:4700:d0::") || c.text.startsWith("2606:4700:d1::")
            )
            // the embedded v4 (last 32 bits) must be inside a WARP v4 prefix
            val lastTwo = c.text.substringAfterLast("::")
            val groups = lastTwo.split(':')
            assertEquals(2, groups.size)
            val v4text = groups.flatMap { g ->
                val h = g.toInt(16)
                listOf((h shr 8) and 0xFF, h and 0xFF)
            }.joinToString(".")
            val v4bytes = IpText.literalToBytes(v4text)
            assertNotNull("embedded v4 $v4text must parse", v4bytes)
            val value = java.math.BigInteger(1, v4bytes!!)
            val inside = Presets.WARP_V4.any { cidr ->
                val b = com.umbra.scanner.core.CidrBlock.parse(cidr)!!
                value >= b.base && value < b.base.add(b.size)
            }
            assertTrue("embedded v4 $v4text must be inside a warp cidr", inside)
        }
    }

    @Test
    fun `generateWarp respects family filter`() {
        val v4only = IpGenerator.generateWarp(NetFamily.V4, 20)
        assertTrue(v4only.all { it.protocol == IpProtocol.IPv4 })
        val v6only = IpGenerator.generateWarp(NetFamily.V6, 20)
        assertTrue(v6only.isNotEmpty())
        assertTrue(v6only.all { it.protocol == IpProtocol.IPv6 })
    }

    // ── port sweep plumbing ─────────────────────────────────────────

    @Test
    fun `warp ports full is sane`() {
        assertEquals(Presets.WARP_PORTS_FULL.size, Presets.WARP_PORTS_FULL.distinct().size)
        assertTrue(Presets.WARP_PORTS_FULL.all { it in 1..65535 })
        assertTrue(2408 in Presets.WARP_PORTS_FULL)
        assertTrue(443 in Presets.WARP_PORTS_FULL)
        assertTrue(Presets.WARP_PORTS_FULL == Presets.WARP_PORTS_FULL.sorted())
    }

    @Test
    fun `effective ports respects sweep and family`() {
        val sweep = ScanParams(mode = ScanMode.WARP, port = 2408, portSweep = true)
        assertEquals(Presets.WARP_PORTS_FULL, sweep.effectivePorts)
        val sweepCustom = sweep.copy(sweepPorts = listOf(894, 443))
        assertEquals(listOf(443, 894), sweepCustom.effectivePorts)
        val single = ScanParams(mode = ScanMode.WARP, port = 894, portSweep = false)
        assertEquals(listOf(894), single.effectivePorts)
        val edge = ScanParams(mode = ScanMode.CF_EDGE, port = 443, portSweep = true)
        assertEquals(listOf(443), edge.effectivePorts)
    }

    @Test
    fun `warp speed always rides 443`() {
        val warp = ScanParams(mode = ScanMode.WARP, port = 2408)
        assertEquals(443, warp.speedPort)
        val edge = ScanParams(mode = ScanMode.CF_EDGE, port = 2053)
        assertEquals(2053, edge.speedPort)
    }

    // ── auto-tune decisions (pure function) ─────────────────────────

    @Test
    fun `tune locks 2408 when open`() {
        val r = AutoTune.decide(
            AutoTune.Calibration(
                rttMs = 120.0,
                v6Ok = false,
                warpPortLatency = mapOf(2408 to 45.0, 894 to 50.0, 443 to 47.0, 928 to 52.0),
                linkMbps = 12.0,
                cores = 8,
                lowRam = false,
            ),
            ScanMode.WARP,
        )
        assertEquals(NetFamily.V4, r.family)
        assertEquals(2408, r.port)
        assertEquals(true, r.portSweep) // 4 working ports → sweep with 2408 first
        assertTrue(r.sweepPorts.first() == 2408)
        assertTrue(r.tcpTimeoutMs in 500..700) // 4×120 → coerced to 700
        assertEquals(3, r.tcpAttempts)
        assertTrue(r.concurrency in 96..320)
        assertTrue(r.downloadMb == 10) // 12mbps → 10mb
    }

    @Test
    fun `tune sweeps when 2408 blocked`() {
        val r = AutoTune.decide(
            AutoTune.Calibration(
                rttMs = 210.0,
                v6Ok = true,
                warpPortLatency = mapOf(894 to 90.0, 928 to 92.0),
                linkMbps = 1.4,
                cores = 4,
                lowRam = false,
            ),
            ScanMode.WARP,
        )
        assertEquals(NetFamily.BOTH, r.family)
        assertTrue(r.portSweep)
        assertTrue(2408 !in r.sweepPorts)
        assertEquals(894, r.port)
        assertTrue(443 in r.sweepPorts) // 443 added as safety
        assertTrue(r.concurrency <= 128) // slow link caps concurrency
        assertEquals(5, r.downloadMb) // <3mbps → 5mb
    }

    @Test
    fun `tune falls back to 443 when everything is blocked`() {
        val r = AutoTune.decide(
            AutoTune.Calibration(
                rttMs = 380.0,
                v6Ok = false,
                warpPortLatency = emptyMap(),
                linkMbps = null,
                cores = 4,
                lowRam = true,
            ),
            ScanMode.WARP,
        )
        assertEquals(443, r.port)
        // nothing answered a real handshake → sweep the full port list anyway
        assertEquals(true, r.portSweep)
        assertTrue(r.sweepPorts.isNotEmpty())
        assertTrue(r.concurrency in 48..160)
        assertEquals(10, r.downloadMb) // unknown link → 10mb
        assertTrue(r.tcpTimeoutMs >= 1500) // 4×380 → 1520 → 1600
        // poor rtt → maximum wireguard retries
        assertEquals(7, r.warpAttempts)
    }

    @Test
    fun `tune edge mode ignores ports but still times out from rtt`() {
        val r = AutoTune.decide(
            AutoTune.Calibration(
                rttMs = 45.0,
                v6Ok = true,
                warpPortLatency = emptyMap(),
                linkMbps = 90.0,
                cores = 8,
                lowRam = false,
            ),
            ScanMode.CF_EDGE,
        )
        assertEquals(443, r.port)
        assertEquals(false, r.portSweep)
        assertEquals(NetFamily.BOTH, r.family)
        assertEquals(20, r.downloadMb) // fast link → 20mb
        assertTrue(r.tcpTimeoutMs in 700..800) // 4×45=180 → 200? no: coerceIn(700..) → 700
    }

    @Test
    fun `tune notes explain every choice`() {
        val r = AutoTune.decide(
            AutoTune.Calibration(rttMs = 100.0, v6Ok = false, cores = 8, lowRam = false),
            ScanMode.WARP,
        )
        assertTrue(r.notes.isNotEmpty())
        assertTrue(r.notes.any { it.contains(":443 sweep fallback") })
        assertTrue(r.notes.any { it.contains("wireguard retries") })
        assertTrue(r.notes.any { it.contains("handshake") })
    }

    @Test
    fun `warp retries scale with network quality`() {
        fun tries(rtt: Double?) = AutoTune.decide(
            AutoTune.Calibration(rttMs = rtt, v6Ok = false, cores = 8, lowRam = false),
            ScanMode.WARP,
        ).warpAttempts
        assertEquals(3, tries(45.0))   // good network
        assertEquals(5, tries(120.0))  // moderate
        assertEquals(7, tries(250.0))  // poor
        assertEquals(5, tries(null))   // unknown → middle
    }
}
