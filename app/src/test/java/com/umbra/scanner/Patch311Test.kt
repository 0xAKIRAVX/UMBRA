package com.umbra.scanner

import com.umbra.scanner.core.CidrBlock
import com.umbra.scanner.core.IpGenerator
import com.umbra.scanner.core.IpProtocol
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanResult
import com.umbra.scanner.export.Exporters
import com.umbra.scanner.net.NetGrade
import com.umbra.scanner.net.NetQuality
import com.umbra.scanner.net.NetworkProfile
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.math.BigInteger
import java.util.Locale
import kotlin.random.Random

/**
 * v3.1.1 regression tests — one per shipped bug fix.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class Patch311Test {

    // ── B2: small blocks must respect the samples knob ─────────────────────

    @Test
    fun `small block honors samples below block size`() {
        val b = CidrBlock.parse("162.159.192.0/24")!!
        val out = ArrayList<ByteArray>()
        b.sampleCandidates(96, Random(1234), out)
        assertEquals("samples knob must be respected, not full enumeration", 96, out.size)
        val base = BigInteger(1, byteArrayOf(162.toByte(), 159.toByte(), 192.toByte(), 0))
        for (bytes in out) {
            val v = BigInteger(1, bytes)
            assertTrue(v > base && v < base.add(BigInteger.valueOf(256)))
            val last = bytes[3].toInt() and 0xFF
            assertTrue("net/broadcast-style edges excluded: .$last", last in 1..254)
        }
    }

    @Test
    fun `small block still enumerates when full coverage requested`() {
        val b = CidrBlock.parse("162.159.192.0/24")!!
        val out = ArrayList<ByteArray>()
        b.sampleCandidates(300, Random(7), out)
        assertEquals(254, out.size)
    }

    @Test
    fun `sampling is uniform enough to spread across the block`() {
        val b = CidrBlock.parse("162.159.192.0/24")!!
        val out = ArrayList<ByteArray>()
        b.sampleCandidates(96, Random(99), out)
        val distinct = out.map { BigInteger(1, it) }.toSet()
        assertEquals(96, distinct.size)
        // with 96/254 sampled, the third-octet spread over .1-.254 should
        // cover a wide range (guard against a pathological clumped sampler)
        val lastBytes = out.map { it[3].toInt() and 0xFF }
        assertTrue("spread too narrow", (lastBytes.maxOrNull()!! - lastBytes.minOrNull()!!) > 100)
    }

    @Test
    fun `estimate matches sampling for small blocks`() {
        val cidrs = listOf("162.159.192.0/24")
        val estimate = IpGenerator.estimate(cidrs, com.umbra.scanner.core.NetFamily.V4, 96)
        val out = ArrayList<ByteArray>()
        for (b in CidrBlock.parseAll(cidrs)) b.sampleCandidates(96, Random(5), out)
        assertEquals("UI estimate must equal actual emitted candidates", out.size, estimate)
    }

    @Test
    fun `warp v4 generation matches the classic estimate`() {
        // 16 /24 blocks × 96 samples — the advertised number
        val estimate = PresetsFixtures.warpV4Count(96)
        val gen = IpGenerator.generateWarp(
            com.umbra.scanner.core.NetFamily.V4, 96, Random(11))
        assertEquals(estimate, gen.size)
    }

    // ── B3: stale error must not haunt verified endpoints ─────────────────

    @Test
    fun `merge clears stale error once endpoint is alive`() {
        val dead = ScanResult(
            ip = "1.2.3.4", protocol = IpProtocol.IPv4, port = 443,
            latencyMs = null, packetLoss = 1.0, tcpAttempts = 3, successfulAttempts = 0,
            error = "unreachable", mode = ScanMode.CF_EDGE,
        )
        val verified = ScanResult(
            ip = "1.2.3.4", protocol = IpProtocol.IPv4, port = 443,
            latencyMs = 42.0, packetLoss = 0.0, tcpAttempts = 3, successfulAttempts = 3,
            tlsSuccess = true, mode = ScanMode.CF_EDGE,
        )
        val merged = dead.merge(verified)
        assertTrue(merged.alive)
        assertNull("stale 'unreachable' must be gone on a verified endpoint", merged.error)
    }

    @Test
    fun `merge keeps a fresh failure note`() {
        val alive = ScanResult(
            ip = "1.2.3.4", protocol = IpProtocol.IPv4, port = 443,
            latencyMs = 42.0, successfulAttempts = 3, tlsSuccess = true,
            mode = ScanMode.CF_EDGE,
        )
        val speedFail = alive.copy(
            error = "no measurable throughput",
            speedMbps = null,
        )
        val merged = alive.merge(speedFail)
        assertEquals("no measurable throughput", merged.error)
    }

    // ── B6: DPI-suspected lines cannot grade EXCELLENT ────────────────────

    @Test
    fun `dpi fake-accept clamps excellent grade to good`() {
        val dpi = NetworkProfile(
            latencyMs = 30.0, jitterMs = 3.0, packetLoss = 0.0,
            tlsRttMs = null, dpiSuspected = true, downloadMbps = 80.0,
        )
        assertEquals(NetGrade.GOOD, dpi.grade)

        val clean = NetworkProfile(
            latencyMs = 30.0, jitterMs = 3.0, packetLoss = 0.0,
            tlsRttMs = 45.0, dpiSuspected = false, downloadMbps = 80.0,
        )
        assertEquals(NetGrade.EXCELLENT, clean.grade)
    }

    // ── B4: exports must be locale-independent (invalid JSON on fa devices) ─

    @Test
    fun `exports stay latin-digit under persian locale`() {
        val prev = Locale.getDefault()
        try {
            Locale.setDefault(Locale("fa", "IR"))
            val r = ScanResult(
                ip = "162.159.192.1", protocol = IpProtocol.IPv4, port = 443,
                latencyMs = 123.4, jitterMs = 5.6, packetLoss = 0.02,
                speedMbps = 12.5, downloadedBytes = 20L * 1024 * 1024,
                tcpAttempts = 3, successfulAttempts = 3, tlsSuccess = true,
                tlsHandshakeMs = 88.9, httpStatus = 200,
                mode = ScanMode.CF_EDGE,
            )
            val json = Exporters.json(listOf(r), null)
            // must parse as strict JSON (Persian digits would corrupt it)
            val parsed = JSONObject(json)
            val arr = parsed.getJSONArray("results")
            assertEquals(1, arr.length())
            assertEquals(123.4, arr.getJSONObject(0).getDouble("latencyMs"), 0.001)
            assertTrue("digits must stay Latin", json.contains("123.4"))

            val csv = Exporters.csv(listOf(r))
            assertTrue("csv digits must stay Latin", csv.contains("12.50"))

            val txt = Exporters.txt(listOf(r), null)
            assertTrue("txt digits must stay Latin", txt.contains("123ms") || txt.contains("1234ms"))
        } finally {
            Locale.setDefault(prev)
        }
    }

    @Test
    fun `round-trip json codec under persian locale`() {
        val prev = Locale.getDefault()
        try {
            Locale.setDefault(Locale("fa", "IR"))
            val r = ScanResult(
                ip = "188.114.96.1", protocol = IpProtocol.IPv4, port = 2408,
                latencyMs = 77.5, jitterMs = 4.5, packetLoss = 0.0,
                successfulAttempts = 2, tcpAttempts = 3, wgHandshakes = 3,
                mode = ScanMode.WARP,
            )
            val json = Exporters.json(listOf(r), null)
            assertNotNull(JSONObject(json)) // strict parse must not throw
        } finally {
            Locale.setDefault(prev)
        }
    }
}

private object PresetsFixtures {
    fun warpV4Count(samples: Int): Int =
        com.umbra.scanner.core.Presets.WARP_V4.size * samples
}
