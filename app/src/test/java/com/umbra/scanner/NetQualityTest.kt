package com.umbra.scanner

import com.umbra.scanner.core.IpProtocol
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanResult
import com.umbra.scanner.core.SmartRanking
import com.umbra.scanner.net.NetGrade
import com.umbra.scanner.net.NetQuality
import com.umbra.scanner.net.NetworkProfile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * NETSENSE grading + the adaptive SmartRanking engine (pure logic, no network).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class NetQualityTest {

    // ── grading thresholds ────────────────────────────────────────────

    @Test
    fun `grade thresholds classify real-world lines`() {
        // fiber-grade European line
        assertEquals(
            NetGrade.EXCELLENT,
            NetQuality.gradeOf(latencyMs = 25.0, jitterMs = 4.0, packetLoss = 0.0, downloadMbps = 80.0),
        )
        // decent cable / good LTE
        assertEquals(
            NetGrade.GOOD,
            NetQuality.gradeOf(latencyMs = 90.0, jitterMs = 15.0, packetLoss = 0.01, downloadMbps = 15.0),
        )
        // typical Iranian mobile line under load
        assertEquals(
            NetGrade.FAIR,
            NetQuality.gradeOf(latencyMs = 180.0, jitterMs = 40.0, packetLoss = 0.08, downloadMbps = 4.0),
        )
        // congested / throttled line
        assertEquals(
            NetGrade.POOR,
            NetQuality.gradeOf(latencyMs = 320.0, jitterMs = 90.0, packetLoss = 0.30, downloadMbps = 1.0),
        )
        // unreachable → poor, never crashes
        assertEquals(
            NetGrade.POOR,
            NetQuality.gradeOf(latencyMs = null, jitterMs = null, packetLoss = 1.0, downloadMbps = null),
        )
    }

    @Test
    fun `profile json round-trips every field`() {
        val p = NetworkProfile(
            latencyMs = 42.5, jitterMs = 7.25, packetLoss = 0.02, tlsRttMs = 120.0,
            dpiSuspected = true, downloadMbps = 33.5, uploadMbps = 9.75,
            v6Ok = true, measuredAt = 1_700_000_000_000L,
        )
        val restored = NetQuality.profileFromJson(NetQuality.profileToJson(p))
        assertEquals(p, restored)

        val sparse = NetworkProfile()
        assertEquals(sparse, NetQuality.profileFromJson(NetQuality.profileToJson(sparse)))
        assertNull(NetQuality.profileFromJson(null))
        assertNull(NetQuality.profileFromJson(""))
        assertNull(NetQuality.profileFromJson("not json"))
    }

    // ── smart ranking weights ────────────────────────────────────────

    @Test
    fun `weights sum to one and shift with the grade`() {
        val profiles = listOf(
            null,
            NetworkProfile(latencyMs = 20.0, jitterMs = 3.0, packetLoss = 0.0, downloadMbps = 90.0),
            NetworkProfile(latencyMs = 80.0, jitterMs = 12.0, packetLoss = 0.01, downloadMbps = 12.0),
            NetworkProfile(latencyMs = 170.0, jitterMs = 35.0, packetLoss = 0.07, downloadMbps = 3.0),
            NetworkProfile(latencyMs = 300.0, jitterMs = 80.0, packetLoss = 0.25, downloadMbps = 0.5),
        )
        val seen = HashSet<NetGrade>()
        for (p in profiles) {
            val w = SmartRanking.weightsFor(p)
            assertEquals(1.0, w.latency + w.stability + w.speed, 1e-9)
            p?.let { seen.add(it.grade) }
        }
        // all four grades covered by the fixtures
        assertEquals(setOf(NetGrade.EXCELLENT, NetGrade.GOOD, NetGrade.FAIR, NetGrade.POOR), seen)
    }

    @Test
    fun `poor line prioritizes stability over speed and vice versa`() {
        val excellent = NetworkProfile(latencyMs = 20.0, jitterMs = 3.0, packetLoss = 0.0, downloadMbps = 90.0)
        val poor = NetworkProfile(latencyMs = 300.0, jitterMs = 80.0, packetLoss = 0.25, downloadMbps = 0.5)

        val wExcellent = SmartRanking.weightsFor(excellent)
        val wPoor = SmartRanking.weightsFor(poor)
        assertTrue("speed weight must dominate on an excellent line", wExcellent.speed > wExcellent.stability)
        assertTrue("stability weight must dominate on a poor line", wPoor.stability > wPoor.speed)
        assertTrue(wPoor.stability > wPoor.latency * 0.9)
    }

    @Test
    fun `same endpoint scores differently for different baselines`() {
        val near = NetworkProfile(latencyMs = 30.0, jitterMs = 5.0, packetLoss = 0.0, downloadMbps = 50.0)
        val far = NetworkProfile(latencyMs = 250.0, jitterMs = 30.0, packetLoss = 0.05, downloadMbps = 5.0)

        val endpoint = result(ip = "162.159.192.1", latency = 260.0, jitter = 30.0, loss = 0.05, speed = 5.0)

        val scoreForNearLine = SmartRanking.score(endpoint, near)
        val scoreForFarLine = SmartRanking.score(endpoint, far)
        // a 260 ms endpoint is mediocre on a 30 ms line but near-perfect on a 250 ms line
        assertTrue(scoreForFarLine > scoreForNearLine)
    }

    @Test
    fun `dead endpoints and null latency score zero`() {
        val profile = NetworkProfile(latencyMs = 50.0, jitterMs = 10.0, packetLoss = 0.0, downloadMbps = 40.0)
        val dead = result(ip = "1.2.3.4", latency = null, jitter = null, loss = 1.0, speed = null)
            .copy(successfulAttempts = 0, tlsSuccess = false, httpStatus = null)
        assertEquals(0.0, SmartRanking.score(dead, profile), 1e-9)
    }

    // ── picks ────────────────────────────────────────────────────────

    @Test
    fun `picks choose ping stable fast and adaptive best`() {
        val profile = NetworkProfile(latencyMs = 200.0, jitterMs = 25.0, packetLoss = 0.05, downloadMbps = 6.0)
        val results = listOf(
            result("10.0.0.1", latency = 190.0, jitter = 40.0, loss = 0.30, speed = 12.0),
            result("10.0.0.2", latency = 230.0, jitter = 3.0, loss = 0.0, speed = 8.0),
            result("10.0.0.3", latency = 300.0, jitter = 30.0, loss = 0.10, speed = 25.0),
        )
        val picks = SmartRanking.picks(results, profile)

        assertEquals("10.0.0.1", picks.ping?.ip)       // lowest latency
        assertEquals("10.0.0.2", picks.stable?.ip)     // lowest jitter → best stability
        assertEquals("10.0.0.3", picks.fast?.ip)       // highest throughput
        assertNotNull(picks.best)
        assertTrue(picks.best!!.alive)
    }

    @Test
    fun `picks on empty input are all null`() {
        val picks = SmartRanking.picks(emptyList(), null)
        assertNull(picks.best)
        assertNull(picks.ping)
        assertNull(picks.stable)
        assertNull(picks.fast)
    }

    @Test
    fun `smart sort orders by the adaptive score`() {
        val profile = NetworkProfile(latencyMs = 40.0, jitterMs = 5.0, packetLoss = 0.0, downloadMbps = 60.0)
        val a = result("10.0.0.1", latency = 45.0, jitter = 6.0, loss = 0.0, speed = 60.0)
        val b = result("10.0.0.2", latency = 120.0, jitter = 6.0, loss = 0.0, speed = 6.0)
        val sorted = SmartRanking.sort(listOf(b, a), profile)
        assertEquals("10.0.0.1", sorted.first().ip)
    }

    private fun result(
        ip: String,
        latency: Double?,
        jitter: Double?,
        loss: Double,
        speed: Double?,
    ): ScanResult = ScanResult(
        ip = ip,
        protocol = IpProtocol.IPv4,
        port = 443,
        latencyMs = latency,
        jitterMs = jitter,
        packetLoss = loss,
        speedMbps = speed,
        tcpAttempts = 3,
        successfulAttempts = 3,
        tlsSuccess = true,
        mode = ScanMode.CF_EDGE,
    )
}
