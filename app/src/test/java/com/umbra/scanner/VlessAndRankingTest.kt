package com.umbra.scanner

import com.umbra.scanner.core.Ranking
import com.umbra.scanner.core.ScanResult
import com.umbra.scanner.core.SortKey
import com.umbra.scanner.vless.VlessGenerator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VlessTest {

    @Test
    fun `ipv6 gets brackets`() {
        val link = VlessGenerator.buildLink(
            VlessGenerator.Config(
                uuid = "6ba14b1e-8fd8-4c1f-9a2b-2b7c12345678",
                host = "2606:4700::1",
                port = 443,
                sni = "speed.cloudflare.com",
                wsPath = "/cf",
                remark = "test",
            )
        )
        assertTrue(link.startsWith("vless://6ba14b1e-8fd8-4c1f-9a2b-2b7c12345678@[2606:4700::1]:443?"))
        assertTrue(link.contains("encryption=none"))
        assertTrue(link.contains("security=tls"))
        assertTrue(link.contains("sni=speed.cloudflare.com"))
        assertTrue(link.contains("type=ws"))
        assertTrue(link.contains("path=/cf"))
        assertTrue(link.endsWith("#test"))
    }

    @Test
    fun `ipv4 stays plain`() {
        val link = VlessGenerator.buildLink(
            VlessGenerator.Config(
                uuid = "6ba14b1e-8fd8-4c1f-9a2b-2b7c12345678",
                host = "104.16.1.1",
                port = 8443,
            )
        )
        assertTrue(link.contains("@104.16.1.1:8443"))
    }

    @Test
    fun `already bracketed ipv6 is not double wrapped`() {
        val link = VlessGenerator.buildLink(
            VlessGenerator.Config(
                uuid = "6ba14b1e-8fd8-4c1f-9a2b-2b7c12345678",
                host = "[2606:4700::1]",
            )
        )
        assertTrue(link.contains("@[2606:4700::1]:443"))
        assertFalse(link.contains("[["))
    }

    @Test
    fun `uuid validation`() {
        assertTrue(VlessGenerator.isValidUuid("6ba14b1e-8fd8-4c1f-9a2b-2b7c12345678"))
        assertFalse(VlessGenerator.isValidUuid("not-a-uuid"))
        val random = VlessGenerator.randomUuid()
        assertTrue(VlessGenerator.isValidUuid(random))
    }
}

class RankingTest {

    private fun result(
        ip: String,
        lat: Double?,
        loss: Double = 0.0,
        speed: Double? = null,
        ok: Int = 3,
        attempts: Int = 3,
        tls: Boolean = false,
        jitter: Double? = null,
    ) = ScanResult(
        ip = ip,
        protocol = com.umbra.scanner.core.IpProtocol.IPv4,
        port = 443,
        latencyMs = lat,
        jitterMs = jitter,
        packetLoss = loss,
        speedMbps = speed,
        tcpAttempts = attempts,
        successfulAttempts = ok,
        tlsSuccess = tls,
    )

    @Test
    fun `faster latency scores higher`() {
        val fast = Ranking.scoreOf(result("1.1.1.1", 30.0))
        val slow = Ranking.scoreOf(result("2.2.2.2", 300.0))
        assertTrue(fast > slow)
    }

    @Test
    fun `dead endpoints score zero`() {
        assertEquals(0.0, Ranking.scoreOf(result("3.3.3.3", null, ok = 0)), 0.001)
    }

    @Test
    fun `loss is penalized`() {
        val clean = Ranking.scoreOf(result("1.1.1.1", 50.0, loss = 0.0))
        val flaky = Ranking.scoreOf(result("2.2.2.2", 50.0, loss = 0.34, ok = 2))
        assertTrue(clean > flaky)
    }

    @Test
    fun `speed and tls add score`() {
        val base = Ranking.scoreOf(result("1.1.1.1", 50.0))
        val fast = Ranking.scoreOf(result("2.2.2.2", 50.0, speed = 80.0))
        val fastTls = Ranking.scoreOf(result("4.4.4.4", 50.0, speed = 80.0, tls = true))
        assertTrue(fast > base)
        assertTrue(fastTls > fast)
    }

    @Test
    fun `score sort orders descending`() {
        val list = listOf(
            result("1.1.1.1", 200.0),
            result("2.2.2.2", 20.0, speed = 40.0, tls = true),
            result("3.3.3.3", 90.0),
        )
        val sorted = Ranking.sort(list, SortKey.SCORE)
        assertEquals("2.2.2.2", sorted.first().ip)
    }
}
