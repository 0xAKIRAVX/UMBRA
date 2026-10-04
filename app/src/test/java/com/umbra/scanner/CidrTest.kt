package com.umbra.scanner

import com.umbra.scanner.core.CidrBlock
import com.umbra.scanner.core.IpProtocol
import com.umbra.scanner.core.IpText
import com.umbra.scanner.core.NetFamily
import com.umbra.scanner.core.Presets
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger

class CidrTest {

    @Test
    fun `parses ipv4 cidr`() {
        val b = CidrBlock.parse("104.16.0.0/13")
        assertNotNull(b)
        assertEquals(IpProtocol.IPv4, b!!.family)
        assertEquals(13, b.prefix)
        assertEquals(BigInteger.valueOf(2).pow(19), b.size)
    }

    @Test
    fun `parses ipv6 cidr`() {
        val b = CidrBlock.parse("2606:4700::/32")
        assertNotNull(b)
        assertEquals(IpProtocol.IPv6, b!!.family)
        assertEquals(32, b.prefix)
        assertEquals(BigInteger.valueOf(2).pow(96), b.size)
    }

    @Test
    fun `parses bare address as full prefix`() {
        val b = CidrBlock.parse("1.2.3.4")
        assertNotNull(b)
        assertEquals(32, b!!.prefix)
        assertEquals(BigInteger.ONE, b.size)
    }

    @Test
    fun `rejects garbage`() {
        assertNull(CidrBlock.parse("nonsense/33"))
        assertNull(CidrBlock.parse("999.1.1.1/8"))
        assertNull(CidrBlock.parse("1.2.3.4/33"))
        assertNull(CidrBlock.parse("2606:4700::/129"))
        assertNull(CidrBlock.parse(""))
        assertNull(CidrBlock.parse("/"))
    }

    @Test
    fun `samples stay inside block`() {
        val b = CidrBlock.parse("104.16.0.0/13")!!
        val out = ArrayList<ByteArray>()
        b.sampleCandidates(500, kotlin.random.Random(42), out)
        assertEquals(500, out.size)
        val base = BigInteger(1, byteArrayOf(104.toByte(), 16.toByte(), 0, 0))
        val high = base.add(BigInteger.valueOf(2).pow(19))
        for (bytes in out) {
            val v = BigInteger(1, bytes)
            assertTrue("sample outside block: $v", v >= base && v < high)
        }
    }

    @Test
    fun `small ipv4 block enumerates and skips edges`() {
        val b = CidrBlock.parse("162.159.192.0/24")!!
        val out = ArrayList<ByteArray>()
        b.sampleCandidates(1000, kotlin.random.Random(7), out)
        // 254 usable host addresses (.1-.254)
        assertEquals(254, out.size)
        for (bytes in out) {
            val last = bytes[3].toInt() and 0xFF
            assertTrue(last in 1..254)
        }
    }

    @Test
    fun `ipv6 formatting compresses zero runs`() {
        assertEquals("2606:4700::1", IpText.formatIpv6(hexToBytes("26064700000000000000000000000001")))
        assertEquals("2606:4700:d000::", IpText.formatIpv6(hexToBytes("26064700d00000000000000000000000")))
        assertEquals("::1", IpText.formatIpv6(hexToBytes("00000000000000000000000000000001")))
    }

    @Test
    fun `url form brackets ipv6 only`() {
        assertEquals("[2606:4700::1]", IpText.forUrl("2606:4700::1"))
        assertEquals("[2606:4700::1]", IpText.forUrl("[2606:4700::1]"))
        assertEquals("104.16.1.1", IpText.forUrl("104.16.1.1"))
    }

    @Test
    fun `preset cidrs all parse`() {
        val all = Presets.CF_EDGE_V4 + Presets.CF_EDGE_V6 + Presets.WARP_V4 + Presets.WARP_V6
        for (c in all) {
            assertNotNull("preset must parse: $c", CidrBlock.parse(c))
        }
    }

    @Test
    fun `warp v6 is inside cloudflare space`() {
        val b = CidrBlock.parse("2606:4700:d0::/48")!!
        assertEquals(BigInteger.valueOf(2).pow(80), b.size)
    }

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.replace(" ", "")
        val out = ByteArray(clean.length / 2)
        for (i in out.indices) {
            out[i] = ((Character.digit(clean[i * 2], 16) shl 4) + Character.digit(clean[i * 2 + 1], 16)).toByte()
        }
        return out
    }
}
