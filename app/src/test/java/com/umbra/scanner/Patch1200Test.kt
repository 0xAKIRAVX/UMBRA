package com.umbra.scanner

import com.umbra.scanner.debug.DebugLog
import com.umbra.scanner.debug.DbgEntry
import com.umbra.scanner.debug.DbgLevel
import com.umbra.scanner.debug.DeepEndpointTest
import com.umbra.scanner.debug.DiagCenter
import com.umbra.scanner.net.UdpEvidence
import com.umbra.scanner.net.WarpAccount
import com.umbra.scanner.net.WgProtocol
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * v3.12 regression tests — the debug system (journal, diagnostics verdict
 * tree, deep endpoint microscope). Every pure decision is pinned here so
 * the Diagnostics tab can never silently lie: a verdict class named in a
 * release note must keep mapping to the exact input combination that
 * produced it.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class Patch1200Test {

    // ── DebugLog ──────────────────────────────────────────────────────────

    @Test
    fun `debug journal caps at CAP and drops the oldest`() {
        DebugLog.reset()
        var t = 1_000L
        DebugLog.clock = { t }
        repeat(DebugLog.CAP + 10) { i ->
            DebugLog.info("t", "entry $i")
            t += 1
        }
        val snap = DebugLog.snapshot()
        assertEquals(DebugLog.CAP, snap.size)
        // newest first, oldest of the kept window is entry 10
        assertEquals("entry ${DebugLog.CAP + 9}", snap.first().message)
        assertEquals("entry 10", snap.last().message)
    }

    @Test
    fun `mirror scan line infers levels from engine wording`() {
        DebugLog.reset()
        DebugLog.clock = { 2_000L }
        DebugLog.mirrorScanLine("scan session started · mode ENDPOINT")
        DebugLog.mirrorScanLine("pre-flight witness · 3/16 answered · udp path live")
        DebugLog.mirrorScanLine("endpoint scan aborted — 504 dead probes would only repeat this verdict")
        DebugLog.mirrorScanLine("engine failure — NoClassDefFoundError · recorded to crash log (settings)")
        val levels = DebugLog.snapshot().associate { it.message.substringBefore(" —").substringBefore(" ·") to it.level }
        // positive lines stay INFO (the "udp path live" line is a PASS — the
        // reason "udp path" is NOT a warn keyword)
        assertEquals(DbgLevel.INFO, levels["scan session started"])
        assertEquals(DbgLevel.INFO, levels["pre-flight witness"])
        assertEquals(DbgLevel.WARN, levels["endpoint scan aborted"])
        assertEquals(DbgLevel.ERROR, levels["engine failure"])
    }

    @Test
    fun `dump is chronological with a header`() {
        DebugLog.reset()
        var t = 5_000L
        DebugLog.clock = { t }
        DebugLog.info("a", "first")
        DebugLog.warn("b", "second")
        DebugLog.error("c", "third")
        val dump = DebugLog.dump()
        assertTrue(dump.startsWith("UMBRA debug journal · 3 entries"))
        // oldest first: the WARN/ERROR level letters ride the line
        assertTrue(dump.indexOf("first") < dump.indexOf("second"))
        assertTrue(dump.indexOf("second") < dump.indexOf("third"))
        assertTrue(dump.contains("/b "))
        assertTrue(dump.contains("/c "))
    }

    @Test
    fun `blank messages are ignored and clear works`() {
        DebugLog.reset()
        DebugLog.clock = { 7_000L }
        DebugLog.info("t", "   ")
        DebugLog.info("t", "")
        assertTrue(DebugLog.snapshot().isEmpty())
        DebugLog.info("t", "real")
        DebugLog.clear()
        assertTrue(DebugLog.snapshot().isEmpty())
    }

    @Test
    fun `entries carry tag and level`() {
        DebugLog.reset()
        DebugLog.clock = { 9_000L }
        DebugLog.warn(DebugLog.TAG_SCAN, "line")
        val e: DbgEntry = DebugLog.snapshot().first()
        assertEquals(DbgLevel.WARN, e.level)
        assertEquals("scan", e.tag)
        assertEquals(9_000L, e.epochMs)
    }

    // ── DiagCenter verdict tree ───────────────────────────────────────────

    private fun facts(network: Boolean = true, validated: Boolean = true, vpn: Boolean? = false) =
        DiagCenter.ConnectivityFacts(network, validated, vpn)

    private fun bothNtp() = UdpEvidence.Evidence(cloudflareNtp = true, otherNtp = true)
    private fun noNtp() = UdpEvidence.Evidence(cloudflareNtp = false, otherNtp = false)

    private fun account() = WarpAccount(
        privateKey = ByteArray(32) { it.toByte() },
        publicKey = ByteArray(32) { (it + 1).toByte() },
        reserved = byteArrayOf(1, 2, 3),
        v6 = "2606:4700:d1::2",
        v4 = "172.16.0.2",
        responderPublicKey = ByteArray(32) { (it + 7).toByte() },
    )

    @Test
    fun `no network is the terminal verdict`() {
        val (v, l) = DiagCenter.verdictOf(facts(network = false), null, null, null, null, 0, 0)
        assertTrue(v.startsWith("NO USABLE NETWORK"))
        assertEquals(DbgLevel.ERROR, l)
    }

    @Test
    fun `vpn with dead udp names the tunnel`() {
        val (v, l) = DiagCenter.verdictOf(facts(vpn = true), listOf("1.2.3.4"), true, noNtp(), account(), 0, 6)
        assertTrue(v.startsWith("SYSTEM VPN IS ACTIVE"))
        assertEquals(DbgLevel.ERROR, l)
    }

    @Test
    fun `vpn with working udp does not blame the vpn`() {
        val (v, l) = DiagCenter.verdictOf(facts(vpn = true), listOf("1.2.3.4"), true, bothNtp(), account(), 2, 6)
        assertTrue(v.startsWith("WARP PATH PROVEN"))
        assertEquals(DbgLevel.INFO, l)
    }

    @Test
    fun `empty dns is dns broken`() {
        val (v, l) = DiagCenter.verdictOf(facts(), emptyList(), true, bothNtp(), account(), 1, 6)
        assertTrue(v.startsWith("DNS BROKEN"))
        assertEquals(DbgLevel.ERROR, l)
    }

    @Test
    fun `tcp failure is total cloudflare block`() {
        val (v, l) = DiagCenter.verdictOf(facts(), listOf("1.2.3.4"), false, bothNtp(), account(), 0, 6)
        assertTrue(v.startsWith("CLOUDFLARE UNREACHABLE OVER TCP"))
        assertEquals(DbgLevel.ERROR, l)
    }

    @Test
    fun `dead udp with working tcp is udp egress block`() {
        val (v, l) = DiagCenter.verdictOf(facts(), listOf("1.2.3.4"), true, noNtp(), account(), 0, 6)
        assertTrue(v.startsWith("UDP EGRESS BLOCKED"))
        assertEquals(DbgLevel.ERROR, l)
    }

    @Test
    fun `partial udp plus warp silence is a warn`() {
        val (v, l) = DiagCenter.verdictOf(
            facts(), listOf("1.2.3.4"), true,
            UdpEvidence.Evidence(cloudflareNtp = true, otherNtp = false),
            account(), 0, 6,
        )
        assertTrue(v.startsWith("PARTIAL UDP + WARP SILENT"))
        assertEquals(DbgLevel.WARN, l)
    }

    @Test
    fun `identity blocked is a warn not a warp verdict`() {
        val (v, l) = DiagCenter.verdictOf(facts(), listOf("1.2.3.4"), true, bothNtp(), null, 0, 6)
        assertTrue(v.startsWith("REGISTRATION BLOCKED"))
        assertEquals(DbgLevel.WARN, l)
    }

    @Test
    fun `healthy udp with zero witnesses is warp filtered`() {
        val (v, l) = DiagCenter.verdictOf(facts(), listOf("1.2.3.4"), true, bothNtp(), account(), 0, 6)
        assertTrue(v.startsWith("WARP FILTERED"))
        assertEquals(DbgLevel.ERROR, l)
    }

    @Test
    fun `answered witness is the proven path`() {
        val (v, l) = DiagCenter.verdictOf(facts(), listOf("1.2.3.4"), true, bothNtp(), account(), 3, 6)
        assertTrue(v.startsWith("WARP PATH PROVEN — 3/6"))
        assertEquals(DbgLevel.INFO, l)
    }

    @Test
    fun `all null inputs is incomplete`() {
        val (v, l) = DiagCenter.verdictOf(null, null, null, null, null, 0, 0)
        assertTrue(v.startsWith("INCOMPLETE"))
        assertEquals(DbgLevel.WARN, l)
    }

    @Test
    fun `witness pool carries the seeds plus v6 twins`() {
        val pairs = DiagCenter.buildWitnessPairs()
        // 4 seed endpoints + 2 v6 twins
        assertEquals(6, pairs.size)
        val texts = pairs.map { "${it.candidate.text}:${it.port}" }
        assertTrue(texts.contains("188.114.96.1:2408"))
        assertTrue(texts.contains("162.159.192.42:2408"))
        assertTrue(texts.contains("162.159.192.1:894"))
        assertTrue(texts.contains("162.159.192.1:928"))
        // the twins are IPv6
        val twins = pairs.filter { it.candidate.protocol == com.umbra.scanner.core.IpProtocol.IPv6 }
        assertEquals(2, twins.size)
        assertTrue(twins.all { it.port == 2408 })
    }

    // ── DeepEndpointTest pure layer ───────────────────────────────────────

    @Test
    fun `parse endpoint accepts ip, ipport, v6 bracketed, host, hostport`() {
        assertEquals(Triple("1.2.3.4", "1.2.3.4", 2408), DeepEndpointTest.parseEndpoint("1.2.3.4"))
        assertEquals(Triple("1.2.3.4", "1.2.3.4", 894), DeepEndpointTest.parseEndpoint("1.2.3.4:894"))
        assertEquals(
            Triple("2606:4700:d0::1", "2606:4700:d0::1", 2408),
            DeepEndpointTest.parseEndpoint("[2606:4700:d0::1]:2408"),
        )
        assertEquals(
            Triple("2606:4700:d0::1", "2606:4700:d0::1", 2408),
            DeepEndpointTest.parseEndpoint("2606:4700:d0::1"),
        )
        assertEquals(
            Triple("engage.cloudflareclient.com", null, 2408),
            DeepEndpointTest.parseEndpoint("engage.cloudflareclient.com"),
        )
        assertEquals(
            Triple("engage.cloudflareclient.com", null, 894),
            DeepEndpointTest.parseEndpoint("engage.cloudflareclient.com:894"),
        )
        // whitespace tolerated
        assertEquals(Triple("1.2.3.4", "1.2.3.4", 2408), DeepEndpointTest.parseEndpoint("  1.2.3.4 "))
    }

    @Test
    fun `parse endpoint rejects garbage`() {
        assertNull(DeepEndpointTest.parseEndpoint(""))
        assertNull(DeepEndpointTest.parseEndpoint("1.2.3.4:"))
        assertNull(DeepEndpointTest.parseEndpoint("1.2.3.4:0"))
        assertNull(DeepEndpointTest.parseEndpoint("1.2.3.4:99999"))
        assertNull(DeepEndpointTest.parseEndpoint("1.2.3.4:abc"))
        assertNull(DeepEndpointTest.parseEndpoint("[2606::1"))
        assertNull(DeepEndpointTest.parseEndpoint("[2606::1]:notaport"))
    }

    @Test
    fun `classify reply buckets every outcome class`() {
        val silent = DeepEndpointTest.classifyReply(null, null)
        assertEquals(DeepEndpointTest.DeepOutcome.SILENT, silent)
        assertEquals(
            DeepOutcome_SOCKET_ERROR,
            DeepEndpointTest.classifyReply(null, "receive failed: SocketException"),
        )
        // valid response shape (type 2, 92 bytes)
        val resp = ByteArray(92).also { it[0] = 2 }
        assertEquals(DeepEndpointTest.DeepOutcome.HANDSHAKE_OK, DeepEndpointTest.classifyReply(resp, null))
        // cookie reply (type 3, 64 bytes)
        val cookie = ByteArray(64).also { it[0] = 3 }
        assertEquals(DeepOutcome_COOKIE, DeepEndpointTest.classifyReply(cookie, null))
        // junk: 16-byte quic version negotiation
        assertEquals(
            DeepOutcome_UNPARSEABLE,
            DeepEndpointTest.classifyReply(ByteArray(16), null),
        )
        // wrong type on a response-sized datagram
        val wrongType = ByteArray(92).also { it[0] = 7 }
        assertEquals(DeepOutcome_UNPARSEABLE, DeepEndpointTest.classifyReply(wrongType, null))
    }

    @Test
    fun `hex dump has offsets, 16 per row and a cap note`() {
        val bytes = ByteArray(40) { (it + 1).toByte() }
        val dump = DeepEndpointTest.hexDump(bytes, maxBytes = 20)
        assertTrue(dump.contains("0000"))
        assertTrue(dump.contains("0010"))
        assertTrue(dump.contains("+20 bytes"))
        // full dump of a short reply has no cap note
        val short = DeepEndpointTest.hexDump(ByteArray(16))
        assertFalse(short.contains("+"))
    }

    @Test
    fun `outcome details speak plainly`() {
        val silent = DeepEndpointTest.outcomeDetail(DeepOutcome_SILENT, null, 0x1a, null, 2, 3000)
        assertTrue(silent.contains("2408/894/928"))
        val ok = DeepEndpointTest.outcomeDetail(DeepOutcome_OK, null, 0x1a, null, 1, 3000)
        assertTrue(ok.contains("ALIVE"))
        val sockErr = DeepEndpointTest.outcomeDetail(DeepOutcome_SOCKET_ERROR, "send failed: PortUnreachableException", 0, null, 1, 3000)
        assertTrue(sockErr.contains("PortUnreachableException"))
    }

    // ── DeepEndpointTest flow (seams injected) ────────────────────────────

    private val savedDns = DeepEndpointTest.dnsResolver
    private val savedReg = DeepEndpointTest.registrationProvider
    private val savedUdp = DeepEndpointTest.udpExchange

    @Before
    fun pinSeams() {
        // stable identity + a resolver that never resolves (unused in the
        // literal-IP flows) + silent exchange (overridden per test)
        DeepEndpointTest.registrationProvider = { account() }
        DeepEndpointTest.dnsResolver = { emptyList() }
        DeepEndpointTest.udpExchange = { _, _, _, _, _ ->
            DeepEndpointTest.UdpExchange(null, null, 40000, null, 0)
        }
    }

    @After
    fun restoreSeams() {
        DeepEndpointTest.dnsResolver = savedDns
        DeepEndpointTest.registrationProvider = savedReg
        DeepEndpointTest.udpExchange = savedUdp
        DiagCenter.reset()
        // the journal is a singleton — leave it armed and empty for other tests
        DebugLog.reset()
    }

    @Test
    fun `deep test full flow reports handshake with annotated packet`() = runBlocking {
        val resp = ByteArray(WgProtocol.RESPONSE_SIZE).also { it[0] = WgProtocol.MSG_RESPONSE.toByte() }
        DeepEndpointTest.udpExchange = { _, _, _, _, _ ->
            DeepEndpointTest.UdpExchange(resp, null, 40000, 137, 0)
        }
        val r = DeepEndpointTest.run("162.159.192.1:2408", timeoutMs = 300, attempts = 1)
        assertEquals(DeepOutcome_OK, r.outcome)
        assertEquals("162.159.192.1", r.ip)
        assertEquals(2408, r.port)
        assertEquals(137L, r.rttMs)
        // the initiation dump is annotated and hex-dumped
        assertNotNull(r.sentHex)
        assertTrue(r.sentHex!!.contains("mac1"))
        assertTrue(r.sentHex!!.contains("mac2"))
        // the raw section covers all 148 bytes: rows 0000..0090 (10th row holds the tail)
        assertTrue(r.sentHex!!.lines().any { it.startsWith("0090") })
        // stages tell the story
        assertTrue(r.stages.first().name.startsWith("parse"))
        assertTrue(r.stages.any { it.name.startsWith("build initiation") })
        assertTrue(r.stages.any { it.name.startsWith("exchange") })
        // a fabricated type-2 fails AEAD verification honestly
        assertFalse(r.aeadVerified)
        // the shareable report carries the target
        val text = DeepEndpointTest.formatReport(r)
        assertTrue(text.contains("UMBRA deep endpoint test · 162.159.192.1:2408"))
        assertTrue(text.contains("outcome HANDSHAKE_OK"))
    }

    @Test
    fun `deep test silent endpoint runs every attempt`() = runBlocking {
        var exchanges = 0
        DeepEndpointTest.udpExchange = { _, _, _, _, _ ->
            exchanges++
            DeepEndpointTest.UdpExchange(null, null, 40000, null, 0)
        }
        val r = DeepEndpointTest.run("188.114.96.1:2408", timeoutMs = 200, attempts = 3)
        assertEquals(DeepOutcome_SILENT, r.outcome)
        assertEquals(3, exchanges)
        assertEquals(3, r.attemptsRun)
        assertNull(r.receivedHex)
        assertNull(r.rttMs)
    }

    @Test
    fun `deep test socket error surfaces the error class`() = runBlocking {
        DeepEndpointTest.udpExchange = { _, _, _, _, _ ->
            DeepEndpointTest.UdpExchange(null, "send failed: PortUnreachableException — icmp", -1, null, 0)
        }
        val r = DeepEndpointTest.run("162.159.192.1:2408", timeoutMs = 200, attempts = 2)
        assertEquals(DeepOutcome_SOCKET_ERROR, r.outcome)
        assertTrue(r.outcomeDetail.contains("PortUnreachableException"))
        // a socket error stops the retry loop — no point repeating it
        assertEquals(1, r.attemptsRun)
    }

    @Test
    fun `deep test identity failure is honest`() = runBlocking {
        DeepEndpointTest.registrationProvider = { throw java.io.IOException("api unreachable") }
        val r = DeepEndpointTest.run("162.159.192.1:2408", timeoutMs = 200)
        assertEquals(DeepOutcome_IDENTITY, r.outcome)
        assertTrue(r.stages.any { it.name.startsWith("identity") })
    }

    @Test
    fun `deep test hostname resolution failure`() = runBlocking {
        val r = DeepEndpointTest.run("engage.cloudflareclient.com:2408", timeoutMs = 200)
        assertEquals(DeepOutcome_DNS, r.outcome)
        assertEquals("engage.cloudflareclient.com", r.host)
        assertNull(r.ip)
    }

    @Test
    fun `deep test unparseable input`() = runBlocking {
        val r = DeepEndpointTest.run("1.2.3.4:99999", timeoutMs = 200)
        assertEquals(DeepOutcome_PARSE, r.outcome)
    }

    @Test
    fun `deep test dns path resolves and probes the resolved ip`() = runBlocking {
        var probed: ByteArray? = null
        DeepEndpointTest.dnsResolver = { listOf("162.159.192.1") }
        DeepEndpointTest.udpExchange = { ip, _, _, _, _ ->
            probed = ip
            DeepEndpointTest.UdpExchange(null, null, 40000, null, 0)
        }
        val r = DeepEndpointTest.run("engage.cloudflareclient.com:2408", timeoutMs = 200)
        assertEquals(DeepOutcome_SILENT, r.outcome)
        assertEquals("162.159.192.1", r.ip)
        assertNotNull(probed)
        assertEquals(4, probed!!.size)
    }

    // outcome aliases to keep the assertions above readable
    private val DeepOutcome_OK = DeepEndpointTest.DeepOutcome.HANDSHAKE_OK
    private val DeepOutcome_SILENT = DeepEndpointTest.DeepOutcome.SILENT
    private val DeepOutcome_COOKIE = DeepEndpointTest.DeepOutcome.COOKIE_REPLY
    private val DeepOutcome_UNPARSEABLE = DeepEndpointTest.DeepOutcome.REPLY_UNPARSEABLE
    private val DeepOutcome_SOCKET_ERROR = DeepEndpointTest.DeepOutcome.SOCKET_ERROR
    private val DeepOutcome_IDENTITY = DeepEndpointTest.DeepOutcome.IDENTITY_FAILED
    private val DeepOutcome_DNS = DeepEndpointTest.DeepOutcome.DNS_FAILED
    private val DeepOutcome_PARSE = DeepEndpointTest.DeepOutcome.PARSE_ERROR
}
