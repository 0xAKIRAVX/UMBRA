package com.umbra.scanner

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.umbra.scanner.core.NetFamily
import com.umbra.scanner.core.Presets
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.core.ScanPhase
import com.umbra.scanner.engine.ScanEngine
import com.umbra.scanner.engine.ScanSink
import com.umbra.scanner.engine.VpnSensor
import com.umbra.scanner.engine.WarpGate
import com.umbra.scanner.net.UdpEvidence
import com.umbra.scanner.net.WarpAccount
import com.umbra.scanner.net.WarpRegistration
import com.umbra.scanner.settings.UmbraSettings
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * v3.6.2 — the "این مشکل رو کامل رفع کن" round. User evidence (screenshot
 * 2026-10-09 23:58 IRST): v3.6.1 gate verdict "WARP UNREACHABLE — fresh
 * identity, 35 endpoints × every canonical port, zero replies" while the
 * registration API worked. The scanner stack itself was re-proven live
 * (handshake + in-tunnel ping OK from a clean network the same hour), so the
 * remaining failure classes are ENVIRONMENTAL — and the app must detect and
 * NAME them instead of looking broken:
 *
 *  1. ACTIVE VPN: every UDP probe rides the VPN tunnel; TCP-only proxy
 *     tunnels drop UDP silently — the verdict is about the TUNNEL. → the
 *     gate now warns up front and appends the VPN explanation (VpnSensor).
 *  2. v4-ONLY FILTERING: ISPs (Iranian mobile carriers) filter the v4 WARP
 *     ranges while v6 passes. → new v6 rescue rounds produce
 *     Outcome.AdaptFamily and the scan regenerates on v6.
 *  3. VERDICT READABILITY: the old 3-line truncation cut the full evidence
 *     off mid-sentence (the screenshot literally ends with "…CANONICAL PO").
 *     → Done panel now shows up to 10 lines.
 *  4. "SCAN ANYWAY": a hard gate abort leaves no user path on networks that
 *     are (or look) blocked. → persisted pre-flight gate switch.
 *  5. NTP WITNESS: negative verdicts carry independent UDP-egress evidence
 *     separating "no udp at all" / "cloudflare filtered" / "warp-specific".
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class Patch62Test {

    private val realProber = WarpGate.seedProber
    private val realSampler = WarpGate.poolSampler
    private val realSweeper = WarpGate.portSweeper
    private val realRegistrar = WarpGate.freshRegistrar
    private val realPoster = WarpRegistration.apiPoster
    private val realEvidence = WarpGate.evidenceGatherer
    private val realV6Seeds = WarpGate.v6Seeds
    private val realV6Pool = WarpGate.v6PoolSampler
    private val realGateEnabled = WarpGate.gateEnabled
    private val realVpnProbe = VpnSensor.probe
    private val realNtpProber = UdpEvidence.ntpProber

    private val v6SeedIp = com.umbra.scanner.core.IpGenerator.v6Embedded(
        Presets.WARP_V6_PREFIX_D0, byteArrayOf(162.toByte(), 159.toByte(), 192.toByte(), 1),
    )!!

    @Before
    fun resetState() {
        // hermetic: no real network from this suite, no leaked seams
        WarpGate.evidenceGatherer = { UdpEvidence.Evidence(false, false) }
        WarpGate.v6PoolSampler = { emptyList() }
        WarpGate.gateEnabled = { true }
        VpnSensor.probe = { null }
        WarpGate.poolSampler = { emptyList() }
        WarpGate.portSweeper = { _, _ -> emptyMap() }
        val prefsField = WarpRegistration.javaClass.getDeclaredField("prefs")
        prefsField.isAccessible = true
        prefsField.set(WarpRegistration, null)
        WarpRegistration.attach(ApplicationProvider.getApplicationContext<Context>())
        WarpRegistration.clearCache()
    }

    @After
    fun restoreSeams() {
        WarpGate.seedProber = realProber
        WarpGate.poolSampler = realSampler
        WarpGate.portSweeper = realSweeper
        WarpGate.freshRegistrar = realRegistrar
        WarpRegistration.apiPoster = realPoster
        WarpGate.evidenceGatherer = realEvidence
        WarpGate.v6Seeds = realV6Seeds
        WarpGate.v6PoolSampler = realV6Pool
        WarpGate.gateEnabled = realGateEnabled
        VpnSensor.probe = realVpnProbe
        UdpEvidence.ntpProber = realNtpProber
        WarpRegistration.clearCache()
    }

    private fun fakeAccount(tag: String = "stored"): WarpAccount = WarpAccount(
        privateKey = ByteArray(32) { it.toByte() },
        publicKey = ByteArray(32) { (it + 1).toByte() },
        reserved = byteArrayOf(1, 2, 3),
        v6 = "2606:4700:d1:1234:5678:9abc:def0:1111",
        v4 = "172.16.0.2",
        responderPublicKey = ByteArray(32) { (it + 2).toByte() },
    )

    // ── 1. VPN sensor ───────────────────────────────────────────────────

    @Test
    fun `vpn sensor hint appears only when a vpn is confirmed active`() {
        VpnSensor.probe = { true }
        assertEquals(true, VpnSensor.active())
        val hint = VpnSensor.hint()
        assertNotNull(hint)
        assertTrue(hint!!.contains("VPN is ACTIVE"))
        assertTrue(hint.contains("disconnect"))
        // unknown (JVM default) and false → no hint, no false accusations
        VpnSensor.probe = { null }
        assertEquals(null, VpnSensor.active())
        assertEquals(null, VpnSensor.hint())
        VpnSensor.probe = { false }
        assertEquals(null, VpnSensor.hint())
    }

    @Test
    fun `gate logs a vpn warning up front and pins it to the blocked verdict`() = runBlocking {
        VpnSensor.probe = { true }
        WarpGate.seedProber = { _, _, _, _ -> null }
        WarpGate.v6Seeds = { emptyList() }
        WarpGate.freshRegistrar = { fakeAccount("fresh") }
        val logs = mutableListOf<String>()
        val out = WarpGate.check(fakeAccount(), 2408, 3000) { logs.add(it) }
        assertTrue("expected Blocked, got $out", out is WarpGate.Outcome.Blocked)
        assertTrue(logs.any { it.contains("WARNING: a system VPN is active") })
        assertTrue((out as WarpGate.Outcome.Blocked).note.contains("VPN is ACTIVE"))
        assertTrue(out.note.contains("disconnect the vpn"))
    }

    @Test
    fun `blocked verdict without vpn stays clean of vpn text`() = runBlocking {
        VpnSensor.probe = { false }
        WarpGate.seedProber = { _, _, _, _ -> null }
        WarpGate.v6Seeds = { emptyList() }
        WarpGate.freshRegistrar = { fakeAccount("fresh") }
        val out = WarpGate.check(fakeAccount(), 2408, 3000) {}
        assertTrue(out is WarpGate.Outcome.Blocked)
        assertFalse((out as WarpGate.Outcome.Blocked).note.contains("VPN"))
    }

    // ── 2. IPv6 rescue ──────────────────────────────────────────────────

    @Test
    fun `v6 seed answer adapts the gate to ipv6 after v4 silence`() = runBlocking {
        WarpGate.seedProber = { _, ip, _, _ ->
            // v4 probes silent everywhere; the v6 twin of 162.159.192.1 answers
            if (ip.size == 16) WarpGate.SeedStats(handshakes = 1, cookieReplies = 0, pingMs = 41.0)
            else null
        }
        WarpGate.v6Seeds = { listOf(v6SeedIp) }
        WarpGate.freshRegistrar = { null }
        val stored = fakeAccount()
        val out = WarpGate.check(stored, 2408, 3000) {}
        assertTrue("expected AdaptFamily, got $out", out is WarpGate.Outcome.AdaptFamily)
        val adapt = out as WarpGate.Outcome.AdaptFamily
        assertEquals(NetFamily.V6, adapt.family)
        assertTrue(adapt.account === stored)
        assertTrue(adapt.note.contains("IPv6"))
    }

    @Test
    fun `v6 mini storm rescues when v6 seeds are stale`() = runBlocking {
        val randomV6 = com.umbra.scanner.core.IpGenerator.v6Embedded(
            Presets.WARP_V6_PREFIX_D1, byteArrayOf(188.toByte(), 114.toByte(), 96.toByte(), 42.toByte()),
        )!!
        WarpGate.seedProber = { _, ip, _, _ ->
            if (ip contentEquals randomV6) WarpGate.SeedStats(handshakes = 1, cookieReplies = 0, pingMs = 63.0)
            else null
        }
        WarpGate.v6Seeds = { listOf(v6SeedIp) } // stale, silent
        WarpGate.v6PoolSampler = { listOf(randomV6) }
        WarpGate.freshRegistrar = { null }
        val out = WarpGate.check(fakeAccount(), 2408, 3000) {}
        assertTrue("expected AdaptFamily, got $out", out is WarpGate.Outcome.AdaptFamily)
        assertTrue((out as WarpGate.Outcome.AdaptFamily).note.contains("random ipv6 pool endpoint"))
    }

    @Test
    fun `v6 rescue also runs with a fresh identity before the port sweep`() = runBlocking {
        val fresh = fakeAccount("fresh")
        WarpGate.seedProber = { account, ip, _, _ ->
            if (account === fresh && ip.size == 16)
                WarpGate.SeedStats(handshakes = 1, cookieReplies = 0, pingMs = 38.0)
            else null
        }
        WarpGate.v6Seeds = { listOf(v6SeedIp) }
        WarpGate.freshRegistrar = { fresh }
        val out = WarpGate.check(fakeAccount(), 2408, 3000) {}
        assertTrue("expected AdaptFamily(fresh), got $out", out is WarpGate.Outcome.AdaptFamily)
        assertTrue((out as WarpGate.Outcome.AdaptFamily).account === fresh)
    }

    @Test
    fun `engine regenerates v6 candidates when the gate adapts the family`() = runBlocking {
        val acc = fakeAccount()
        WarpGate.seedProber = { _, ip, _, _ ->
            if (ip.size == 16) WarpGate.SeedStats(handshakes = 1, cookieReplies = 0, pingMs = 40.0)
            else null
        }
        WarpGate.v6Seeds = { listOf(v6SeedIp) }
        WarpGate.freshRegistrar = { null }
        val logs = mutableListOf<String>()
        var lastGenerated = -1
        val sink = object : ScanSink {
            override fun onPhase(phase: ScanPhase) {}
            override fun onGenerated(count: Int) { if (count > 0) lastGenerated = count }
            override fun onResult(result: com.umbra.scanner.core.ScanResult) {}
            override fun onActive(delta: Int) {}
            override fun onLog(line: String) { logs.add(line) }
            override fun snapshot(): List<com.umbra.scanner.core.ScanResult> = emptyList()
        }
        val engine = ScanEngine()
        engine.registrationProvider = { acc }
        // family = V4 deliberately: the adaptation must SWITCH the pool to v6
        // even though the user configured an all-v4 scan.
        engine.run(
            ScanParams(mode = ScanMode.WARP, family = NetFamily.V4, samplesPerPrefix = 1,
                port = 2408, speedTest = false, tlsVerify = false),
            sink,
        )
        assertTrue(logs.any { it.contains("scan continues on ipv6") })
        // generateWarp(V6, 1) = 16 v4 samples × 2 prefixes = 32 candidates × 1 port;
        // the storm probes them (instant send failures on the v6-less JVM —
        // exactly the silence the engine must tolerate) and finishes.
        assertEquals(32, lastGenerated)
        assertTrue(logs.any { it.contains("ipv6 candidates") })
        assertTrue(logs.any { it.contains("wg probe storm done") })
    }

    // ── 3. NTP evidence ─────────────────────────────────────────────────

    @Test
    fun `udp evidence describe separates the three failure worlds`() {
        assertTrue(UdpEvidence.describe(UdpEvidence.Evidence(true, true)).contains("REPLIED"))
        assertTrue(UdpEvidence.describe(UdpEvidence.Evidence(true, true)).contains("SELECTIVELY"))
        assertTrue(UdpEvidence.describe(UdpEvidence.Evidence(false, true)).contains("cloudflare"))
        assertTrue(UdpEvidence.describe(UdpEvidence.Evidence(false, true)).contains("EDGE"))
        assertTrue(UdpEvidence.describe(UdpEvidence.Evidence(false, false)).contains("NO udp egress"))
        assertTrue(UdpEvidence.describe(UdpEvidence.Evidence(false, false)).contains("EDGE"))
    }

    @Test
    fun `blocked verdict carries the ntp witness line`() = runBlocking {
        WarpGate.seedProber = { _, _, _, _ -> null }
        WarpGate.v6Seeds = { emptyList() }
        WarpGate.freshRegistrar = { fakeAccount("fresh") }
        WarpGate.evidenceGatherer = { UdpEvidence.Evidence(cloudflareNtp = true, otherNtp = true) }
        val out = WarpGate.check(fakeAccount(), 2408, 3000) {}
        assertTrue(out is WarpGate.Outcome.Blocked)
        val note = (out as WarpGate.Outcome.Blocked).note
        assertTrue(note.contains("every canonical port"))   // old core verdict intact
        assertTrue(note.contains("scan anyway"))            // new third remedy
        assertTrue(note.contains("time.cloudflare.com"))    // NTP witness present
    }

    @Test
    fun `unverifiable verdict carries the ntp witness line too`() = runBlocking {
        WarpGate.seedProber = { _, _, _, _ -> null }
        WarpGate.v6Seeds = { emptyList() }
        WarpGate.freshRegistrar = { null }
        WarpGate.evidenceGatherer = { UdpEvidence.Evidence(cloudflareNtp = false, otherNtp = true) }
        val out = WarpGate.check(fakeAccount(), 2408, 3000) {}
        assertTrue(out is WarpGate.Outcome.Unverifiable)
        assertTrue((out as WarpGate.Outcome.Unverifiable).note.contains("external ntp replied"))
    }

    @Test
    fun `udp evidence gather maps the ntp prober to both witnesses`() = runBlocking {
        UdpEvidence.ntpProber = { ip, _ ->
            ip contentEquals UdpEvidence.CF_NTP // cloudflare replies, google does not
        }
        val e = UdpEvidence.gather(300)
        assertTrue(e.cloudflareNtp)
        assertFalse(e.otherNtp)
        UdpEvidence.ntpProber = { _, _ -> throw java.io.IOException("no route") }
        val e2 = UdpEvidence.gather(300)
        assertFalse(e2.cloudflareNtp)
        assertFalse(e2.otherNtp)
    }

    // ── 4. gate bypass ("scan anyway") ──────────────────────────────────

    @Test
    fun `engine skips the gate entirely when gateEnabled is false`() = runBlocking {
        WarpGate.gateEnabled = { false }
        // any consultation of the gate must explode — proof it never ran
        WarpGate.seedProber = { _, _, _, _ -> throw AssertionError("gate must not run") }
        WarpGate.v6Seeds = { throw AssertionError("gate must not run") }
        val logs = mutableListOf<String>()
        val sink = object : ScanSink {
            override fun onPhase(phase: ScanPhase) {}
            override fun onGenerated(count: Int) {}
            override fun onResult(result: com.umbra.scanner.core.ScanResult) {}
            override fun onActive(delta: Int) {}
            override fun onLog(line: String) { logs.add(line) }
            override fun snapshot(): List<com.umbra.scanner.core.ScanResult> = emptyList()
        }
        val engine = ScanEngine()
        engine.registrationProvider = { fakeAccount("offline") }
        engine.run(
            ScanParams(mode = ScanMode.WARP, family = NetFamily.V4, samplesPerPrefix = 1,
                port = 2408, speedTest = false, tlsVerify = false, warpAttempts = 1),
            sink,
        )
        assertTrue(logs.any { it.contains("gate disabled") })
        // the scan must CONTINUE past the disabled gate — the full storm ran
        assertTrue(logs.any { it.contains("wg probe storm done") })
        // and no gate round ever executed (its preflight lines are absent)
        assertFalse(logs.any { it.contains("preflight · seed handshake") })
    }

    @Test
    fun `preflight gate setting persists and defaults to on`() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val s = UmbraSettings(ctx)
        assertTrue(s.preflightGate.value)
        s.setPreflightGate(false)
        assertFalse(s.preflightGate.value)
        // a second instance over the same prefs must see the persisted value
        val s2 = UmbraSettings(ctx)
        assertFalse(s2.preflightGate.value)
        s2.setPreflightGate(true)
    }

    // ── 5. v6 seeds built from the v4 list ──────────────────────────────

    @Test
    fun `warp v6 seeds are the embedded twins of the v4 seeds`() {
        assertEquals(3, Presets.WARP_SEED_V6.size)
        val texts = Presets.WARP_SEED_V6.map { com.umbra.scanner.core.IpText.format(it) }
        assertTrue(texts.contains("2606:4700:d0::bc72:6001")) // 188.114.96.1
        assertTrue(texts.contains("2606:4700:d0::a29f:c02a")) // 162.159.192.42
        assertTrue(texts.contains("2606:4700:d0::a29f:c001")) // 162.159.192.1
    }
}
