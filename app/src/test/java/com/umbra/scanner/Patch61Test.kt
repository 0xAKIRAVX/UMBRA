package com.umbra.scanner

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.core.ScanPhase
import com.umbra.scanner.core.ScanResult
import com.umbra.scanner.engine.ScanEngine
import com.umbra.scanner.engine.ScanSink
import com.umbra.scanner.engine.WarpGate
import com.umbra.scanner.net.WarpAccount
import com.umbra.scanner.net.WarpRegistration
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * v3.6.1 — the "WARP scanners don't work at all" round. Every fix below is
 * driven by LIVE-VERIFIED failure classes (2026-10-10):
 *
 *  1. SEEDS GO STALE / per-PoP: 162.159.192.1 stopped answering :2408 while
 *     random pool IPs (162.159.192.42, 188.114.96.x, 8.6.112.1) still do —
 *     the gate now has a mini-storm over random pool endpoints and never
 *     concludes "blocked" from seed silence alone.
 *  2. DEAD IDENTITIES ARE SILENT: WARP responders drop initiations from
 *     unknown keys without any reply (verified live with a ghost key) — the
 *     fresh-identity round now also runs against random pool endpoints, and
 *     the Unverifiable outcome + engine zero-result line say plainly that an
 *     expired identity is one of the possibilities.
 *  3. REGISTRATION HARDENING: api.cloudflareclient.com domain failures
 *     (DNS poisoning / filtering) now fall back to pinned SNI-routed
 *     Cloudflare IPs (verified live: 104.16.192.82, 104.16.24.84,
 *     162.159.192.1, 188.114.96.1 all serve the API on :443 via SNI).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class Patch61Test {

    private val realProber = WarpGate.seedProber
    private val realSampler = WarpGate.poolSampler
    private val realSweeper = WarpGate.portSweeper
    private val realRegistrar = WarpGate.freshRegistrar
    private val realPoster = WarpRegistration.apiPoster

    @Before
    fun resetIdentityState() {
        // each test owns the whole registration state (cache + disk + mark).
        // Robolectric builds a NEW Application per test method while the
        // WarpRegistration prefs singleton survives — re-attach it to the
        // CURRENT method's storage or persist() writes into a stale app.
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

    // ── 1. mini-storm: stale seeds can no longer fake a dead network ────

    @Test
    fun `gate stays ok via a random pool endpoint when every seed is stale`() = runBlocking {
        val stored = fakeAccount()
        val poolIp = byteArrayOf(8.toByte(), 6.toByte(), 112.toByte(), 9.toByte())
        WarpGate.poolSampler = { listOf(poolIp) }
        WarpGate.seedProber = { _, ip, _, _ ->
            // seeds silent; the RANDOM pool endpoint answers
            if (ip contentEquals poolIp) WarpGate.SeedStats(handshakes = 1, cookieReplies = 0, pingMs = 55.0)
            else null
        }
        WarpGate.freshRegistrar = { null } // must NOT be needed
        val out = WarpGate.check(stored, 2408, 3000) {}
        assertTrue("expected Ok, got $out", out is WarpGate.Outcome.Ok)
        assertTrue((out as WarpGate.Outcome.Ok).account === stored)
        assertTrue("note must credit the random pool endpoint", out.note.contains("random pool endpoint"))
    }

    @Test
    fun `gate swaps a dead identity when a fresh key answers a random endpoint`() = runBlocking {
        val stored = fakeAccount()
        val fresh = fakeAccount("fresh")
        val poolIp = byteArrayOf(162.toByte(), 159.toByte(), 192.toByte(), 42.toByte())
        WarpGate.poolSampler = { listOf(poolIp) }
        // the stored identity is dead server-side: NOTHING answers for it
        // (live-verified: unknown keys are dropped silently). The fresh key
        // answers on a random pool endpoint even though seeds stay silent.
        WarpGate.seedProber = { account, ip, _, _ ->
            if (account === fresh && ip contentEquals poolIp)
                WarpGate.SeedStats(handshakes = 1, cookieReplies = 0, pingMs = 71.0)
            else null
        }
        WarpGate.freshRegistrar = { fresh }
        val out = WarpGate.check(stored, 2408, 3000) {}
        assertTrue("expected Ok(fresh), got $out", out is WarpGate.Outcome.Ok)
        assertTrue((out as WarpGate.Outcome.Ok).account === fresh)
        assertTrue(out.note.contains("stale"))
    }

    @Test
    fun `blocked verdict cites the full evidence breadth`() = runBlocking {
        WarpGate.poolSampler = { emptyList() }
        WarpGate.seedProber = { _, _, _, _ -> null }
        WarpGate.freshRegistrar = { fakeAccount("fresh") }
        WarpGate.portSweeper = { _, _ -> emptyMap() }
        val out = WarpGate.check(fakeAccount(), 2408, 3000) {}
        assertTrue("expected Blocked, got $out", out is WarpGate.Outcome.Blocked)
        assertTrue((out as WarpGate.Outcome.Blocked).note.contains("every canonical port"))
    }

    @Test
    fun `unverifiable verdict warns about silent identity expiry`() = runBlocking {
        WarpGate.poolSampler = { emptyList() }
        WarpGate.seedProber = { _, _, _, _ -> null }
        WarpGate.freshRegistrar = { null } // api blocked
        WarpGate.portSweeper = { _, _ -> emptyMap() }
        val stored = fakeAccount()
        val out = WarpGate.check(stored, 2408, 3000) {}
        assertTrue("expected Unverifiable, got $out", out is WarpGate.Outcome.Unverifiable)
        assertTrue((out as WarpGate.Outcome.Unverifiable).account === stored)
        assertTrue(out.note.contains("expired"))
        assertTrue(out.note.contains("SILENTLY"))
    }

    // ── 2. registration: apiPoster seam + disk fallback ────────────────

    private fun registrationBody(): String {
        val peerPub = android.util.Base64.encodeToString(
            ByteArray(32) { (it + 2).toByte() }, android.util.Base64.NO_WRAP)
        return """
            {
              "id": "acc-123",
              "token": "tok-456",
              "config": {
                "client_id": "AQID",
                "interface": { "addresses": { "v6": "2606:4700:d1:1234::2", "v4": "172.16.0.2" } },
                "peers": [ { "public_key": "$peerPub" } ]
              }
            }
        """.trimIndent()
    }

    @Test
    fun `register succeeds through the apiPoster seam and persists the identity`() = runBlocking {
        WarpRegistration.apiPoster = { registrationBody() }
        val acc = WarpRegistration.register()
        assertEquals("2606:4700:d1:1234::2", acc.v6)
        assertEquals("acc-123", acc.accountId)
        assertEquals("tok-456", acc.authToken)
        // identity persisted for the API-blocked fallback
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val prefs = ctx.getSharedPreferences("warp_identity", Context.MODE_PRIVATE)
        assertTrue("identity must be persisted", prefs.getString("identity_v1", null) != null)
    }

    @Test
    fun `register falls back to the persisted identity when the api is unreachable`() = runBlocking {
        // seed the disk identity first (simulating a past good registration)
        WarpRegistration.apiPoster = { registrationBody() }
        WarpRegistration.register()
        // simulate a process restart: in-process cache gone, api now blocked
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val field = WarpRegistration.javaClass.getDeclaredField("cachedAccount")
        field.isAccessible = true
        field.set(WarpRegistration, null)
        WarpRegistration.apiPoster = { throw java.io.IOException("registration api unreachable — dns poisoned") }
        val acc = WarpRegistration.register()
        assertEquals("the disk identity must be reused", "2606:4700:d1:1234::2", acc.v6)
    }

    @Test
    fun `register fresh throws honestly when the api is unreachable`() = runBlocking {
        WarpRegistration.apiPoster = { throw java.io.IOException("registration api unreachable") }
        var thrown: IllegalStateException? = null
        try {
            WarpRegistration.register(fresh = true)
        } catch (e: IllegalStateException) {
            thrown = e
        }
        assertTrue("fresh registration must throw when the api is down", thrown != null)
        assertTrue(
            "the reason must ride the message",
            thrown!!.message?.contains("registration api unreachable") == true,
        )
    }

    // ── 3. engine: zero-result scan on an unverifiable identity explains ──

    @Test
    fun `engine zero-result scan appends the identity-expiry hint`() = runBlocking {
        val engine = ScanEngine()
        engine.registrationProvider = { fakeAccount() }
        WarpGate.poolSampler = { emptyList() }
        WarpGate.seedProber = { _, _, _, _ -> null }
        WarpGate.freshRegistrar = { null } // api blocked → Unverifiable
        WarpGate.portSweeper = { _, _ -> emptyMap() }

        val phases = ArrayList<ScanPhase>()
        val logs = ArrayList<String>()
        val results = ArrayList<ScanResult>()
        val sink = object : ScanSink {
            override fun onPhase(phase: ScanPhase) { phases.add(phase) }
            override fun onGenerated(count: Int) {}
            override fun onResult(result: ScanResult) { results.add(result) }
            override fun onActive(delta: Int) {}
            override fun onLog(line: String) { logs.add(line) }
            override fun snapshot(): List<ScanResult> = results
        }
        // the fake identity is unknown to production WARP servers, so every
        // real probe fails silently — exactly the dead-identity user state
        engine.run(
            ScanParams(
                mode = ScanMode.WARP,
                port = 2408,
                samplesPerPrefix = 1, // 16 v4 + 32 v6-mapped candidates — small storm
                warpAttempts = 1,
                udpNoise = false,
                speedTest = false,
            ),
            sink,
        )

        assertTrue("scan must reach DONE, got $phases", phases.contains(ScanPhase.DONE))
        assertTrue("fake identity must verify nothing", results.none { it.alive })
        assertTrue(
            "the zero-result line must point at the identity",
            logs.any { it.contains("storm done") && it.contains("identity may be expired") },
        )
        assertTrue(
            "failure classes must still be tallied",
            logs.any { it.contains("storm done") && ("handshake timeout" in it || "no handshake" in it || "udp " in it) },
        )
    }
}
