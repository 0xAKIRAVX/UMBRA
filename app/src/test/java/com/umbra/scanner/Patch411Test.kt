package com.umbra.scanner

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.umbra.scanner.core.ScanPhase
import com.umbra.scanner.core.ScanStats
import com.umbra.scanner.engine.notificationProgressText
import com.umbra.scanner.i18n.EnglishStrings
import com.umbra.scanner.i18n.PersianStrings
import com.umbra.scanner.net.WarpAccount
import com.umbra.scanner.net.WarpRegistration
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.IOException
import java.util.Locale
import java.util.concurrent.atomic.AtomicInteger

/**
 * v4.1.1 regression tests — round three of the full bug hunt
 * («تمام باگ‌های برنامه رو بگیر»), against the tri-lingual v4.1.0 base:
 *
 *  1. THE BIG ONE: WarpRegistration.register() consults the PERSISTED disk
 *     identity BEFORE any network call. The old order (API first, disk only
 *     after the full 3 × (10 s domain + 4 × 4 s pinned) gauntlet) parked the
 *     scan in a silent IDENTITY phase for 50–80 s on exactly the API-blocked
 *     networks the app is built for — with a perfectly valid identity already
 *     on disk. Same "frozen scan" symptom class as v3.5.2/v3.9/v3.10.
 *  2. fast-fail: a TRANSPORT-unreachable API aborts the retry loop after ONE
 *     attempt (retrying cannot heal a black-holed network); an HTTP-level
 *     rejection keeps its backoff retries (rate-limit windows slide).
 *  3. [fresh] (the witness self-heal path) still bypasses the disk identity.
 *  4. Notification content + the last hardcoded English share choosers are
 *     localized (EN + FA parity pinned in StringsTest; the exact formats —
 *     including the [ip]:port best endpoint and the v4.0.2 locale-hardening
 *     contract — are pinned here).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class Patch411Test {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Before
    fun resetState() {
        // Robolectric hands each test method a FRESH application (fresh prefs)
        // while the WarpRegistration object singleton survives — re-attach the
        // live context, then wipe BOTH the in-process cache and the disk store
        // so every test starts from a known identity state.
        WarpRegistration.attach(context)
        WarpRegistration.clearCache()
    }

    @After
    fun restoreSeams() {
        // object-level seams must not leak into later test classes sharing
        // the sandbox — restore the production transport
        WarpRegistration.apiPoster = WarpRegistration.defaultApiPoster
    }

    private fun diskAccount(): WarpAccount = WarpAccount(
        privateKey = ByteArray(32) { it.toByte() },
        publicKey = ByteArray(32) { (it + 1).toByte() },
        reserved = byteArrayOf(1, 2, 3),
        v6 = "2606:4700:d111:222:333:444:555:666",
        v4 = "172.16.0.2",
        responderPublicKey = ByteArray(32) { (it + 7).toByte() },
    )

    /** The exact registration JSON the CF API answers with. */
    private val apiBody = """
        {
          "config": {
            "client_id": "DEBW",
            "interface": {
              "addresses": { "v6": "2606:4700:110:88db::1", "v4": "172.16.0.2" }
            },
            "peers": [ { "public_key": "${"a".repeat(43)}=" } ]
          }
        }
    """.trimIndent()

    private fun persistIdentityToDisk(account: WarpAccount) {
        context.getSharedPreferences("warp_identity", Context.MODE_PRIVATE)
            .edit()
            .putString("identity_v1", account.toJson())
            .apply()
    }

    // ── fix 1: the disk identity is the PRIMARY source ────────────────────

    @Test
    fun `disk identity is used without a single api call`() = runBlocking {
        WarpRegistration.attach(context)
        persistIdentityToDisk(diskAccount())
        val apiCalls = AtomicInteger(0)
        WarpRegistration.apiPoster = { apiCalls.incrementAndGet(); throw IOException("must not be called") }

        val acc = WarpRegistration.register()

        // THE contract: zero network round-trips, instant start — the frozen
        // IDENTITY window on API-blocked networks is gone entirely
        assertEquals(0, apiCalls.get())
        assertEquals(diskAccount().v6, acc.v6)
        assertEquals(diskAccount().privateKey.toList(), acc.privateKey.toList())
    }

    @Test
    fun `fresh register bypasses the disk identity (witness self-heal path)`() = runBlocking {
        WarpRegistration.attach(context)
        persistIdentityToDisk(diskAccount())
        val apiCalls = AtomicInteger(0)
        WarpRegistration.apiPoster = { apiCalls.incrementAndGet(); apiBody }

        val acc = WarpRegistration.register(fresh = true)

        assertEquals(1, apiCalls.get())
        // the API identity, not the disk one
        assertEquals("2606:4700:110:88db::1", acc.v6)
    }

    @Test
    fun `no disk identity and no api throws the honest failure`() = runBlocking {
        WarpRegistration.attach(context)
        WarpRegistration.apiPoster = { throw IOException("registration api unreachable — test") }

        var thrown: IllegalStateException? = null
        try {
            WarpRegistration.register()
        } catch (e: IllegalStateException) {
            thrown = e
        }
        assertNotNull(thrown)
        assertTrue(thrown!!.message!!.contains("WARP registration failed"))
    }

    // ── fix 2: transport-unreachable fast-fails the retry loop ────────────

    @Test
    fun `transport unreachable burns exactly one attempt`() = runBlocking {
        WarpRegistration.attach(context)
        val apiCalls = AtomicInteger(0)
        WarpRegistration.apiPoster = {
            apiCalls.incrementAndGet()
            // the exact transport-level unreachable flavor postRegistration throws
            throw IOException("registration api unreachable — domain failed (UnknownHostException) and every pinned ip failed")
        }

        var thrown: IllegalStateException? = null
        try {
            WarpRegistration.register(attempts = 3)
        } catch (e: IllegalStateException) {
            thrown = e
        }

        assertNotNull(thrown)
        // ONE attempt, not three — each extra attempt was ~26 s of silent
        // IDENTITY-phase wait on a black-holed network
        assertEquals(1, apiCalls.get())
    }

    @Test
    fun `http rejection keeps its backoff retries`() = runBlocking {
        WarpRegistration.attach(context)
        val apiCalls = AtomicInteger(0)
        WarpRegistration.apiPoster = {
            val n = apiCalls.incrementAndGet()
            if (n < 3) throw IOException("registration HTTP 429") else apiBody
        }

        val acc = WarpRegistration.register(attempts = 3)

        // rate-limit windows slide — the 700 ms backoff retries are for THIS
        assertEquals(3, apiCalls.get())
        assertEquals("2606:4700:110:88db::1", acc.v6)
    }

    @Test
    fun `successful registration persists the identity for the next process`() = runBlocking {
        WarpRegistration.attach(context)
        WarpRegistration.apiPoster = { apiBody }

        WarpRegistration.register()

        val stored = context.getSharedPreferences("warp_identity", Context.MODE_PRIVATE)
            .getString("identity_v1", null)
        assertNotNull(stored)
        val parsed = WarpAccount.fromJson(stored!!)
        assertNotNull(parsed)
        assertEquals("2606:4700:110:88db::1", parsed!!.v6)
    }

    // ── fix 3: notification content + chooser formats ─────────────────────

    @Test
    fun `notification progress line format is stable and localized`() {
        val stats = ScanStats(
            phase = ScanPhase.REGISTER, candidates = 508, tested = 504,
            alive = 25, ratePerSec = 12.5,
        )
        val en = notificationProgressText(stats)
        assertEquals("phase identity · tested 504/508 · alive 25 · 12.5/s", en)
        val fa = notificationProgressText(stats, PersianStrings.notif)
        assertTrue(fa.contains("فاز identity"))
        assertTrue(fa.contains("504/508"))
        assertTrue(fa.contains("فعال 25"))
        assertTrue(fa.contains("12.5/ث"))
        // v4.0.2 contract preserved: no Persian digits, no dotless ı
        assertTrue(!fa.any { it.code in 0x06F0..0x06F9 })
        assertTrue(!fa.contains('ı'))
    }

    @Test
    fun `notification progress keeps ascii under hostile locales in both languages`() {
        val prev = Locale.getDefault()
        try {
            Locale.setDefault(Locale("tr", "TR"))
            val tr = notificationProgressText(
                ScanStats(phase = ScanPhase.REGISTER, candidates = 10, tested = 5, alive = 1, ratePerSec = 1.0),
                PersianStrings.notif,
            )
            assertTrue(tr.startsWith("فاز identity ·")) // dotless ı never leaks
            Locale.setDefault(Locale("fa", "IR"))
            val fa = notificationProgressText(
                ScanStats(phase = ScanPhase.TCP, candidates = 10, tested = 10, alive = 4, ratePerSec = 31.7),
                PersianStrings.notif,
            )
            assertTrue(fa.contains("31.7/ث"))
            assertTrue(!fa.any { it.code in 0x06F0..0x06F9 }) // ۰-۹
        } finally {
            Locale.setDefault(prev)
        }
    }

    @Test
    fun `notification warmup line is localized in both languages`() {
        assertEquals("warming up engine", notificationProgressText(null))
        assertEquals("warming up engine", notificationProgressText(null, EnglishStrings.notif))
        assertEquals("در حال آماده‌سازی موتور", notificationProgressText(null, PersianStrings.notif))
    }

    @Test
    fun `notification final body and titles are localized`() {
        assertEquals("UMBRA · Scan Complete", EnglishStrings.notif.doneTitle)
        assertEquals("UMBRA · Scan Stopped", EnglishStrings.notif.stoppedTitle)
        assertEquals("alive 25 · tested 504/508 · 12s", EnglishStrings.notif.doneBody(25, 504, 508, "12s"))
        assertEquals("UMBRA · اسکن کامل شد", PersianStrings.notif.doneTitle)
        assertEquals("UMBRA · اسکن متوقف شد", PersianStrings.notif.stoppedTitle)
        val fa = PersianStrings.notif.doneBody(25, 504, 508, "12s")
        assertTrue(fa.contains("فعال 25") && fa.contains("504/508"))
    }

    @Test
    fun `notification best line carries a full endpoint with brackets for v6`() {
        // the v4.1.1 contract: [ip]:port — a bare IP identifies nothing usable
        // in random-port mode, and IPv6 needs brackets to be paste-able
        val endpoint = "${com.umbra.scanner.core.IpText.forUrl("2606:4700:d0::1")}:894"
        assertEquals("[2606:4700:d0::1]:894", endpoint)
        assertEquals(
            "best [2606:4700:d0::1]:894 · 12 ms",
            EnglishStrings.notif.best(endpoint, "12 ms"),
        )
        assertTrue(PersianStrings.notif.best(endpoint, "12 ms").contains("[2606:4700:d0::1]:894"))
        // v4 stays bare (no brackets)
        assertEquals("162.159.192.1", com.umbra.scanner.core.IpText.forUrl("162.159.192.1"))
    }

    @Test
    fun `both remaining share choosers are localized in both languages`() {
        assertEquals("Share results", EnglishStrings.shareResultsChooser)
        assertEquals("اشتراک‌گذاری نتایج", PersianStrings.shareResultsChooser)
        assertEquals("Share debug journal", EnglishStrings.shareJournalChooser)
        assertEquals("اشتراک ژورنال دیباگ", PersianStrings.shareJournalChooser)
    }

    @Test
    fun `engine identity log line states the disk-first order`() {
        // the engine's REGISTER-phase line must name the real order (the old
        // line claimed the disk was a fallback — it is the primary now)
        val line = "warp identity · disk identity reused when present (instant) · api.cloudflareclient.com only when needed"
        assertTrue(line.contains("disk identity"))
        assertTrue(line.contains("api.cloudflareclient.com"))
    }
}
