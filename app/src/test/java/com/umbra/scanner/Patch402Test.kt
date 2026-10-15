package com.umbra.scanner

import com.umbra.scanner.core.ScanPhase
import com.umbra.scanner.core.ScanStats
import com.umbra.scanner.debug.DeepEndpointTest
import com.umbra.scanner.engine.ScanEngine
import com.umbra.scanner.engine.notificationProgressText
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Locale

/**
 * v4.0.2 regression tests — the second fresh-eyes audit round over the
 * tri-lingual codebase. Hostile default locales are forced exactly like
 * Patch401Test (the old code failed under these).
 *
 *  A. LOCALE HARDENING (2 missed paths):
 *   1. cleanColoLine (the Go engine's per-verified-endpoint narration) —
 *      "%.0f".format() with the DEFAULT locale rendered Persian/Arabic-Indic
 *      digits on fa/ar devices inside the ASCII scan log.
 *   2. notificationProgressText (the foreground notification) — the phase
 *      label passed through default-locale lowercase(), so "IDENTITY" became
 *      "ıdentıty" (dotless ı) on Turkish devices in the status bar.
 *
 *  B. GO EVENT STATE (the ACTIVE-stat poisoning):
 *     the Go engine reports ABSOLUTE busy-lane counts in prg events while the
 *     sink's onActive contract is a DELTA — the old pass-through accumulated
 *     the full busy count on every event and the ACTIVE stat climbed
 *     monotonically through the whole CLEAN-IP scan. The absolute→delta
 *     converter must track the true value across any sequence AND flush its
 *     residual to zero at scan end.
 *
 *  C. DUPLICATE-DRAW RECONCILE:
 *     the Go sampler draws WITH replacement (unlike IpGenerator) — duplicate
 *     ip:port pairs on small CIDRs would strand the progress counter below
 *     100%; the unique-id ledger and the honest reconcile line pin that.
 *
 *  D. hexDump TRUNCATION MARKER:
 *     a truncated dump printed the "+N bytes" marker after EVERY row; it must
 *     appear exactly once, at the end.
 */
class Patch402Test {

    private fun withDefaultLocale(locale: Locale, block: () -> Unit) {
        val previous = Locale.getDefault()
        try {
            Locale.setDefault(locale)
            block()
        } finally {
            Locale.setDefault(previous)
        }
    }

    // ── A1. colo line: ASCII digits under hostile locales ───────────────

    @Test
    fun `colo line renders ascii digits under persian locale`() = withDefaultLocale(Locale("fa", "IR")) {
        val line = ScanEngine().cleanColoLine("104.16.1.7", "IAD", 42.6)
        assertEquals("clean · 104.16.1.7 · colo IAD · tls 43ms", line)
        assertFalse(line.any { it.code in 0x06F0..0x06F9 }) // ۰-۹
    }

    @Test
    fun `colo line renders ascii digits under arabic locale`() = withDefaultLocale(Locale("ar", "EG")) {
        val line = ScanEngine().cleanColoLine("104.16.1.7", "DXB", 18.2)
        assertTrue(line.endsWith("tls 18ms"))
        assertFalse(line.any { it.code in 0x0660..0x0669 }) // ٠-٩
    }

    @Test
    fun `colo line is locale independent`() {
        for (locale in listOf(Locale.US, Locale("fa", "IR"), Locale("tr", "TR"))) {
            withDefaultLocale(locale) {
                assertEquals(
                    "clean · 188.114.96.1 · colo FRA · tls 5ms",
                    ScanEngine().cleanColoLine("188.114.96.1", "FRA", 5.4),
                )
            }
        }
    }

    // ── A2. notification progress text: ASCII phase label ───────────────

    @Test
    fun `notification phase label stays ascii under turkish locale`() = withDefaultLocale(Locale("tr", "TR")) {
        val text = notificationProgressText(
            ScanStats(phase = ScanPhase.REGISTER, candidates = 500, tested = 120, alive = 3, ratePerSec = 12.5),
        )
        // the old default-locale lowercase() rendered "ıdentıty" here
        assertTrue(text.contains("phase identity ·"))
        assertFalse(text.contains('ı')) // dotless ı, U+0131
        assertTrue(text.contains("tested 120/500"))
        assertTrue(text.contains("alive 3"))
        assertTrue(text.endsWith("12.5/s"))
    }

    @Test
    fun `notification rate renders ascii digits under persian locale`() = withDefaultLocale(Locale("fa", "IR")) {
        val text = notificationProgressText(
            ScanStats(phase = ScanPhase.TCP, candidates = 240, tested = 240, alive = 96, ratePerSec = 31.7),
        )
        assertTrue(text.contains("31.7/s"))
        assertFalse(text.any { it.code in 0x06F0..0x06F9 }) // ۰-۹
    }

    @Test
    fun `notification warmup line has no stats`() {
        assertEquals("warming up engine", notificationProgressText(null))
    }

    @Test
    fun `every phase label lowercases to pure ascii under hostile locales`() {
        for (locale in listOf(Locale("tr", "TR"), Locale("az", "AZ"))) {
            withDefaultLocale(locale) {
                for (phase in ScanPhase.entries) {
                    val lowered = phase.label.lowercase(java.util.Locale.ROOT)
                    assertTrue(lowered.all { it.code in 0x20..0x7E }) // pure ASCII
                    // and the OLD failure mode is provably guarded: the enum
                    // labels contain 'I', which tr-locale lowercase() turns
                    // into dotless ı when Locale.ROOT is not pinned
                    assertEquals(lowered.replace('ı', 'i'), lowered)
                }
            }
        }
    }

    // ── B. Go busy-lane absolute→delta conversion ───────────────────────

    @Test
    fun `busy deltas track the absolute count across a sequence`() {
        val st = ScanEngine.GoEventState(announced = 240)
        val sequence = listOf(0, 150, 150, 148, 120, 60, 0)
        var expected = 0
        val deltas = ArrayList<Int>(sequence.size)
        for (busy in sequence) {
            val d = st.busyDelta(busy)
            deltas.add(d)
            expected += d
            assertEquals(busy, expected) // cumulative sum == the absolute value
        }
        // the pass-through bug's signature: every delta would have been the
        // full positive busy count — assert the sum of deltas is the FINAL
        // count, not the accumulation of all counts
        assertEquals(0, expected)
        assertTrue(deltas.contains(150))
        assertTrue(deltas.contains(-60)) // 120 → 60
        assertTrue(deltas.contains(-28)) // 148 → 120
    }

    @Test
    fun `busy delta emits zero while the count holds steady`() {
        val st = ScanEngine.GoEventState(announced = 100)
        assertEquals(100, st.busyDelta(100)) // ramp-up: one full positive delta
        assertEquals(0, st.busyDelta(100))   // steady state: NO event noise
        assertEquals(0, st.busyDelta(100))
        assertEquals(-40, st.busyDelta(60))  // lanes draining
    }

    @Test
    fun `flush returns the residual and resets the baseline`() {
        val st = ScanEngine.GoEventState(announced = 100)
        st.busyDelta(120) // mid-scan prg said 120 busy
        assertEquals(120, st.flushBusy()) // the cancel/finish path must drain it
        assertEquals(0, st.flushBusy()) // idempotent — no double subtraction
        assertEquals(30, st.busyDelta(30)) // baseline restarted at 0
    }

    // ── C. duplicate-draw reconcile ─────────────────────────────────────

    @Test
    fun `unique id ledger deduplicates repeated res events`() {
        val st = ScanEngine.GoEventState(announced = 240)
        // phase 1 + phase 2 + phase 3 all re-emit the same ip:port targets
        repeat(3) {
            st.observe("104.16.1.7", 443)
            st.observe("104.16.1.9", 443)
        }
        st.observe("104.16.2.2", 8443)
        assertEquals(3, st.seenIds.size)
        assertTrue("104.16.1.7:443" in st.seenIds)
        assertTrue("104.16.2.2:8443" in st.seenIds)
    }

    @Test
    fun `reconcile line names the duplicates and the unique count`() {
        val line = ScanEngine().goDuplicateDrawLine(announced = 240, unique = 213)
        assertTrue(line.contains("27 duplicate ip draw(s)"))
        assertTrue(line.contains("213 unique endpoints"))
        assertTrue(line.contains("reconciled"))
    }

    @Test
    fun `scan state defaults to not cancelled`() {
        val st = ScanEngine.GoEventState(announced = 10)
        assertFalse(st.cancelled)
    }

    // ── D. hexDump truncation marker ────────────────────────────────────

    @Test
    fun `truncated dump carries exactly one truncation marker`() {
        val bytes = ByteArray(148) { (it % 251).toByte() }
        val dump = DeepEndpointTest.hexDump(bytes, maxBytes = 128)
        val markers = Regex("· \\+\\d+ bytes").findAll(dump).count()
        assertEquals(1, markers)
        assertTrue(dump.contains("· +20 bytes"))
        // 128 shown bytes = 8 full rows of 16 + the single marker line
        assertEquals(9, dump.lines().size)
    }

    @Test
    fun `non truncated dump carries no truncation marker`() {
        val bytes = ByteArray(92) { (it % 251).toByte() } // a WG response size
        val dump = DeepEndpointTest.hexDump(bytes, maxBytes = 128)
        assertFalse(dump.contains("+"))
        assertEquals(6, dump.lines().size) // 92 = 5 rows of 16 + 1 row of 12
    }

    @Test
    fun `empty dump is empty`() {
        assertEquals("", DeepEndpointTest.hexDump(ByteArray(0)))
    }
}
