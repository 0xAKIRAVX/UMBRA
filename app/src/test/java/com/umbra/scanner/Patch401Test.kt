package com.umbra.scanner

import com.umbra.scanner.core.NetFamily
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.debug.inferLevel
import com.umbra.scanner.debug.DbgLevel
import com.umbra.scanner.engine.formatRttCompact
import com.umbra.scanner.engine.sessionStartLine
import com.umbra.scanner.i18n.AppLanguage
import com.umbra.scanner.vless.VlessGenerator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Locale

/**
 * v4.0.1 regression tests — the fresh-eyes audit round over the v4.0.0
 * tri-lingual codebase. Every test forces a HOSTILE default locale first:
 * the old code failed exactly under these locales.
 *
 *  A. LOCALE HARDENING (8 code paths):
 *   1. formatRttCompact (recovery-sweep log) — Persian/Arabic-Indic digits
 *      garbled the engine's ASCII diagnostics on fa/ar devices.
 *   2. sessionStartLine (scan session log) — Turkish dotless ı in the
 *      family label ("ıpv4").
 *   3. isTestOnlySni — an all-caps "SPEED.CLOUDFLARE.COM" slipped past the
 *      VLESS test-only guard on Turkish devices (forged never-proxying link).
 *   4. AppLanguage.defaultFor — locale tags lowercased with the default locale.
 *   5. inferLevel (debug journal level inference) — "IDENTITY FAILED" painted
 *      INFO instead of WARN on Turkish devices.
 *
 *  B. WG DEEP-PROBE DEFAULT PORT: a bare IP in the WG deep probe defaulted
 *     to :443 (the clean-ip default) — WARP speaks 2408, so the probe
 *     honestly reported a dead endpoint. The default is now probe-specific.
 */
class Patch401Test {

    private fun withDefaultLocale(locale: Locale, block: () -> Unit) {
        val previous = Locale.getDefault()
        try {
            Locale.setDefault(locale)
            block()
        } finally {
            Locale.setDefault(previous)
        }
    }

    // ── A1. sweep RTT: ASCII digits under hostile locales ──────────────

    @Test
    fun `sweep rtt renders ascii digits under persian locale`() = withDefaultLocale(Locale("fa", "IR")) {
        val out = formatRttCompact(5.4)
        assertEquals("5", out)
        assertFalse(out.any { it.code in 0x06F0..0x06F9 }) // ۰-۹
    }

    @Test
    fun `sweep rtt renders ascii digits under arabic locale`() = withDefaultLocale(Locale("ar", "EG")) {
        val out = formatRttCompact(12.7)
        assertEquals("13", out)
        assertFalse(out.any { it.code in 0x0660..0x0669 }) // ٠-٩
    }

    @Test
    fun `sweep rtt rounding is locale independent`() {
        for (locale in listOf(Locale.US, Locale("fa", "IR"), Locale("tr", "TR"))) {
            withDefaultLocale(locale) {
                assertEquals("0", formatRttCompact(0.4))
                assertEquals("1", formatRttCompact(0.5))
                assertEquals("7", formatRttCompact(6.51))
            }
        }
    }

    // ── A2. session line: ASCII family label under Turkish locale ──────

    @Test
    fun `session line family label stays ascii under turkish locale`() = withDefaultLocale(Locale("tr", "TR")) {
        val line = sessionStartLine(ScanParams(mode = ScanMode.ENDPOINT, family = NetFamily.V4))
        assertFalse(line.contains('ı')) // dotless ı, U+0131
        assertTrue(line.contains("ipv4"))
        assertTrue(line.startsWith("scan session started · mode ENDPOINT"))
    }

    @Test
    fun `session line carries the full endpoint contract`() {
        val line = sessionStartLine(
            ScanParams(
                mode = ScanMode.ENDPOINT, family = NetFamily.BOTH, port = 0,
                endpointsCount = 500, warpAttempts = 5, udpNoise = true, noiseCount = 5,
            )
        )
        assertTrue(line.contains("500 random ip:port endpoints"))
        assertTrue(line.contains("seeds"))
        assertTrue(line.contains("wireguard handshake ×5"))
        assertTrue(line.contains("random ports"))
        assertTrue(line.contains("all"))
        assertTrue(line.contains("udp noise ×5"))

        val edge = sessionStartLine(ScanParams(mode = ScanMode.CF_EDGE, tcpAttempts = 3, tcpTimeoutMs = 2000))
        assertTrue(edge.contains("mode CF_EDGE"))
        assertTrue(edge.contains("3 attempts × 2000 ms"))
    }

    // ── A3. all-caps test-only SNIs caught under hostile locales ───────

    @Test
    fun `all caps test sni is rejected under turkish locale`() = withDefaultLocale(Locale("tr", "TR")) {
        // "SPEED.CLOUDFLARE.COM".lowercase() in tr → "speed.cloudflare.com"
        // ONLY if I→ı doesn't strike; the old code produced "speed.cloudflare.com"
        // with dotless ı and the equality FAILED — the forged-link bug.
        assertTrue(VlessGenerator.isTestOnlySni("SPEED.CLOUDFLARE.COM"))
        assertTrue(VlessGenerator.isTestOnlySni(" Speed.Cloudflare.Com "))
        assertTrue(VlessGenerator.isTestOnlySni("WWW.SpeedTest.NET"))
        assertFalse(VlessGenerator.isTestOnlySni("worker.example.com"))
        assertFalse(VlessGenerator.isTestOnlySni("MY-WORKER.example.IR"))
    }

    // ── A4. language detection independent of default locale ───────────

    @Test
    fun `language detection is locale independent`() = withDefaultLocale(Locale("tr", "TR")) {
        assertEquals(AppLanguage.PERSIAN, AppLanguage.defaultFor("fa"))
        assertEquals(AppLanguage.PERSIAN, AppLanguage.defaultFor("fa-IR"))
        assertEquals(AppLanguage.PERSIAN, AppLanguage.defaultFor("FA_ir"))
        assertEquals(AppLanguage.ENGLISH, AppLanguage.defaultFor("en-US"))
        assertEquals(AppLanguage.ENGLISH, AppLanguage.defaultFor(null))
    }

    // ── A5. debug journal level inference under hostile locales ────────

    @Test
    fun `level inference matches keywords under turkish locale`() = withDefaultLocale(Locale("tr", "TR")) {
        // "IDENTITY FAILED" — the old tr-lowercase produced "ıdentıty faıled",
        // the "identity failed" WARN keyword never matched, and the console
        // painted an honest warning as neutral INFO.
        assertEquals(DbgLevel.WARN, inferLevel("IDENTITY FAILED — cloudflare unreachable"))
        assertEquals(DbgLevel.ERROR, inferLevel("ENGINE FAILURE — NoClassDefFoundError"))
        assertEquals(DbgLevel.INFO, inferLevel("scan session started · mode ENDPOINT"))
        assertEquals(DbgLevel.WARN, inferLevel("recovery sweep · v4 · 0/280 answered"))
    }

    // ── B. WG deep-probe default port is probe-specific ────────────────

    @Test
    fun `wg deep probe defaults bare ip to the warp port`() {
        // the old shared splitTarget sent a bare IP to :443 — WARP's port
        // is 2408, so the WG probe honestly reported a dead endpoint.
        val (ip, port) = com.umbra.scanner.ui.screens.splitTarget("162.159.192.1", 2408)
        assertEquals("162.159.192.1", ip)
        assertEquals(2408, port)
    }

    @Test
    fun `clean deep probe defaults bare ip to the edge port`() {
        val (ip, port) = com.umbra.scanner.ui.screens.splitTarget("104.16.1.1", 443)
        assertEquals("104.16.1.1", ip)
        assertEquals(443, port)
    }

    @Test
    fun `explicit ports and v6 brackets always win over defaults`() {
        assertEquals(894, com.umbra.scanner.ui.screens.splitTarget("162.159.192.1:894", 2408).second)
        assertEquals(928, com.umbra.scanner.ui.screens.splitTarget("162.159.192.1:928", 443).second)
        val (v6, p) = com.umbra.scanner.ui.screens.splitTarget("[2606:4700:d0::1]", 2408)
        assertEquals("[2606:4700:d0::1]", v6)
        assertEquals(2408, p)
        val (v6p, p2) = com.umbra.scanner.ui.screens.splitTarget("[2606:4700:d0::1]:894", 443)
        assertEquals("[2606:4700:d0::1]", v6p)
        assertEquals(894, p2)
        // garbage ports fall back to the probe-specific default, never 443-for-WG
        assertEquals(2408, com.umbra.scanner.ui.screens.splitTarget("[2606:4700:d0::1]:", 2408).second)
    }
}
