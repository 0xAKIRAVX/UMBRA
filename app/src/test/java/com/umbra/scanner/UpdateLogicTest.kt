package com.umbra.scanner

import com.umbra.scanner.net.UpdateChecker
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class UpdateLogicTest {

    // ── version comparison ───────────────────────────────────────

    @Test
    fun `equal versions are not newer`() {
        assertFalse(UpdateChecker.isNewer("2.3.0", "v2.3.0"))
        assertFalse(UpdateChecker.isNewer("2.3.0", "2.3.0"))
    }

    @Test
    fun `higher patch is newer`() {
        assertTrue(UpdateChecker.isNewer("2.2.9", "v2.3.0"))
    }

    @Test
    fun `higher minor is newer`() {
        assertTrue(UpdateChecker.isNewer("2.9.5", "v2.10.0"))
    }

    @Test
    fun `higher major is newer`() {
        assertTrue(UpdateChecker.isNewer("2.9.9", "v3.0.0"))
    }

    @Test
    fun `lower version is not newer`() {
        assertFalse(UpdateChecker.isNewer("2.4.0", "v2.3.1"))
        assertFalse(UpdateChecker.isNewer("3.0.0", "v2.9.9"))
    }

    @Test
    fun `unequal segment counts compare numerically not lexically`() {
        // 2.3 vs 2.3.0 must be equal; 2.10 vs 2.9 must be newer (numeric, not string)
        assertFalse(UpdateChecker.isNewer("2.3", "v2.3.0"))
        assertTrue(UpdateChecker.isNewer("2.9", "v2.10"))
    }

    @Test
    fun `build suffixes are tolerated`() {
        assertTrue(UpdateChecker.isNewer("2.3.0", "v2.4.0-beta"))
        assertFalse(UpdateChecker.isNewer("2.4.0", "v2.4.0-rc.1"))
    }

    @Test
    fun `garbage input never reports newer`() {
        assertFalse(UpdateChecker.isNewer("2.3.0", ""))
        assertFalse(UpdateChecker.isNewer("2.3.0", "latest"))
        assertFalse(UpdateChecker.isNewer("2.3.0", "v"))
    }

    // ── release payload parsing ──────────────────────────────────

    private fun payload(
        tag: String = "v2.4.0",
        apkName: String? = "UMBRA-v2.4.0-Cloudflare-Scanner.apk",
        htmlUrl: String = "https://github.com/0xAKIRAVX/UMBRA/releases/tag/v2.4.0",
        body: String? = "release notes here",
    ): String {
        val o = JSONObject()
        o.put("tag_name", tag)
        o.put("name", "UMBRA v2.4.0")
        o.put("html_url", htmlUrl)
        o.put("body", body ?: JSONObject.NULL)
        o.put("published_at", "2026-10-04T12:00:00Z")
        if (apkName != null) {
            val asset = JSONObject()
            asset.put("name", apkName)
            asset.put("browser_download_url", "https://github.com/0xAKIRAVX/UMBRA/releases/download/v2.4.0/$apkName")
            o.put("assets", org.json.JSONArray().put(asset))
        } else {
            o.put("assets", org.json.JSONArray())
        }
        return o.toString()
    }

    @Test
    fun `parses tag page url notes and apk asset`() {
        val r = UpdateChecker.parseLatest(payload())!!
        assertEquals("v2.4.0", r.tag)
        assertEquals("https://github.com/0xAKIRAVX/UMBRA/releases/download/v2.4.0/UMBRA-v2.4.0-Cloudflare-Scanner.apk", r.apkUrl)
        assertEquals("https://github.com/0xAKIRAVX/UMBRA/releases/tag/v2.4.0", r.pageUrl)
        assertEquals("release notes here", r.notes)
        assertNotNull(r.publishedAt)
    }

    @Test
    fun `non apk asset yields null apk url but keeps page url`() {
        val r = UpdateChecker.parseLatest(payload(apkName = "source.zip"))!!
        assertNull(r.apkUrl)
        assertEquals("v2.4.0", r.tag)
        assertNotNull(r.pageUrl)
    }

    @Test
    fun `missing tag makes release unusable`() {
        assertNull(UpdateChecker.parseLatest(payload(tag = "")))
    }

    @Test
    fun `malformed json yields null not crash`() {
        assertNull(UpdateChecker.parseLatest("{not json"))
        assertNull(UpdateChecker.parseLatest(""))
    }

    @Test
    fun `blank body yields null notes`() {
        val r = UpdateChecker.parseLatest(payload(body = ""))!!
        assertNull(r.notes)
    }
}
