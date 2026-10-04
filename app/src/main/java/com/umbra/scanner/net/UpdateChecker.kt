package com.umbra.scanner.net

import com.umbra.scanner.core.Project
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * Checks GitHub for the latest UMBRA release. Pure parsing + version math live
 * here as plain functions so they are unit-testable without any network.
 */
object UpdateChecker {

    /** Everything the update UI needs, distilled from a GitHub release. */
    data class Release(
        val tag: String,
        val name: String?,
        val pageUrl: String,
        val apkUrl: String?,
        val notes: String?,
        val publishedAt: String?,
    )

    /**
     * Compares dotted numeric versions, tolerating a leading `v`, build
     * suffixes (`-beta`, `-rc.1`) and unequal segment counts.
     * Returns true only when [latestTag] is strictly newer than [current].
     */
    fun isNewer(current: String, latestTag: String): Boolean {
        fun parts(v: String): List<Int> = v.trim()
            .removePrefix("v").removePrefix("V")
            .substringBefore('-')
            .split('.')
            .map { it.toIntOrNull() ?: 0 }
        val c = parts(current)
        val l = parts(latestTag)
        val n = maxOf(c.size, l.size)
        for (i in 0 until n) {
            val a = c.getOrElse(i) { 0 }
            val b = l.getOrElse(i) { 0 }
            if (b != a) return b > a
        }
        return false
    }

    /** Parses the `GET /releases/latest` JSON payload; null when unusable. */
    fun parseLatest(body: String): Release? = runCatching {
        val o = JSONObject(body)
        val tag = o.optString("tag_name")
        if (tag.isBlank()) return@runCatching null
        val pageUrl = o.optString("html_url").ifBlank { Project.RELEASES_URL }
        var apkUrl: String? = null
        val assets = o.optJSONArray("assets")
        if (assets != null) {
            for (i in 0 until assets.length()) {
                val a = assets.getJSONObject(i)
                val nm = a.optString("name")
                if (nm.endsWith(".apk", ignoreCase = true)) {
                    apkUrl = a.optString("browser_download_url").ifBlank { null }
                    break
                }
            }
        }
        Release(
            tag = tag,
            name = o.optString("name").ifBlank { null },
            pageUrl = pageUrl,
            apkUrl = apkUrl,
            notes = o.optString("body").ifBlank { null },
            publishedAt = o.optString("published_at").ifBlank { null },
        )
    }.getOrNull()

    /**
     * Live fetch of the latest release. Returns null on any failure
     * (offline, rate-limited, malformed payload) — never throws.
     */
    suspend fun fetchLatest(): Release? = withContext(Dispatchers.IO) {
        runCatching {
            val conn = URL(Project.LATEST_API).openConnection() as HttpURLConnection
            try {
                conn.requestMethod = "GET"
                // GitHub's API rejects requests without a User-Agent.
                conn.setRequestProperty("User-Agent", "UMBRA-Android-Updater")
                conn.setRequestProperty("Accept", "application/vnd.github+json")
                conn.connectTimeout = 8_000
                conn.readTimeout = 8_000
                if (conn.responseCode !in 200..299) return@runCatching null
                parseLatest(conn.inputStream.bufferedReader().use { it.readText() })
            } finally {
                conn.disconnect()
            }
        }.getOrNull()
    }
}
