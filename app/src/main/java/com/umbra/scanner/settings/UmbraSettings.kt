package com.umbra.scanner.settings

import android.content.Context
import com.umbra.scanner.core.NetFamily
import com.umbra.scanner.core.Presets
import com.umbra.scanner.core.ResultCodec
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.core.ScanResult
import com.umbra.scanner.core.WarpFlavor
import com.umbra.scanner.i18n.AppLanguage
import com.umbra.scanner.net.NetQuality
import com.umbra.scanner.net.NetworkProfile
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

class UmbraSettings(context: Context) {

    private val prefs = context.getSharedPreferences("umbra_prefs", Context.MODE_PRIVATE)

    val accent = MutableStateFlow(prefs.getInt("accent", 0))
    val amoled = MutableStateFlow(prefs.getBoolean("amoled", false))
    val haptics = MutableStateFlow(prefs.getBoolean("haptics", true))
    val highRefresh = MutableStateFlow(prefs.getBoolean("high_refresh", true))
    val lightFx = MutableStateFlow(prefs.getBoolean("light_fx", false))

    // ── language (0 = english · 1 = فارسی · default follows system locale) ──
    val language = MutableStateFlow(
        prefs.getInt("language", -1).let { stored ->
            if (stored in 0..1) stored else AppLanguage.defaultFor(
                context.resources.configuration.locales.get(0)?.language
            )
        }
    )

    fun setLanguage(v: Int) { language.value = v; prefs.edit().putInt("language", v).apply() }

    // ── update channel ──
    val autoUpdate = MutableStateFlow(prefs.getBoolean("auto_update", true))
    val dismissedUpdateTag = MutableStateFlow(prefs.getString("dismissed_update_tag", null))
    val lastUpdateCheck = MutableStateFlow(prefs.getLong("last_update_check", 0L))

    // ── v3.1.1: POST_NOTIFICATIONS is asked exactly once, not on every scan ──
    val notifAsked = MutableStateFlow(prefs.getBoolean("notif_asked", false))

    fun setNotifAsked() {
        notifAsked.value = true
        prefs.edit().putBoolean("notif_asked", true).apply()
    }

    // ── netsense: the measured line profile powering smart ranking ──
    private val _networkProfile = MutableStateFlow(
        NetQuality.profileFromJson(prefs.getString("net_profile_v1", null))
    )
    val networkProfile = _networkProfile.asStateFlow()

    fun setNetworkProfile(p: NetworkProfile) {
        _networkProfile.value = p
        prefs.edit().putString("net_profile_v1", NetQuality.profileToJson(p)).apply()
    }

    // ── netsense: last verified results per bucket (WARP / CF-EDGE) so the
    //    smart-pick board can recommend BOTH families at once ──
    private val _savedWarpResults = MutableStateFlow(loadSaved("saved_warp_v1"))
    val savedWarpResults = _savedWarpResults.asStateFlow()

    private val _savedEdgeResults = MutableStateFlow(loadSaved("saved_edge_v1"))
    val savedEdgeResults = _savedEdgeResults.asStateFlow()

    private fun loadSaved(key: String): List<ScanResult> =
        ResultCodec.fromJsonList(prefs.getString(key, null))

    /** Mode of the last completed scan (p_mode is persisted on every start). */
    fun lastScanMode(): ScanMode =
        ScanMode.entries.getOrElse(prefs.getInt("p_mode", 0)) { ScanMode.CF_EDGE }

    /** v3.1.1: wipes BOTH persisted buckets — the clear-board button must
     *  actually clear the board, not just the in-memory list. */
    fun clearSavedResults() {
        _savedWarpResults.value = emptyList()
        _savedEdgeResults.value = emptyList()
        prefs.edit().remove("saved_warp_v1").remove("saved_edge_v1").apply()
    }

    fun saveScanResults(mode: ScanMode, results: List<ScanResult>) {
        val capped = results.take(60)
        when (mode) {
            ScanMode.WARP -> {
                _savedWarpResults.value = capped
                prefs.edit().putString("saved_warp_v1", ResultCodec.toJsonList(capped)).apply()
            }
            else -> { // CF_EDGE + CUSTOM both land in the edge bucket
                _savedEdgeResults.value = capped
                prefs.edit().putString("saved_edge_v1", ResultCodec.toJsonList(capped)).apply()
            }
        }
    }

    fun setAccent(v: Int) { accent.value = v; prefs.edit().putInt("accent", v).apply() }
    fun setAmoled(v: Boolean) { amoled.value = v; prefs.edit().putBoolean("amoled", v).apply() }
    fun setHaptics(v: Boolean) { haptics.value = v; prefs.edit().putBoolean("haptics", v).apply() }
    fun setHighRefresh(v: Boolean) { highRefresh.value = v; prefs.edit().putBoolean("high_refresh", v).apply() }
    fun setLightFx(v: Boolean) { lightFx.value = v; prefs.edit().putBoolean("light_fx", v).apply() }

    fun setAutoUpdate(v: Boolean) { autoUpdate.value = v; prefs.edit().putBoolean("auto_update", v).apply() }
    fun setDismissedUpdateTag(tag: String?) {
        dismissedUpdateTag.value = tag
        prefs.edit().apply { if (tag != null) putString("dismissed_update_tag", tag) else remove("dismissed_update_tag") }.apply()
    }
    fun setLastUpdateCheck(ms: Long) { lastUpdateCheck.value = ms; prefs.edit().putLong("last_update_check", ms).apply() }

    fun saveParams(p: ScanParams) {
        prefs.edit()
            .putInt("p_mode", p.mode.ordinal)
            .putString("p_cidrs", p.cidrs.joinToString("\n"))
            .putInt("p_family", p.family.ordinal)
            .putInt("p_port", p.port)
            .putInt("p_samples", p.samplesPerPrefix)
            .putInt("p_attempts", p.tcpAttempts)
            .putInt("p_timeout", p.tcpTimeoutMs)
            .putInt("p_concurrency", p.concurrency)
            .putBoolean("p_tls", p.tlsVerify)
            .putInt("p_verifyN", p.verifyTopN)
            .putBoolean("p_speed", p.speedTest)
            .putInt("p_speedN", p.speedTopN)
            .putInt("p_dlmb", p.downloadMbLabel)
            .putInt("p_warp", p.warpFlavor.ordinal)
            .putBoolean("p_sweep", p.portSweep)
            .putString("p_sweepports", p.sweepPorts.joinToString(","))
            .putInt("p_speedconc", p.speedConcurrency)
            .putInt("p_warptries", p.warpAttempts)
            .putBoolean("p_noise", p.udpNoise)
            .putInt("p_noisecnt", p.noiseCount)
            .apply()
    }

    fun loadParams(): ScanParams {
        val mode = ScanMode.entries.getOrElse(prefs.getInt("p_mode", 0)) { ScanMode.CF_EDGE }
        val family = NetFamily.entries.getOrElse(prefs.getInt("p_family", 0)) { NetFamily.BOTH }
        val flavor = WarpFlavor.entries.getOrElse(prefs.getInt("p_warp", 0)) { WarpFlavor.WARP }
        val custom = prefs.getString("p_cidrs", "") ?: ""
        val port = prefs.getInt("p_port", Presets.defaultPort(mode)).coerceIn(1, 65535)
        return ScanParams(
            mode = mode,
            cidrs = if (mode == ScanMode.CUSTOM) custom.lines().filter { it.isNotBlank() } else Presets.cidrsFor(mode, family),
            family = family,
            port = port,
            samplesPerPrefix = prefs.getInt("p_samples", 96).coerceIn(10, 5000),
            tcpAttempts = prefs.getInt("p_attempts", 3).coerceIn(1, 10),
            tcpTimeoutMs = prefs.getInt("p_timeout", 2000).coerceIn(300, 8000),
            concurrency = prefs.getInt("p_concurrency", 150).coerceIn(10, 400),
            tlsVerify = prefs.getBoolean("p_tls", true),
            verifyTopN = prefs.getInt("p_verifyN", 1200).coerceIn(50, 2000),
            speedTest = prefs.getBoolean("p_speed", true),
            speedTopN = prefs.getInt("p_speedN", 50).coerceIn(5, 300),
            speedConcurrency = prefs.getInt("p_speedconc", 4).coerceIn(1, 8),
            downloadBytes = (prefs.getInt("p_dlmb", 20).coerceIn(1, 100)).toLong() * 1024 * 1024,
            warpFlavor = flavor,
            portSweep = prefs.getBoolean("p_sweep", false) && mode == ScanMode.WARP,
            sweepPorts = (prefs.getString("p_sweepports", "") ?: "")
                .split(',').mapNotNull { it.trim().toIntOrNull() }
                .filter { it in 1..65535 },
            warpAttempts = prefs.getInt("p_warptries", 3).coerceIn(1, 7),
            udpNoise = prefs.getBoolean("p_noise", true),
            noiseCount = prefs.getInt("p_noisecnt", 5).coerceIn(1, 50),
        )
    }

    companion object {
        val SPEED_MB_CHOICES = listOf(1, 5, 10, 20, 50)
    }
}
