package com.umbra.scanner.settings

import android.content.Context
import com.umbra.scanner.core.NetFamily
import com.umbra.scanner.core.Presets
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.core.WarpFlavor
import kotlinx.coroutines.flow.MutableStateFlow

class UmbraSettings(context: Context) {

    private val prefs = context.getSharedPreferences("umbra_prefs", Context.MODE_PRIVATE)

    val accent = MutableStateFlow(prefs.getInt("accent", 0))
    val amoled = MutableStateFlow(prefs.getBoolean("amoled", false))
    val haptics = MutableStateFlow(prefs.getBoolean("haptics", true))
    val highRefresh = MutableStateFlow(prefs.getBoolean("high_refresh", true))
    val lightFx = MutableStateFlow(prefs.getBoolean("light_fx", false))

    fun setAccent(v: Int) { accent.value = v; prefs.edit().putInt("accent", v).apply() }
    fun setAmoled(v: Boolean) { amoled.value = v; prefs.edit().putBoolean("amoled", v).apply() }
    fun setHaptics(v: Boolean) { haptics.value = v; prefs.edit().putBoolean("haptics", v).apply() }
    fun setHighRefresh(v: Boolean) { highRefresh.value = v; prefs.edit().putBoolean("high_refresh", v).apply() }
    fun setLightFx(v: Boolean) { lightFx.value = v; prefs.edit().putBoolean("light_fx", v).apply() }

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
            samplesPerPrefix = prefs.getInt("p_samples", 500).coerceIn(10, 5000),
            tcpAttempts = prefs.getInt("p_attempts", 3).coerceIn(1, 10),
            tcpTimeoutMs = prefs.getInt("p_timeout", 2000).coerceIn(300, 8000),
            concurrency = prefs.getInt("p_concurrency", 150).coerceIn(10, 400),
            tlsVerify = prefs.getBoolean("p_tls", true),
            verifyTopN = prefs.getInt("p_verifyN", 80).coerceIn(10, 300),
            speedTest = prefs.getBoolean("p_speed", true),
            speedTopN = prefs.getInt("p_speedN", 50).coerceIn(5, 300),
            speedConcurrency = prefs.getInt("p_speedconc", 4).coerceIn(1, 8),
            downloadBytes = (prefs.getInt("p_dlmb", 20).coerceIn(1, 100)).toLong() * 1024 * 1024,
            warpFlavor = flavor,
            portSweep = prefs.getBoolean("p_sweep", false) && mode == ScanMode.WARP,
            sweepPorts = (prefs.getString("p_sweepports", "") ?: "")
                .split(',').mapNotNull { it.trim().toIntOrNull() }
                .filter { it in 1..65535 },
        )
    }

    companion object {
        val SPEED_MB_CHOICES = listOf(1, 5, 10, 20, 50)
    }
}
