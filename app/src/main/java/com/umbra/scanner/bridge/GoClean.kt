package com.umbra.scanner.bridge

import com.umbra.scanner.goclean.goclean.Goclean as NativeGoClean
import org.json.JSONArray
import org.json.JSONObject

/**
 * Bridge to the UMBRA Go engine (native/goclean, embedded as goclean.aar)
 * — the CLEAN-IP scanner: TCP latency + TLS/trace verification + HTTPS
 * download speed against Cloudflare anycast ranges.
 *
 * The Go engine emits the same compact JSON event protocol as the Rust
 * core; Kotlin pumps events through [poll] and dispatches them.
 */
object GoClean {

    /** True when the gomobile runtime + engine classes are live. */
    @Volatile var loaded: Boolean = false
        private set

    init {
        loaded = try {
            // touching the class forces libgojni.so to load
            Class.forName("com.umbra.scanner.goclean.goclean.Goclean")
            true
        } catch (t: Throwable) {
            false
        }
    }

    fun version(): String? =
        if (loaded) NativeGoClean.Version else null

    /** 0 ok | 1 busy | -1 bad config. */
    fun startScan(configJson: String): Int =
        if (loaded) NativeGoClean.startScan(configJson).toInt() else -1

    /** Drains pending events as a JSON array string ("[]" when idle). */
    fun pollEvents(): String? =
        if (loaded) NativeGoClean.pollEvents() else null

    fun cancelScan() {
        if (loaded) NativeGoClean.cancelScan()
    }

    fun scanRunning(): Boolean = loaded && NativeGoClean.running()

    /**
     * Deep probe of one ip:port (TCP + TLS + trace + speed) — the debug
     * system's single-endpoint lens for CLEAN-IP mode.
     */
    fun probeOnce(ip: String, port: Int, configJson: String): JSONObject? {
        if (!loaded) return null
        val s = NativeGoClean.probeOnce(ip, port.toLong(), configJson)
        return runCatching { JSONObject(s) }.getOrNull()
    }

    /** Config builder matching the Go parser. */
    fun buildConfig(
        cidrs: List<String>,
        ports: List<Int>,
        samples: Int,
        attempts: Int = 3,
        timeoutMs: Int = 2000,
        lanes: Int = 200,
        verifyTop: Int = 100,
        speedTop: Int = 20,
        speedBytes: Long = 10L * 1024 * 1024,
        speedConcurrency: Int = 4,
        sni: String = "speed.cloudflare.com",
        debug: Boolean = false,
    ): String {
        val o = JSONObject()
        o.put("cidrs", stringArray(cidrs))
        o.put("ports", intArray(ports))
        o.put("samples", samples)
        o.put("attempts", attempts)
        o.put("timeout_ms", timeoutMs)
        o.put("lanes", lanes)
        o.put("verify_top", verifyTop)
        o.put("speed_top", speedTop)
        o.put("speed_bytes", speedBytes)
        o.put("speed_concurrency", speedConcurrency)
        o.put("sni", sni)
        o.put("debug", debug)
        return o.toString()
    }

    private fun stringArray(items: List<String>): JSONArray {
        val a = JSONArray()
        items.forEach { a.put(it) }
        return a
    }

    private fun intArray(items: List<Int>): JSONArray {
        val a = JSONArray()
        items.forEach { a.put(it) }
        return a
    }
}
