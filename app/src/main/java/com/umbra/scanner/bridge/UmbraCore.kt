package com.umbra.scanner.bridge

import android.util.Base64
import org.json.JSONObject

/**
 * JNI bridge to the UMBRA Rust core (native/umbra-core) — the WireGuard
 * handshake + UDP endpoint probe engine.
 *
 * The library ships for every ABI (arm64-v8a, armeabi-v7a, x86_64) and for
 * the JVM host build under app/src/test/resources/native (Robolectric loads
 * the same symbols in-process, so live tests exercise the REAL native code).
 *
 * The API is deliberately tiny and poll-based (Rust never calls the JVM):
 *   startScan(configJson)  — batch scan (Rust thread pool)
 *   pollEvents()           — drain events (log/dbg/res/prg/fin)
 *   probeOnce(ip, port, configJson) — deep-debug single endpoint
 */
object UmbraCore {

    @Volatile var loaded: Boolean = false
        private set

    init {
        loaded = try {
            System.loadLibrary("umbra_core")
            true
        } catch (t: Throwable) {
            // host JVM (unit tests) loads from resources/native instead
            try {
                val cl = UmbraCore::class.java.classLoader
                // .so files are filtered from unit-test java resources by AGP,
                // so the host build ships as "umbra_core_host.so.bin".
                val res = cl?.getResourceAsStream("native/umbra_core_host.so.bin")
                    ?: cl?.getResourceAsStream("native/libumbra_core.so")
                if (res != null) {
                    val tmp = kotlin.io.path.createTempFile("libumbra_core", ".so")
                    tmp.toFile().deleteOnExit()
                    res.use { input ->
                        java.nio.file.Files.copy(
                            input, tmp,
                            java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                        )
                    }
                    System.load(tmp.toFile().absolutePath)
                    true
                } else {
                    println("UMBRA_CORE: resource native/libumbra_core.so not on classpath · " +
                    "vectors=" + (UmbraCore::class.java.classLoader?.getResource("warp_vectors.json") != null) +
                    " · native=" + (UmbraCore::class.java.classLoader?.getResource("native/libumbra_core.so") != null))
                    false
                }
            } catch (t2: Throwable) {
                println("UMBRA_CORE: host load failed: ${t2.javaClass.simpleName}: ${t2.message}")
                false
            }
        }
    }

    /** Rust core version string (null when the native lib is unavailable). */
    fun version(): String? =
        if (loaded) nativeVersion() else null

    // ------------------------------------------------------------------
    // batch scan API

    /** 0 ok | 1 busy | -1 bad config. */
    fun startScan(configJson: String): Int {
        if (!loaded) return -1
        return nativeStart(configJson.toByteArray(Charsets.UTF_8))
    }

    /** Drains pending events; null/empty when idle. */
    fun pollEvents(): String? {
        if (!loaded) return null
        val bytes = nativePoll()
        if (bytes == null || bytes.isEmpty()) return null
        return String(bytes, Charsets.UTF_8)
    }

    fun cancelScan() {
        if (loaded) nativeCancel()
    }

    fun scanRunning(): Boolean = loaded && nativeRunning()

    /**
     * Deep-debug probe of ONE endpoint: full WG handshake rounds with
     * per-round debug lines (packet sizes, hex previews, timings).
     * Returns a JSON object or null when the core is unavailable.
     */
    fun probeOnce(ip: String, port: Int, configJson: String): JSONObject? {
        if (!loaded) return null
        val bytes = nativeProbeOnce(ip, port, configJson.toByteArray(Charsets.UTF_8))
        if (bytes == null || bytes.isEmpty()) return null
        return runCatching { JSONObject(String(bytes, Charsets.UTF_8)) }.getOrNull()
    }

    /** The TAI64N high-water mark (anti-replay persistence across restarts). */
    fun mark(): ByteArray? =
        if (loaded) nativeGetMark()?.takeIf { it.isNotEmpty() } else null

    fun resetMark() {
        if (loaded) nativeResetMark()
    }

    /** Restores a persisted mark into the Rust core (once per scan start). */
    fun loadMark(mark: ByteArray) {
        if (loaded && mark.size == 12) nativeLoadMark(mark)
    }

    // ------------------------------------------------------------------
    // config builder — the exact JSON the Rust parser expects

    fun buildConfig(
        attempts: Int,
        timeoutMs: Int,
        interMs: Int = 200,
        noise: Boolean = true,
        noiseCount: Int = 5,
        lanes: Int = 128,
        debug: Boolean = false,
        markB64: String? = null,
        markReset: Boolean = false,
        identity: WgIdentity? = null,
        ping: String = "1.1.1.1",
    ): String {
        val o = JSONObject()
        if (identity != null) {
            o.put(
                "identity",
                JSONObject()
                    .put("priv", Base64.encodeToString(identity.priv, Base64.NO_WRAP))
                    .put("pub", Base64.encodeToString(identity.pub, Base64.NO_WRAP))
                    .put("peer", Base64.encodeToString(identity.peer, Base64.NO_WRAP))
                    .put("v4", identity.v4),
            )
        }
        o.put("attempts", attempts)
        o.put("timeout_ms", timeoutMs)
        o.put("inter_ms", interMs)
        o.put("noise", noise)
        o.put("noise_count", noiseCount)
        o.put("lanes", lanes)
        o.put("debug", debug)
        o.put("ping", ping)
        if (markB64 != null) o.put("mark", markB64)
        if (markReset) o.put("mark_reset", true)
        return o.toString()
    }

    /** WG identity as the Rust core wants it (raw 32-byte keys). */
    data class WgIdentity(
        val priv: ByteArray,
        val pub: ByteArray,
        val peer: ByteArray,
        val v4: String,
    )

    // ------------------------------------------------------------------
    // native surface (jni/shim.c)

    private external fun nativeVersion(): String?
    private external fun nativeStart(cfg: ByteArray): Int
    private external fun nativePoll(): ByteArray?
    private external fun nativeCancel()
    private external fun nativeRunning(): Boolean
    private external fun nativeProbeOnce(ip: String, port: Int, cfg: ByteArray): ByteArray?
    private external fun nativeGetMark(): ByteArray?
    private external fun nativeResetMark()
    private external fun nativeLoadMark(mark: ByteArray)
}
