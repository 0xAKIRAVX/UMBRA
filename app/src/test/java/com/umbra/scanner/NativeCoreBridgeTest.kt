package com.umbra.scanner

import android.util.Base64
import com.umbra.scanner.bridge.UmbraCore
import com.umbra.scanner.net.WarpAccount
import com.umbra.scanner.net.WarpRegistration
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * v4: the RUST core through the JNI bridge — the same shim the app loads on
 * device. Robolectric loads the host build (app/src/test/resources/native/
 * libumbra_core.so), so these tests exercise the REAL native code in-process:
 * the x25519/BLAKE2s/ChaCha20-Poly1305 stack, the Noise_IK handshake packet
 * builder, and the UDP probe engine.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class NativeCoreBridgeTest {

    private fun testIdentity(): WarpAccount {
        // deterministic keys via the Kotlin generator (same clamp semantics)
        val (priv, pub) = WarpRegistration.newIdentity(
            kotlin.random.Random(42)
        )
        return WarpAccount(
            privateKey = priv,
            publicKey = pub,
            reserved = byteArrayOf(1, 2, 3),
            v6 = "fd01:db8::2",
            v4 = "172.16.0.2",
            responderPublicKey = Base64.decode(
                "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", Base64.NO_WRAP,
            ),
        )
    }

    @Test
    fun `rust core loads and reports its version`() {
        // skipped when the host .so is absent (non-Linux dev boxes)
        assumeTrue(UmbraCore.loaded)
        val v = UmbraCore.version()
        assertNotNull(v)
        assertTrue(v!!.contains("UMBRA-RUST-CORE"))
    }

    @Test
    fun `config builds and a dead-ip probe returns an honest verdict`() {
        assumeTrue(UmbraCore.loaded)
        val account = testIdentity()
        val cfg = UmbraCore.buildConfig(
            attempts = 1,
            timeoutMs = 500, // dead address → fast verdict
            interMs = 0,
            noise = false,
            identity = UmbraCore.WgIdentity(
                priv = account.privateKey,
                pub = account.publicKey,
                peer = account.responderPublicKey,
                v4 = account.v4,
            ),
            debug = true,
        )
        println("NATIVE cfg = $cfg")
        val res = UmbraCore.probeOnce("203.0.113.1", 2408, cfg) // TEST-NET-3: must be dead
        println("NATIVE raw = ${res}")
        assertNotNull(res)
        assertTrue("raw result: $res · cfg: $cfg", res!!.optBoolean("ok"))
        assertEquals(0, res.optInt("hs", -1))
        // the debug lines narrated the round (probe … budget … timeout)
        val dbg = res.optJSONArray("dbg")
        assertNotNull(dbg)
        assertTrue(dbg!!.length() > 0)
        println("NATIVE dead-probe verdict: ${res.optString("err")}")
    }

    @Test
    fun `tai64n mark round-trips through the rust core`() {
        assumeTrue(UmbraCore.loaded)
        UmbraCore.resetMark()
        assertNull(UmbraCore.mark())
        // a probe with a real timestamp moves the mark
        val account = testIdentity()
        val cfg = UmbraCore.buildConfig(
            attempts = 1, timeoutMs = 300, interMs = 0, noise = false,
            identity = UmbraCore.WgIdentity(
                priv = account.privateKey, pub = account.publicKey,
                peer = account.responderPublicKey, v4 = account.v4,
            ),
        )
        UmbraCore.probeOnce("203.0.113.1", 2408, cfg)
        val mark = UmbraCore.mark()
        assertNotNull(mark)
        assertEquals(12, mark!!.size)
        // restore (ByteArray equality needs assertArrayEquals)
        UmbraCore.loadMark(mark)
        org.junit.Assert.assertArrayEquals(mark, UmbraCore.mark())
        UmbraCore.resetMark()
        assertNull(UmbraCore.mark())
    }

    @Test
    fun `batch scan api refuses bad config and reports idle`() {
        assumeTrue(UmbraCore.loaded)
        assertEquals(-1, UmbraCore.startScan("not json"))
        assertEquals(-1, UmbraCore.startScan("{}")) // missing identity/targets
        assertEquals("[]", UmbraCore.pollEvents())
        assertTrue(!UmbraCore.scanRunning())
    }

    /**
     * LIVE: the RUST core performs a REAL WireGuard handshake + in-tunnel
     * ping against production Cloudflare WARP — the same code path the app
     * runs on device. Gated by UMBRA_LIVE_TEST=1.
     */
    @Test
    fun `rust core completes real handshake and in-tunnel ping`() {
        assumeTrue(System.getenv("UMBRA_LIVE_TEST") == "1")
        assumeTrue(UmbraCore.loaded)
        val account: WarpAccount = runBlocking { WarpRegistration.register() }
        val cfg = UmbraCore.buildConfig(
            attempts = 1,
            timeoutMs = 4000,
            interMs = 0,
            noise = true,
            noiseCount = 3,
            debug = true,
            identity = UmbraCore.WgIdentity(
                priv = account.privateKey,
                pub = account.publicKey,
                peer = account.responderPublicKey,
                v4 = account.v4,
            ),
        )
        var confirmed = false
        for (target in listOf(
            "188.114.96.1" to 2408,
            "162.159.192.1" to 2408,
            "188.114.97.1" to 2408,
            "8.39.214.1" to 2408,
            "162.159.192.42" to 2408,
        )) {
            val res = UmbraCore.probeOnce(target.first, target.second, cfg)
            assertNotNull(res)
            val r: JSONObject = res!!
            println(
                "LIVE-RUST ${target.first}:${target.second} -> " +
                    "hs=${r.optInt("hs")} ping=${r.optInt("png")} " +
                    "rtt=${if (r.isNull("rtt")) "null" else r.optDouble("rtt")} " +
                    "err=${r.optString("err")}"
            )
            r.optJSONArray("dbg")?.let { arr ->
                for (i in 0 until arr.length()) println("   ↳ ${arr.optString(i)}")
            }
            if (r.optInt("png") > 0) {
                confirmed = true
                break
            }
        }
        assertTrue("no endpoint answered the RUST probe with an in-tunnel ping", confirmed)
    }

    /**
     * LIVE: the RUST witness semantics — the seeds answer handshakes on an
     * open network (the pre-flight gate's contract, native side).
     */
    @Test
    fun `rust core witness seeds answer on an open network`() {
        assumeTrue(System.getenv("UMBRA_LIVE_TEST") == "1")
        assumeTrue(UmbraCore.loaded)
        val account: WarpAccount = runBlocking { WarpRegistration.register() }
        val cfg = UmbraCore.buildConfig(
            attempts = 2, timeoutMs = 4000, interMs = 250, noise = false,
            identity = UmbraCore.WgIdentity(
                priv = account.privateKey, pub = account.publicKey,
                peer = account.responderPublicKey, v4 = account.v4,
            ),
        )
        var answered = 0
        // seeds + the census extras: anycast endpoints flap minute-to-minute
        // (the live census documented 2408 going dark for stretches) — one
        // answering endpoint proves the path, exactly like the gate contract.
        val targets = com.umbra.scanner.core.Presets.WARP_SEED_ENDPOINTS +
            listOf(
                "188.114.96.1" to 2408,
                "162.159.192.1" to 2408,
                "188.114.97.1" to 2408,
                "8.39.214.1" to 2408,
                "162.159.192.42" to 2408,
            )
        for (target in targets.distinct()) {
            val res = UmbraCore.probeOnce(target.first, target.second, cfg)
            if (res != null && (res.optInt("hs") > 0 || res.optInt("ck") > 0)) answered++
            println(
                "SEED-RUST ${target.first}:${target.second} -> " +
                    "hs=${res?.optInt("hs") ?: "?"} err=${res?.optString("err") ?: "?"}"
            )
        }
        assertTrue("expected at least one seed to answer the native probe ($answered did)", answered > 0)
    }
}
