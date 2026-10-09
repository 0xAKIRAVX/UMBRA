package com.umbra.scanner

import com.umbra.scanner.core.IpText
import com.umbra.scanner.net.UdpNoiseConfig
import com.umbra.scanner.net.WarpAccount
import com.umbra.scanner.net.WarpProbe
import com.umbra.scanner.net.WarpRegistration
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * LIVE end-to-end validation of the Kotlin WARP probe against production
 * Cloudflare endpoints. Runs only when UMBRA_LIVE_TEST=1 is set (it hits the
 * real registration API and the real WARP network — never in CI).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class WarpLiveProbeTest {

    @Test
    fun `kotlin probe completes real handshake and in-tunnel ping`() {
        assumeTrue(System.getenv("UMBRA_LIVE_TEST") == "1")
        val account: WarpAccount = runBlocking { WarpRegistration.register() }
        assertTrue(account.reserved.size in 1..8)
        assertTrue(account.responderPublicKey.size == 32)

        val probe = WarpProbe(account, noise = UdpNoiseConfig(enabled = true))
        var confirmed = false
        // try a few known-live endpoints; any one full success proves the port
        for (target in listOf(
            "188.114.96.1" to 2408,
            "162.159.192.1" to 2408,
            "188.114.97.1" to 2408,
            "8.39.214.1" to 2408,
            "162.159.193.10" to 2408,
        )) {
            val ip = IpText.literalToBytes(target.first)!!
            val stats = runBlocking {
                probe.probe(ip, target.second, attempts = 1, timeoutMs = 4000,
                    interAttemptDelayMs = 0)
            }
            println("LIVE ${target.first}:${target.second} -> " +
                "handshake=${stats.handshakes} ping=${stats.pings} " +
                "rtt=${stats.pingLatenciesMs} err=${stats.lastError}")
            if (stats.pings > 0) {
                confirmed = true
                break
            }
        }
        assertTrue("no endpoint answered the Kotlin probe with an in-tunnel ping", confirmed)
    }

    @Test
    fun `warp gate verifies the path pre-flight`() {
        assumeTrue(System.getenv("UMBRA_LIVE_TEST") == "1")
        val account: WarpAccount = runBlocking { WarpRegistration.register() }
        val logs = ArrayList<String>()
        val out = runBlocking {
            com.umbra.scanner.engine.WarpGate.check(account, 2408, 4000) { logs.add(it) }
        }
        logs.forEach { println("GATE: $it") }
        println("GATE OUTCOME: $out")
        assertTrue("expected Ok on an open network, got $out", out is com.umbra.scanner.engine.WarpGate.Outcome.Ok)
    }
}
