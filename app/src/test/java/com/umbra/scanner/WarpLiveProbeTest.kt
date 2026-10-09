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

    /**
     * v3.6.1: the pinned-IP registration transport (SNI-routed, used when the
     * api domain is DNS-poisoned/filtered) must reach the SAME origin API and
     * yield an identity that performs a REAL handshake — A/B-compared against
     * a domain-route identity on the SAME endpoints at the SAME time (the
     * endpoints flap minute-to-minute; only the comparison is meaningful).
     */
    @Test
    fun `pinned-ip sni-routed registration yields a working identity`() {
        assumeTrue(System.getenv("UMBRA_LIVE_TEST") == "1")
        val (priv, pub) = runBlocking { WarpRegistration.newIdentity() }
        val payload = com.umbra.scanner.net.WarpRegistration.buildPayload(
            android.util.Base64.encodeToString(pub, android.util.Base64.NO_WRAP),
            com.umbra.scanner.net.WarpRegistration.tosTimestamp(),
        )
        val body = com.umbra.scanner.net.ExactIpHttps.postJson(
            IpText.literalToBytes("104.16.192.82")!!, 443, "api.cloudflareclient.com",
            "/v0a4005/reg", payload, "insomnia/8.6.1", 5000, 15000,
        )
        assertTrue("pinned-IP registration must return a body", body != null)
        val pinned = com.umbra.scanner.net.WarpRegistration.parseResponse(body!!, priv, pub)
        assertTrue("pinned-IP registration body must parse into an account", pinned != null)

        // control identity registered through the DOMAIN in the same minute
        val domain: WarpAccount = runBlocking { WarpRegistration.register() }

        val targets = listOf(
            "188.114.96.1" to 2408,
            "162.159.192.1" to 2408,
            "188.114.97.1" to 2408,
            "8.39.214.1" to 2408,
            "162.159.192.42" to 2408,
        )
        val pinnedProbe = WarpProbe(pinned!!, noise = UdpNoiseConfig(enabled = false))
        val domainProbe = WarpProbe(domain, noise = UdpNoiseConfig(enabled = false))
        var pinnedOk = 0
        var domainOk = 0
        for (t in targets) {
            val ip = IpText.literalToBytes(t.first)!!
            val sp = runBlocking { pinnedProbe.probe(ip, t.second, attempts = 1, timeoutMs = 4000, interAttemptDelayMs = 0) }
            val sd = runBlocking { domainProbe.probe(ip, t.second, attempts = 1, timeoutMs = 4000, interAttemptDelayMs = 0) }
            println("PINNED-AB ${t.first}:${t.second} pinned=${sp.handshakes}/${sp.pings} domain=${sd.handshakes}/${sd.pings}")
            pinnedOk += sp.pings; domainOk += sd.pings
        }
        println("PINNED-AB totals pinned=$pinnedOk domain=$domainOk")
        assertTrue(
            "pinned-route identity must handshake somewhere (pinned=$pinnedOk vs domain=$domainOk — " +
                "if domain is also 0 the live network itself is flapping, rerun)",
            pinnedOk > 0,
        )
    }
}
