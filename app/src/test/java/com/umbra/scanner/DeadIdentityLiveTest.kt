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
 * LIVE EXPERIMENT (v3.6.1 design input): does a Cloudflare WARP responder
 * answer a handshake initiation for a key that was NEVER registered?
 *
 * WireGuard responders are supposed to silently drop initiations from unknown
 * static keys (anti-enumeration). If that holds for WARP, a server-side-dead
 * identity produces EXACTLY the "silent total failure" the user reports on
 * API-blocked networks (where the disk identity is the only one available).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class DeadIdentityLiveTest {

    @Test
    fun `unregistered key is silently dropped by production warp`() {
        assumeTrue(System.getenv("UMBRA_LIVE_TEST") == "1")
        // register a REAL account (also gives us the true responder key)
        val real: WarpAccount = runBlocking { WarpRegistration.register() }
        assertTrue(real.responderPublicKey.size == 32)

        // now forge an identity that was never registered with CF:
        // fresh random static key, but the REAL responder (server) key
        val (priv, pub) = runBlocking { WarpRegistration.newIdentity() }
        val ghost = WarpAccount(
            privateKey = priv,
            publicKey = pub,
            reserved = real.reserved,
            v6 = real.v6,
            v4 = real.v4,
            responderPublicKey = real.responderPublicKey,
        )

        val probe = WarpProbe(ghost, noise = UdpNoiseConfig(enabled = false))
        for (target in listOf(
            "162.159.192.1" to 2408,
            "188.114.96.1" to 2408,
            "162.159.193.10" to 2408,
            "188.114.97.1" to 2408,
            "8.39.214.1" to 2408,
        )) {
            val ip = IpText.literalToBytes(target.first)!!
            val stats = runBlocking {
                probe.probe(ip, target.second, attempts = 2, timeoutMs = 4000, interAttemptDelayMs = 300)
            }
            println("GHOST ${target.first}:${target.second} -> " +
                "handshake=${stats.handshakes} ping=${stats.pings} " +
                "cookie=${stats.cookieReplies} err=${stats.lastError}")
        }

        // control: the REAL identity must still pass somewhere (multi-endpoint)
        val probe2 = WarpProbe(real, noise = UdpNoiseConfig(enabled = false))
        var controlPings = 0
        for (target in listOf(
            "162.159.192.1" to 2408,
            "188.114.96.1" to 2408,
            "162.159.193.10" to 2408,
            "188.114.97.1" to 2408,
            "8.39.214.1" to 2408,
        )) {
            val ip = IpText.literalToBytes(target.first)!!
            val stats2 = runBlocking {
                probe2.probe(ip, target.second, attempts = 2, timeoutMs = 4000, interAttemptDelayMs = 300)
            }
            println("CONTROL ${target.first}:${target.second} -> handshake=${stats2.handshakes} ping=${stats2.pings} err=${stats2.lastError}")
            controlPings += stats2.pings
        }
        assertTrue("control failed on every endpoint — live network itself is down", controlPings > 0)
    }
}
