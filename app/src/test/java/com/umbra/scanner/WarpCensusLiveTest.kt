package com.umbra.scanner

import com.umbra.scanner.core.IpText
import com.umbra.scanner.net.UdpNoiseConfig
import com.umbra.scanner.net.WarpAccount
import com.umbra.scanner.net.WarpProbe
import com.umbra.scanner.net.WarpRegistration
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * LIVE census of WARP endpoint liveness across the pool ranges — design input
 * for seed refresh + mini-storm (v3.6.1). Probes 3 IPs per pool prefix on the
 * canonical port plus a port spread on one representative IP.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class WarpCensusLiveTest {

    @Test
    fun `census of warp pool liveness`() {
        assumeTrue(System.getenv("UMBRA_LIVE_TEST") == "1")
        val account: WarpAccount = runBlocking { WarpRegistration.register() }
        val probe = WarpProbe(account, noise = UdpNoiseConfig(enabled = false))

        data class T(val ip: String, val port: Int)

        val targets = buildList {
            // 3 IPs from each v4 prefix family
            listOf(
                "162.159.192.7", "162.159.192.42", "162.159.192.100",
                "162.159.193.5", "162.159.193.77",
                "162.159.195.11", "162.159.198.9", "162.159.199.21",
                "188.114.96.1", "188.114.96.60", "188.114.97.1", "188.114.98.1", "188.114.99.1",
                "8.34.146.1", "8.34.146.44",
                "8.39.214.1", "8.39.204.1", "8.6.112.1", "8.35.211.1", "8.39.125.1", "8.47.69.1",
            ).forEach { add(T(it, 2408)) }
            // port spread on a known-answering IP
            listOf(894, 443, 500, 928, 1843, 4500, 1701, 878, 2408).forEach { add(T("188.114.96.1", it)) }
            // also spread on 162.159.192.1 to double-check seed staleness
            listOf(894, 443, 928, 2408).forEach { add(T("162.159.192.1", it)) }
        }

        val results = runBlocking {
            coroutineScope {
                targets.map { t ->
                    async(Dispatchers.IO) {
                        val ip = IpText.literalToBytes(t.ip)!!
                        val s = probe.probe(ip, t.port, attempts = 1, timeoutMs = 3500, interAttemptDelayMs = 0)
                        Triple(t, s.handshakes + s.pings + s.cookieReplies, s.lastError)
                    }
                }.awaitAll()
            }
        }
        var alive = 0
        for ((t, ans, err) in results) {
            val mark = if (ans > 0) "ALIVE" else "dead "
            if (ans > 0) alive++
            println("CENSUS ${t.ip}:${t.port} $mark err=$err")
        }
        println("CENSUS total alive: $alive / ${targets.size}")
    }
}
