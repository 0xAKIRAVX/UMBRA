package com.umbra.scanner

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.umbra.scanner.core.IpProtocol
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.core.ScanResult
import com.umbra.scanner.engine.ScanController
import com.umbra.scanner.settings.UmbraSettings
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * v3.1.1 regression: the persisted smart-pick buckets (saved_warp_v1 /
 * saved_edge_v1) were written on every scan but NEVER read back on a fresh
 * process — the results tab showed "NO SCAN DATA YET" after every app restart.
 * A fresh ScanController must now hydrate the board from the last mode's
 * bucket, and clearResults() must wipe the buckets for real.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ResultsRestoreTest {

    private lateinit var settings: UmbraSettings

    private fun warpResult(ip: String) = ScanResult(
        ip = ip, protocol = IpProtocol.IPv4, port = 2408,
        latencyMs = 50.0, jitterMs = 4.0, packetLoss = 0.0,
        tcpAttempts = 3, successfulAttempts = 2, wgHandshakes = 3,
        mode = ScanMode.ENDPOINT,
    )

    private fun edgeResult(ip: String) = ScanResult(
        ip = ip, protocol = IpProtocol.IPv4, port = 443,
        latencyMs = 40.0, jitterMs = 3.0, packetLoss = 0.0,
        tcpAttempts = 3, successfulAttempts = 3, tlsSuccess = true,
        mode = ScanMode.CF_EDGE,
    )

    @Before
    fun clean() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        ctx.getSharedPreferences("umbra_prefs", Context.MODE_PRIVATE).edit().clear().commit()
        settings = UmbraSettings(ctx)
    }

    @Test
    fun `fresh controller hydrates warp bucket after restart`() {
        settings.saveParams(ScanParams(mode = ScanMode.ENDPOINT))
        settings.saveScanResults(ScanMode.ENDPOINT, listOf(warpResult("162.159.192.1"), warpResult("188.114.96.4")))

        val controller = ScanController(settings) // simulates a fresh process
        assertEquals(2, controller.results.value.size)
        assertEquals("162.159.192.1", controller.results.value.first().ip)
        assertTrue(controller.results.value.all { it.alive })
        assertEquals(2, controller.top.value.size) // top-5 board cap, 2 available
    }

    @Test
    fun `fresh controller hydrates edge bucket after restart`() {
        // p_mode defaults to CF_EDGE (0) — no saveParams needed
        settings.saveScanResults(ScanMode.CF_EDGE, listOf(edgeResult("104.16.1.1")))

        val controller = ScanController(settings)
        assertEquals(1, controller.results.value.size)
        assertEquals("104.16.1.1", controller.results.value.first().ip)
    }

    @Test
    fun `no saved results leave the board empty`() {
        val controller = ScanController(settings)
        assertTrue(controller.results.value.isEmpty())
    }

    @Test
    fun `clear results wipes both persisted buckets`() {
        settings.saveParams(ScanParams(mode = ScanMode.ENDPOINT))
        settings.saveScanResults(ScanMode.ENDPOINT, listOf(warpResult("162.159.192.1")))
        settings.saveScanResults(ScanMode.CF_EDGE, listOf(edgeResult("104.16.1.1")))

        val controller = ScanController(settings)
        assertEquals(1, controller.results.value.size)
        controller.clearResults()

        assertTrue(controller.results.value.isEmpty())
        assertTrue(settings.savedWarpResults.value.isEmpty())
        assertTrue(settings.savedEdgeResults.value.isEmpty())

        // a brand-new controller (next launch) must stay empty too
        assertTrue(ScanController(settings).results.value.isEmpty())
    }

    @Test
    fun `restart after clear does not resurrect results`() {
        settings.saveParams(ScanParams(mode = ScanMode.ENDPOINT))
        settings.saveScanResults(ScanMode.ENDPOINT, listOf(warpResult("162.159.192.1")))
        ScanController(settings).clearResults()
        assertEquals(0, ScanController(settings).results.value.size)
    }
}
