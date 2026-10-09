package com.umbra.scanner

import android.app.Application
import com.umbra.scanner.core.ResultCodec
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.core.ScanUi
import com.umbra.scanner.engine.CrashGuard
import com.umbra.scanner.engine.ScanController
import com.umbra.scanner.net.NetQuality
import com.umbra.scanner.net.NetworkProfile
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/**
 * v3.5.2 — regression tests for the zombie-scan fix and the NaN-proof codecs.
 *
 * The user's screenshot showed the exact failure: an engine Error
 * (NoClassDefFoundError from the v3.5.0 BigInteger.TWO bug) was journaled by
 * the CEH net, but the scanJob's catch only handled Exception — finalize()
 * never ran and the session stayed Running FOREVER (progress stuck, elapsed
 * ticking, ongoing notification, STOP a silent no-op on the dead job).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [30])
class Patch52Test {

    private fun app(): Application = RuntimeEnvironment.getApplication() as Application

    private fun cleanup() {
        CrashGuardTestAccess.reset()
        CrashGuard.clear()
    }

    // ------------------------------------------------------ zombie fix ----

    @Test
    fun `engine Error fails the session instead of staying zombie Running`() {
        CrashGuardTestAccess.reset()
        CrashGuard.install(app())
        CrashGuard.clear()
        try {
            val controller = ScanController()
            controller.debugInjectState(
                uiState = ScanUi.Running(ScanParams(), System.currentTimeMillis()),
                paramsValue = ScanParams(mode = ScanMode.ENDPOINT),
            )
            // the exact crash from the user's device log
            controller.engineRunner = { _, _ -> throw NoClassDefFoundError("v1.W") }
            controller.launchScan()

            val deadline = System.currentTimeMillis() + 10_000
            while (controller.ui.value is ScanUi.Running && System.currentTimeMillis() < deadline) {
                Thread.sleep(20)
            }
            val state = controller.ui.value
            assertTrue("session must leave Running — was $state", state is ScanUi.Done)
            val done = state as ScanUi.Done

            // the reason is stated honestly in the log AND the Done panel
            val line = controller.log.value.firstOrNull { it.contains("engine failure") }
            assertNotNull("engine-failure log line missing", line)
            assertTrue(line!!.contains("NoClassDefFoundError"))
            assertNotNull("Done summary must carry the reason", done.summary.error)

            // full stack trace journaled for the CRASH LOG card
            val entry = CrashGuard.recentCrashes().firstOrNull { it.contains("NoClassDefFoundError") }
            assertNotNull("crash journal entry missing", entry)
            assertTrue("journal entry must name the scan-engine scope", entry!!.contains("coroutine[scan-engine]"))
        } finally {
            cleanup()
        }
    }

    @Test
    fun `stop scan on a dead engine closes the session instead of no-op`() {
        val controller = ScanController()
        controller.debugInjectState(
            uiState = ScanUi.Running(ScanParams(), 0L),
            paramsValue = ScanParams(),
        )
        // engine never launched — scanJob is null; the old stopScan() was a
        // silent no-op and the Running screen never ended
        controller.stopScan()
        val state = controller.ui.value
        assertTrue("stop must end the zombie session — was $state", state is ScanUi.Done)
        val done = state as ScanUi.Done
        assertTrue(done.summary.cancelled)
    }

    @Test
    fun `stop scan cancels a live engine cooperatively`() {
        val controller = ScanController()
        controller.debugInjectState(
            uiState = ScanUi.Running(ScanParams(), System.currentTimeMillis()),
            paramsValue = ScanParams(),
        )
        var entered = false
        controller.engineRunner = { _, _ ->
            entered = true
            try {
                delay(30_000)
            } catch (e: CancellationException) {
                throw e
            }
        }
        controller.launchScan()

        val started = System.currentTimeMillis() + 10_000
        while (!entered && System.currentTimeMillis() < started) Thread.sleep(10)

        controller.stopScan()

        val deadline = System.currentTimeMillis() + 10_000
        while (controller.ui.value is ScanUi.Running && System.currentTimeMillis() < deadline) {
            Thread.sleep(20)
        }
        val state = controller.ui.value
        assertTrue("cancelled scan must reach Done — was $state", state is ScanUi.Done)
        val done = state as ScanUi.Done
        assertTrue(done.summary.cancelled)
    }

    // ----------------------------------------------------- NaN-proofing ----

    @Test
    fun `profileFromJson reads missing or corrupt doubles as unknown, never NaN`() {
        val p = requireNotNull(NetQuality.profileFromJson("""{"packetLoss":"corrupt"}""")) { "profile must parse" }
        assertNull(p.latencyMs)
        assertNull(p.jitterMs)
        assertNull(p.tlsRttMs)
        assertNull(p.downloadMbps)
        assertNull(p.uploadMbps)
        assertEquals(0.0, p.packetLoss, 1e-9)
        // a NaN baseline must never poison SmartRanking's relative latency
        assertTrue(p.latencyMs == null)
    }

    @Test
    fun `profileFromJson round-trip keeps real values`() {
        val q = NetworkProfile(
            latencyMs = 42.5, jitterMs = 3.25, packetLoss = 0.02,
            tlsRttMs = 90.0, downloadMbps = 11.0, uploadMbps = 4.0, v6Ok = true,
        )
        val rt = requireNotNull(NetQuality.profileFromJson(NetQuality.profileToJson(q))) { "round-trip must parse" }
        assertEquals(42.5, rt.latencyMs!!, 1e-9)
        assertEquals(3.25, rt.jitterMs!!, 1e-9)
        assertEquals(0.02, rt.packetLoss, 1e-9)
        assertEquals(90.0, rt.tlsRttMs!!, 1e-9)
        assertEquals(11.0, rt.downloadMbps!!, 1e-9)
        assertEquals(4.0, rt.uploadMbps!!, 1e-9)
        assertTrue(rt.v6Ok)
    }

    @Test
    fun `ResultCodec corrupt doubles read as null not NaN`() {
        val o = JSONObject()
            .put("ip", "1.1.1.1")
            .put("lat", "oops")
            .put("jit", JSONObject.NULL)
            .put("spd", 3.5)
        val r = requireNotNull(ResultCodec.fromJson(o)) { "result must parse" }
        assertNull(r.latencyMs)
        assertNull(r.jitterMs)
        assertEquals(3.5, r.speedMbps!!, 1e-9)
    }

    @Test
    fun `CrashGuard record journals a handled throwable with stack trace`() {
        CrashGuardTestAccess.reset()
        CrashGuard.install(app())
        CrashGuard.clear()
        try {
            CrashGuard.record("scan-engine", IllegalStateException("boom-marker"))
            val e = requireNotNull(CrashGuard.recentCrashes().firstOrNull()) { "journal must not be empty" }
            assertTrue(e.contains("IllegalStateException"))
            assertTrue(e.contains("boom-marker"))
            assertTrue(e.contains("coroutine[scan-engine]"))
        } finally {
            cleanup()
        }
    }
}
