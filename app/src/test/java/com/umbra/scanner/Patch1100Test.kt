package com.umbra.scanner

import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.core.ScanPhase
import com.umbra.scanner.core.ScanResult
import com.umbra.scanner.core.ScanUi
import com.umbra.scanner.core.NetFamily
import com.umbra.scanner.engine.ScanEngine
import com.umbra.scanner.engine.ScanController
import com.umbra.scanner.engine.ScanSink
import com.umbra.scanner.net.NetworkProfile
import com.umbra.scanner.net.UdpEvidence
import com.umbra.scanner.net.WarpAccount
import com.umbra.scanner.settings.UmbraSettings
import com.umbra.scanner.ui.screens.clampToSlider
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * v3.11 regression tests — the "make it completely bug-free" polish pass.
 *
 * Guards the exact defects fixed in this release:
 *
 *  1. MASKED ZERO-RESULT DIAGNOSIS: finalize() read the Done-panel error from
 *     the newest log line AFTER appending "net profile · …" — on any device
 *     that had ever run NETSENSE, a zero-result scan showed the net-profile
 *     line instead of the engine's verdict (the product's core honesty
 *     feature silently skipped). The error line is now captured BEFORE the
 *     profile line is appended.
 *  2. DANGLING SEPARATOR: evidenceDiagnosis() returned parts joined with a
 *     LEADING " · " — the standalone gate-abort log line started with " · "
 *     (and an empty line was logged when no evidence existed). Now: parts
 *     joined bare, callers add their own separator, empty ⇒ not logged.
 *  3. HIDDEN FAMILY FILTER: CUSTOM mode rendered no family selector while
 *     params.family silently filtered the pasted CIDR list — the selector is
 *     now visible in every mode (UI change; the generator contract itself is
 *     pinned by IpGenerator/Cidr tests).
 *  4. OUT-OF-RANGE SLIDERS: loadParams clamps into the ENGINE ranges
 *     (timeout 300..8000, samples 10..5000) but the UI sliders draw narrower
 *     boxes — clampToSlider now clamps every slider init into its own box.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class Patch1100Test {

    private class RecordingSink : ScanSink {
        val phases = ArrayList<ScanPhase>()
        val logs = ArrayList<String>()
        val results = ArrayList<ScanResult>()
        var generated = 0
        override fun onPhase(phase: ScanPhase) { phases.add(phase) }
        override fun onGenerated(count: Int) { generated = count }
        override fun onResult(result: ScanResult) { results.add(result) }
        override fun onActive(delta: Int) {}
        override fun onLog(line: String) { logs.add(line) }
        override fun snapshot(): List<ScanResult> = ArrayList(results)
    }

    private fun fakeAccount(seed: Int = 0): WarpAccount = WarpAccount(
        privateKey = ByteArray(32) { (it + seed).toByte() },
        publicKey = ByteArray(32) { (it + seed + 1).toByte() },
        reserved = byteArrayOf(1, 2, 3),
        v6 = "2606:4700:d111:222:333:444:555:666",
        v4 = "172.16.0.2",
        responderPublicKey = ByteArray(32) { (it + seed + 7).toByte() },
    )

    private fun endpointParams(count: Int = 4) = ScanParams(
        mode = ScanMode.ENDPOINT,
        family = NetFamily.V4,
        port = 0,
        endpointsCount = count,
        warpAttempts = 1,
        tcpTimeoutMs = 300,
        concurrency = 150,
        udpNoise = false,
        speedTest = false,
    )

    // ── fix 1: the zero-result Done panel shows the ENGINE verdict ─────────

    @Test
    fun `zero-result done panel carries the engine verdict - not the net profile line`() {
        val ctx = androidx.test.core.app.ApplicationProvider.getApplicationContext<android.content.Context>()
        ctx.getSharedPreferences("umbra_prefs", android.content.Context.MODE_PRIVATE)
            .edit().clear().commit()
        val settings = UmbraSettings(ctx)
        // the masked-diagnosis precondition: a NETSENSE profile EXISTS (persisted)
        settings.setNetworkProfile(
            NetworkProfile(latencyMs = 42.0, jitterMs = 3.0, packetLoss = 0.0, v6Ok = true)
        )
        val controller = ScanController(settings)
        controller.debugInjectState(
            uiState = ScanUi.Running(ScanParams(), System.currentTimeMillis()),
            paramsValue = endpointParams(count = 4),
        )
        controller.engineRunner = { _, sink ->
            // a zero-result endpoint scan: the engine's honest last word
            sink.onPhase(ScanPhase.GENERATING)
            sink.onGenerated(4)
            sink.onPhase(ScanPhase.WG)
            sink.onLog("endpoint scan done · 0 validated of 4 (v4 0 · v6 0 · handshakes 0 · in-tunnel pings 0) — handshake timeout ×4")
            sink.onPhase(ScanPhase.DONE)
        }
        controller.launchScan()

        val deadline = System.currentTimeMillis() + 10_000
        while (controller.ui.value is ScanUi.Running && System.currentTimeMillis() < deadline) {
            Thread.sleep(20)
        }
        val state = controller.ui.value
        assertTrue("session must reach Done — was $state", state is ScanUi.Done)
        val done = state as ScanUi.Done

        // THE contract: the Done panel carries the engine's diagnosis…
        assertNotNull("zero-result Done must carry an error", done.summary.error)
        assertTrue(
            "Done error must be the engine verdict — was ${done.summary.error}",
            done.summary.error!!.contains("endpoint scan done") &&
                done.summary.error!!.contains("handshake timeout ×4"),
        )
        // …never the net-profile card's own log line
        assertFalse(
            "the net-profile line must not mask the diagnosis",
            done.summary.error!!.contains("net profile"),
        )
        // the profile line itself is still logged (unchanged behavior)
        assertTrue(controller.log.value.any { it.contains("net profile") })
    }

    @Test
    fun `healthy scan done panel stays error-free even with a net profile`() {
        val ctx = androidx.test.core.app.ApplicationProvider.getApplicationContext<android.content.Context>()
        ctx.getSharedPreferences("umbra_prefs", android.content.Context.MODE_PRIVATE)
            .edit().clear().commit()
        val settings = UmbraSettings(ctx)
        settings.setNetworkProfile(NetworkProfile(latencyMs = 42.0))
        val controller = ScanController(settings)
        controller.debugInjectState(
            uiState = ScanUi.Running(ScanParams(), System.currentTimeMillis()),
            paramsValue = endpointParams(count = 2),
        )
        controller.engineRunner = { _, sink ->
            sink.onGenerated(2)
            sink.onResult(
                ScanResult(
                    ip = "188.114.96.1", protocol = com.umbra.scanner.core.IpProtocol.IPv4,
                    port = 2408, latencyMs = 6.0, wgHandshakes = 1,
                    mode = ScanMode.ENDPOINT,
                )
            )
            sink.onLog("endpoint scan done · 1 validated of 2")
            sink.onPhase(ScanPhase.DONE)
        }
        controller.launchScan()

        val deadline = System.currentTimeMillis() + 10_000
        while (controller.ui.value is ScanUi.Running && System.currentTimeMillis() < deadline) {
            Thread.sleep(20)
        }
        val done = controller.ui.value as ScanUi.Done
        assertEquals(1, done.summary.alive)
        assertEquals(null, done.summary.error)
    }

    // ── fix 2: no dangling separator, no empty evidence log lines ──────────

    @Test
    fun `gate abort path logs clean evidence lines - no leading separator`() = runBlocking {
        val engine = ScanEngine()
        engine.registrationProvider = { _, _ -> fakeAccount() }
        engine.witnessProber = { _, _, _ -> 0 }
        engine.sweepProber = { _, _, _ -> emptyList() }
        engine.evidenceGatherer = { UdpEvidence.Evidence(cloudflareNtp = false, otherNtp = false) }
        val sink = RecordingSink()
        engine.run(endpointParams(count = 3), sink)

        // the abort verdict + its sweep coverage + the witness diagnosis
        assertTrue(sink.logs.any { it.contains("endpoint scan aborted") })
        assertTrue(sink.logs.any { it.contains("even ntp is dead") })
        // THE fix: no log line starts with a dangling separator…
        assertTrue(
            "no log line may start with a dangling separator — was ${sink.logs.filter { it.startsWith(" · ") }}",
            sink.logs.none { it.startsWith(" · ") },
        )
        // …and none is empty (the old call logged "" when no evidence existed)
        assertTrue("no empty log lines allowed", sink.logs.none { it.isBlank() })
    }

    @Test
    fun `gate abort with no evidence logs no evidence line at all`() = runBlocking {
        val engine = ScanEngine()
        engine.registrationProvider = { _, _ -> fakeAccount() }
        engine.witnessProber = { _, _, _ -> 0 }
        engine.sweepProber = { _, _, _ -> emptyList() }
        engine.evidenceGatherer = { null } // no witness evidence available
        val sink = RecordingSink()
        engine.run(endpointParams(count = 3), sink)

        assertTrue(sink.logs.any { it.contains("endpoint scan aborted") })
        // THE fix: an empty diagnosis is simply not logged — the old code
        // logged "" (a blank line in the visible log screen)
        assertTrue(
            "no empty log lines allowed — was ${sink.logs}",
            sink.logs.none { it.isBlank() },
        )
        assertTrue(sink.logs.none { it.contains("udp witness") })
    }

    @Test
    fun `zero-result completion line joins diagnosis with a single separator`() = runBlocking {
        val engine = ScanEngine()
        engine.registrationProvider = { _, _ -> fakeAccount() }
        engine.witnessProber = { _, _, _ -> 2 }   // gate passes, storm rolls
        engine.evidenceGatherer = { UdpEvidence.Evidence(cloudflareNtp = false, otherNtp = false) }
        val sink = RecordingSink()
        engine.run(endpointParams(count = 2), sink)

        val completion = sink.logs.last { it.contains("endpoint scan done") }
        assertTrue(completion.contains("even ntp is dead"))
        // format contract: single " · " between sections, no doubled separator,
        // no trailing separator, no leading one
        assertFalse("doubled separator: $completion", completion.contains(" · · "))
        assertFalse("trailing separator: $completion", completion.endsWith(" · "))
        assertFalse("leading separator: $completion", completion.startsWith(" · "))
    }

    // ── fix 4: slider inits are clamped into their own boxes ───────────────

    @Test
    fun `clampToSlider pulls out-of-range persisted values into the box`() {
        // the three REAL mismatches between prefs ranges and slider ranges
        assertEquals(3000, clampToSlider(5000, 50..3000))   // samples: prefs cap 5000
        assertEquals(6000, clampToSlider(8000, 300..6000))  // timeout: prefs cap 8000
        assertEquals(50, clampToSlider(10, 50..20000))      // endpoints: prefs floor 10
        // the download chips max out at 50 MB (prefs cap 100)
        assertEquals(50, clampToSlider(100, 1..50))
        // endpoint retries slider is 1..7 (an old EDGE value of 8..10)
        assertEquals(7, clampToSlider(8, 1..7))
    }

    @Test
    fun `clampToSlider keeps in-range and boundary values untouched`() {
        assertEquals(96, clampToSlider(96, 50..3000))
        assertEquals(2000, clampToSlider(2000, 300..6000))
        assertEquals(500, clampToSlider(500, 50..20000))
        assertEquals(50, clampToSlider(50, 50..3000))
        assertEquals(3000, clampToSlider(3000, 50..3000))
        assertEquals(1, clampToSlider(1, 1..7))
    }
}
