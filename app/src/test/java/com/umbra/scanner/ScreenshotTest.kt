package com.umbra.scanner

import android.app.Activity
import android.graphics.Bitmap
import android.graphics.Canvas
import androidx.compose.ui.test.junit4.AndroidComposeTestRule
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.umbra.scanner.core.IpProtocol
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.core.ScanPhase
import com.umbra.scanner.core.ScanResult
import com.umbra.scanner.core.ScanStats
import com.umbra.scanner.core.ScanSummary
import com.umbra.scanner.core.ScanUi
import com.umbra.scanner.engine.UpdateCenter
import com.umbra.scanner.net.UpdateChecker
import com.umbra.scanner.ui.components.UpdateDialog
import com.umbra.scanner.ui.screens.ResultsScreen
import com.umbra.scanner.ui.screens.ScanScreen
import com.umbra.scanner.ui.screens.SettingsScreen
import com.umbra.scanner.ui.screens.VlessScreen
import com.umbra.scanner.ui.theme.UmbraTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.io.File

/**
 * Renders the real Compose UI (real theme, real fonts, real components) at
 * phone resolution and captures PNG screenshots for the repository docs.
 * These are genuine renders of the app's actual UI code — no mockups.
 *
 * Capture uses a manual decorView draw pass (the standard captureToImage
 * draw-listener path times out under Robolectric).
 */
@RunWith(AndroidJUnit4::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34], qualifiers = "w411dp-h891dp-420dpi")
class ScreenshotTest {

    @get:Rule
    val compose = createComposeRule()

    private val app: UmbraApp = ApplicationProvider.getApplicationContext()
    private val outDir = File("/home/z/my-project/umbra/docs/screenshots")

    private fun shot(name: String) {
        compose.mainClock.advanceTimeBy(700) // let staggered entrances settle
        @Suppress("UNCHECKED_CAST")
        val rule = compose as AndroidComposeTestRule<*, Activity>
        val activity = rule.activity
        val decor = activity.window.decorView
        val bmp = Bitmap.createBitmap(decor.width, decor.height, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bmp)
        InstrumentationRegistry.getInstrumentation().runOnMainSync { decor.draw(canvas) }
        outDir.mkdirs()
        File(outDir, name).outputStream().use { fos ->
            bmp.compress(Bitmap.CompressFormat.PNG, 100, fos)
        }
    }

    private fun sampleResults(): List<ScanResult> = listOf(
        ScanResult(
            ip = "104.16.132.229", protocol = IpProtocol.IPv4, port = 443,
            latencyMs = 11.2, jitterMs = 1.4, packetLoss = 0.0,
            speedMbps = 38.4, downloadedBytes = 20L * 1024 * 1024,
            tcpAttempts = 3, successfulAttempts = 3,
            tlsSuccess = true, tlsHandshakeMs = 23.5, httpStatus = 200,
        ),
        ScanResult(
            ip = "172.64.229.14", protocol = IpProtocol.IPv4, port = 443,
            latencyMs = 14.9, jitterMs = 2.1, packetLoss = 0.0,
            speedMbps = 31.7, downloadedBytes = 20L * 1024 * 1024,
            tcpAttempts = 3, successfulAttempts = 3,
            tlsSuccess = true, tlsHandshakeMs = 26.8, httpStatus = 200,
        ),
        ScanResult(
            ip = "162.159.192.1", protocol = IpProtocol.IPv4, port = 2408,
            latencyMs = 18.3, jitterMs = 2.9, packetLoss = 0.0,
            speedMbps = 24.2, downloadedBytes = 20L * 1024 * 1024,
            tcpAttempts = 3, successfulAttempts = 3,
            tlsSuccess = true, tlsHandshakeMs = 31.2, httpStatus = 200,
            wgHandshakes = 3,
            mode = ScanMode.WARP,
        ),
        ScanResult(
            ip = "2606:4700:d0::a29f:c001", protocol = IpProtocol.IPv6, port = 2408,
            latencyMs = 21.7, jitterMs = 3.6, packetLoss = 0.0,
            speedMbps = 19.8, downloadedBytes = 20L * 1024 * 1024,
            tcpAttempts = 3, successfulAttempts = 3,
            tlsSuccess = true, tlsHandshakeMs = 35.9, httpStatus = 200,
            wgHandshakes = 3,
            mode = ScanMode.WARP,
        ),
        ScanResult(
            ip = "104.17.214.49", protocol = IpProtocol.IPv4, port = 8443,
            latencyMs = 26.4, jitterMs = 5.2, packetLoss = 33.3,
            speedMbps = 12.5, downloadedBytes = 20L * 1024 * 1024,
            tcpAttempts = 3, successfulAttempts = 2,
            tlsSuccess = true, tlsHandshakeMs = 42.1, httpStatus = 200,
        ),
        ScanResult(
            ip = "188.114.97.4", protocol = IpProtocol.IPv4, port = 894,
            latencyMs = 33.1, jitterMs = 7.8, packetLoss = 0.0,
            speedMbps = null, downloadedBytes = 0,
            tcpAttempts = 3, successfulAttempts = 3,
            tlsSuccess = true, tlsHandshakeMs = 48.4, httpStatus = null,
            wgHandshakes = 3,
            mode = ScanMode.WARP,
        ),
    )

    @Test
    fun `01 scan idle config`() {
        app.controller.debugInjectState(uiState = ScanUi.Idle)
        compose.mainClock.autoAdvance = false
        compose.setContent { UmbraTheme(settings = app.settings) { ScanScreen(app) {} } }
        shot("scan-config.png")
    }

    @Test
    fun `02 scan running live`() {
        val params = ScanParams(mode = ScanMode.WARP, port = 2408, portSweep = true)
        app.controller.debugInjectState(
            uiState = ScanUi.Running(params, System.currentTimeMillis()),
            statsValue = ScanStats(
                phase = ScanPhase.TCP,
                candidates = 4080,
                tested = 2563,
                alive = 611,
                tlsOk = 0,
                speedTested = 0,
                active = 150,
                elapsedMs = 42_300,
                ratePerSec = 60.6,
                etaSec = 25.0,
            ),
            topValue = sampleResults().take(3),
            logValue = listOf(
                "scan session started · mode WARP · 3 attempts × 2000 ms",
                "sweep 68 ports × 60 endpoints = 4080 probes",
                "tcp storm · 150 lanes open",
            ),
        )
        compose.mainClock.autoAdvance = false
        compose.setContent { UmbraTheme(settings = app.settings) { ScanScreen(app) {} } }
        shot("scan-live.png")
    }

    @Test
    fun `03 results board`() {
        val params = ScanParams(mode = ScanMode.CF_EDGE)
        app.controller.debugInjectState(
            uiState = ScanUi.Done(
                ScanSummary(
                    cancelled = false,
                    candidates = 7000,
                    tested = 7000,
                    alive = 214,
                    best = sampleResults().first(),
                    elapsedMs = 183_400,
                    params = params,
                )
            ),
            resultsValue = sampleResults(),
            topValue = sampleResults().take(5),
        )
        compose.mainClock.autoAdvance = false
        compose.setContent { UmbraTheme(settings = app.settings) { ResultsScreen(app, {}, {}) } }
        shot("results.png")
    }

    @Test
    fun `04 vless generator`() {
        app.controller.pendingVlessIp = "104.16.132.229"
        compose.mainClock.autoAdvance = false
        compose.setContent { UmbraTheme(settings = app.settings) { VlessScreen(app) } }
        compose.onNodeWithText("SHOW QR").performClick()
        shot("vless.png")
    }

    @Test
    fun `05 settings system`() {
        app.controller.debugInjectState(
            resultsValue = sampleResults(),
            uiState = ScanUi.Idle,
        )
        compose.mainClock.autoAdvance = false
        compose.setContent { UmbraTheme(settings = app.settings) { SettingsScreen(app) } }
        shot("settings.png")
    }

    @Test
    fun `06 update announcement dialog`() {
        val release = UpdateChecker.Release(
            tag = "v2.4.0",
            name = "UMBRA v2.4.0",
            pageUrl = "https://github.com/0xAKIRAVX/UMBRA/releases/tag/v2.4.0",
            apkUrl = "https://github.com/0xAKIRAVX/UMBRA/releases/download/v2.4.0/UMBRA.apk",
            notes = "- WARP endpoint discovery 2x faster\n- New signal palettes\n- Bug fixes & smoother animations",
            publishedAt = "2026-10-04T12:00:00Z",
        )
        compose.mainClock.autoAdvance = false
        compose.setContent {
            UmbraTheme(settings = app.settings) {
                ScanScreen(app) {}
                UpdateDialog(
                    state = UpdateCenter.State.Available(release, "2.3.0"),
                    onDismiss = {},
                )
            }
        }
        shot("update-dialog.png")
    }
}
