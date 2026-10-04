package com.umbra.scanner

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.core.view.WindowCompat
import com.umbra.scanner.ui.UmbraRoot
import com.umbra.scanner.ui.theme.UmbraTheme

class MainActivity : ComponentActivity() {

    private val app by lazy { application as UmbraApp }
    private val updateDelay = Handler(Looper.getMainLooper())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        if (app.settings.highRefresh.value) {
            unlockMaxRefreshRate()
        }
        WindowCompat.getInsetsController(window, window.decorView).apply {
            isAppearanceLightStatusBars = false
            isAppearanceLightNavigationBars = false
        }
        setContent {
            UmbraTheme(settings = app.settings) {
                UmbraRoot(app = app)
            }
        }
        scheduleUpdateCheck()
    }

    override fun onResume() {
        super.onResume()
        if (app.settings.highRefresh.value) {
            unlockMaxRefreshRate()
        }
    }

    /** Silent GitHub check a moment after the UI settles — never blocks startup. */
    private fun scheduleUpdateCheck() {
        updateDelay.postDelayed({ app.updateCenter.maybeAutoCheck() }, 1500L)
    }
}

/**
 * Frame-rate unlock: picks the highest physical refresh-rate display mode at the
 * current resolution and pins the window to it (works on 90/120/144 Hz panels,
 * including on low-end devices that default to 60 Hz for non-game apps).
 */
@Suppress("DEPRECATION")
fun Activity.unlockMaxRefreshRate() {
    try {
        val display = windowManager.defaultDisplay ?: return
        val current = display.mode
        val best = display.supportedModes
            .filter {
                it.physicalWidth == current.physicalWidth &&
                    it.physicalHeight == current.physicalHeight
            }
            .maxByOrNull { it.refreshRate } ?: return
        if (best.modeId == current.modeId) return
        window.attributes = window.attributes.also { it.preferredDisplayModeId = best.modeId }
        if (best.refreshRate > window.attributes.preferredRefreshRate) {
            window.attributes = window.attributes.also { it.preferredRefreshRate = best.refreshRate }
        }
    } catch (_: Exception) {
    }
}
