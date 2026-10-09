package com.umbra.scanner

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.core.view.WindowCompat
import com.umbra.scanner.i18n.AppLanguage
import com.umbra.scanner.i18n.LocalStrings
import com.umbra.scanner.ui.UmbraRoot
import com.umbra.scanner.ui.components.OrbitGlobe
import com.umbra.scanner.ui.components.staggerIn
import com.umbra.scanner.ui.theme.UmbraTheme
import kotlinx.coroutines.delay

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
            // v3.8 (visual bug fix): the app ships a full Persian translation
            // but the layout stayed LTR in فارسی — Persian text left-aligned in
            // an LTR frame looks broken. Persian users now get a proper RTL
            // mirror (nav order, paddings, chevrons) exactly like v2rayNG and
            // Hiddify do in FA. Latin technical tokens (IPs, ports, WG) are
            // unaffected — the bidi algorithm keeps LTR runs readable.
            val language by app.settings.language.collectAsState()
            CompositionLocalProvider(
                LocalLayoutDirection provides if (language == AppLanguage.PERSIAN) {
                    LayoutDirection.Rtl
                } else {
                    LayoutDirection.Ltr
                }
            ) {
                UmbraTheme(settings = app.settings) {
                    UmbraRoot(app = app)
                    BootSplash(version = "v" + app.updateCenter.currentVersion)
                }
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
 * v3 boot splash — the crimson orbit globe breathing over the void with the
 * gradient wordmark, dissolving into the app once the first frame settles.
 * Pure overlay: no extra activity, no window lock, tap to skip.
 */
@Composable
private fun BootSplash(version: String) {
    var visible by remember { mutableStateOf(true) }
    LaunchedEffect(Unit) {
        delay(1150)
        visible = false
    }
    AnimatedVisibility(
        visible = visible,
        enter = fadeIn(tween(90)),
        exit = fadeOut(tween(420)),
    ) {
        val accent = com.umbra.scanner.ui.theme.LocalAccent.current
        val bg = MaterialTheme.colorScheme.background
        Box(
            Modifier
                .fillMaxSize()
                .background(bg),
        ) {
            Column(
                Modifier
                    .align(Alignment.Center)
                    .staggerIn(0),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                OrbitGlobe(sizeDp = 148.dp)
                Spacer(Modifier.height(22.dp))
                Text(
                    "U M B R A",
                    style = MaterialTheme.typography.displayLarge.copy(
                        brush = Brush.verticalGradient(
                            listOf(accent.glow, accent.primary, accent.secondary)
                        )
                    ),
                    color = Color.Unspecified,
                    maxLines = 1,
                    softWrap = false,
                    overflow = TextOverflow.Ellipsis,
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    LocalStrings.current.brandTagline,
                    style = MaterialTheme.typography.labelSmall,
                    color = com.umbra.scanner.ui.theme.Fog,
                    maxLines = 1,
                    softWrap = false,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            // subtle bottom-inset version whisper
            Text(
                version,
                style = MaterialTheme.typography.labelSmall,
                color = com.umbra.scanner.ui.theme.Fade,
                maxLines = 1,
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .padding(bottom = 34.dp),
            )
        }
    }
}

/**
 * v3.2: reverts the window to the display's DEFAULT mode — the refresh-rate
 * toggle previously only ever pinned the max mode and never reset, leaving the
 * panel running hot while the switch showed OFF.
 */
fun Activity.resetRefreshRate() {
    try {
        window.attributes = window.attributes.also { it.preferredDisplayModeId = 0 }
        window.attributes = window.attributes.also { it.preferredRefreshRate = 0f }
    } catch (_: Exception) {
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
