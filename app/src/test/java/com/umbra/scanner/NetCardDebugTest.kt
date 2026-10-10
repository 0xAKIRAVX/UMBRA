package com.umbra.scanner

import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.assertIsDisplayed
import androidx.test.core.app.ApplicationProvider
import com.umbra.scanner.core.ScanUi
import com.umbra.scanner.ui.screens.ScanScreen
import com.umbra.scanner.ui.theme.UmbraTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/**
 * v3.1 regression guard: the NET CHECK card must be present (composed AND
 * displayed) on the idle scan screen — it is the entry point of the whole
 * NetSense feature. (Robolectric's decor-draw capture is known to skip this
 * nested-AnimatedContent subtree in full-screen captures, which is why the
 * assertion targets the semantics/layout truth, not pixels.)
 */
@RunWith(AndroidJUnit4::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34], qualifiers = "w411dp-h891dp-420dpi")
class NetCardDebugTest {

    @get:Rule
    val compose = createComposeRule()

    private val app: UmbraApp = ApplicationProvider.getApplicationContext()

    @Test
    fun `net status card is composed and displayed in idle state`() {
        app.controller.debugInjectState(uiState = ScanUi.Idle)
        compose.setContent { UmbraTheme(settings = app.settings) { ScanScreen(app) {} } }
        compose.mainClock.advanceTimeBy(800)
        compose.onNodeWithText("NET CHECK").assertExists()
        compose.onNodeWithText("MEASURE MY NET").assertExists()
        compose.onNodeWithText("MEASURE MY NET").assertIsDisplayed()
        compose.waitForIdle()
        compose.onNodeWithText("MEASURE MY NET").assertIsDisplayed()
    }
}
