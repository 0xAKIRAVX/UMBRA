package com.umbra.scanner.ui.screens

import android.view.WindowManager
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.umbra.scanner.UmbraApp
import com.umbra.scanner.unlockMaxRefreshRate
import com.umbra.scanner.ui.components.NeonCard
import com.umbra.scanner.ui.components.OutlineButton
import com.umbra.scanner.ui.components.SectionLabel
import com.umbra.scanner.ui.components.ToggleRow
import com.umbra.scanner.ui.components.bouncyClickable
import com.umbra.scanner.ui.components.staggerIn
import com.umbra.scanner.ui.theme.ACCENTS
import com.umbra.scanner.ui.theme.Fade
import com.umbra.scanner.ui.theme.Fog
import com.umbra.scanner.ui.theme.Graphite
import com.umbra.scanner.ui.theme.LocalAccent
import com.umbra.scanner.ui.theme.Mist
import com.umbra.scanner.ui.theme.MonoStyleSmall
import com.umbra.scanner.ui.theme.SlateLine
import android.app.Activity

@Composable
fun SettingsScreen(app: UmbraApp) {
    val settings = app.settings
    val accentIdx by settings.accent.collectAsState()
    val amoled by settings.amoled.collectAsState()
    val haptics by settings.haptics.collectAsState()
    val highRefresh by settings.highRefresh.collectAsState()
    val lightFx by settings.lightFx.collectAsState()
    val accent = LocalAccent.current
    val context = LocalContext.current
    val resultsCount = app.controller.results.collectAsState().value.size

    val displayHz = rememberDisplayHz()

    Column(
        Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp)
    ) {
        Spacer(Modifier.height(10.dp))
        Text(
            "SYSTEM",
            style = MaterialTheme.typography.displayMedium,
            color = Mist,
            modifier = Modifier.staggerIn(0),
            maxLines = 1,
            softWrap = false,
        )
        Spacer(Modifier.height(4.dp))
        Text(
            "identity · performance · internals",
            style = MaterialTheme.typography.bodySmall,
            color = Fade,
            modifier = Modifier.staggerIn(1),
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )

        Spacer(Modifier.height(14.dp))

        NeonCard(modifier = Modifier.staggerIn(2)) {
            SectionLabel("SIGNAL PALETTE")
            Spacer(Modifier.height(10.dp))
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                ACCENTS.forEachIndexed { i, scheme ->
                    val selected = accentIdx == i
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(11.dp))
                            .background(if (selected) scheme.primary.copy(alpha = 0.10f) else Graphite)
                            .border(
                                1.dp,
                                if (selected) scheme.primary.copy(alpha = 0.8f) else SlateLine,
                                RoundedCornerShape(11.dp),
                            )
                            .bouncyClickable(pressedScale = 0.97f) { settings.setAccent(i) }
                            .padding(horizontal = 12.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                            Box(
                                Modifier
                                    .size(11.dp)
                                    .clip(CircleShape)
                                    .background(scheme.primary)
                            )
                            Box(
                                Modifier
                                    .size(11.dp)
                                    .clip(CircleShape)
                                    .background(scheme.secondary)
                            )
                        }
                        Spacer(Modifier.padding(start = 10.dp))
                        Text(
                            scheme.name,
                            style = MaterialTheme.typography.labelLarge,
                            color = if (selected) scheme.tint else Mist,
                            modifier = Modifier.weight(1f),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        if (selected) {
                            Text("ACTIVE", style = MaterialTheme.typography.labelSmall, color = scheme.primary)
                        }
                    }
                }
            }
            Spacer(Modifier.height(6.dp))
            Text(
                "rare palettes — phantom mint, lunar iris, nova rose, ember flare",
                style = MaterialTheme.typography.bodySmall,
                color = Fade,
            )
        }

        Spacer(Modifier.height(14.dp))
        NeonCard(glow = false, modifier = Modifier.staggerIn(3)) {
            SectionLabel("PERFORMANCE")
            Spacer(Modifier.height(6.dp))
            ToggleRow(
                title = "MAX REFRESH RATE",
                subtitle = "unlocks 90 / 120 / 144 Hz — display: ${displayHz ?: "?"} Hz",
                checked = highRefresh,
                onChange = { on ->
                    settings.setHighRefresh(on)
                    if (on) (context as? Activity)?.unlockMaxRefreshRate()
                },
            )
            ToggleRow(
                title = "LIGHTWEIGHT FX",
                subtitle = "freezes radar + glow animations on very weak devices",
                checked = lightFx,
                onChange = { settings.setLightFx(it) },
            )
            ToggleRow(
                title = "AMOLED VOID",
                subtitle = "true-black surfaces for OLED panels",
                checked = amoled,
                onChange = { settings.setAmoled(it) },
            )
            ToggleRow(
                title = "HAPTIC SIGNALS",
                subtitle = "subtle feedback on controls and scan start",
                checked = haptics,
                onChange = { settings.setHaptics(it) },
            )
        }

        Spacer(Modifier.height(14.dp))
        NeonCard(glow = false, modifier = Modifier.staggerIn(4)) {
            SectionLabel("ABOUT UMBRA")
            Spacer(Modifier.height(8.dp))
            Row(Modifier.fillMaxWidth()) {
                Text("VERSION", style = MaterialTheme.typography.labelMedium, color = Fade, modifier = Modifier.weight(1f))
                Text("2.2.0 · build 4", style = MonoStyleSmall, color = accent.tint, maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis)
            }
            Spacer(Modifier.height(5.dp))
            Row(Modifier.fillMaxWidth()) {
                Text("ENGINE", style = MaterialTheme.typography.labelMedium, color = Fade, modifier = Modifier.weight(1f))
                Text("exact-IP tcp + tls + https", style = MonoStyleSmall, color = Fog, maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis)
            }
            Spacer(Modifier.height(5.dp))
            Row(Modifier.fillMaxWidth()) {
                Text("DNS", style = MaterialTheme.typography.labelMedium, color = Fade, modifier = Modifier.weight(1f))
                Text("never used for candidates", style = MonoStyleSmall, color = Fog, maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis)
            }
            Spacer(Modifier.height(12.dp))
            Text(
                "fonts · Bruno Ace SC, Chakra Petch, Major Mono Display — SIL Open Font License. " +
                    "scoring · latency 34% · loss 26% · speed 20% · jitter 10% + tls bonus. " +
                    "use responsibly and within your local network policies.",
                style = MaterialTheme.typography.bodySmall,
                color = Fade,
            )
            if (resultsCount > 0) {
                Spacer(Modifier.height(12.dp))
                OutlineButton(
                    text = "CLEAR RESULT BOARD ($resultsCount)",
                    onClick = { app.controller.clearResults() },
                    modifier = Modifier.fillMaxWidth(),
                    height = 40.dp,
                )
            }
        }

        Spacer(Modifier.height(24.dp))
    }
}

@Composable
private fun rememberDisplayHz(): Float? {
    val activity = LocalContext.current as? Activity
    return remember(activity) {
        try {
            activity?.windowManager?.defaultDisplay?.refreshRate
        } catch (_: Exception) {
            null
        }
    }
}
