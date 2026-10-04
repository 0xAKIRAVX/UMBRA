package com.umbra.scanner.ui.screens

import android.content.Intent
import android.net.Uri
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
import androidx.compose.foundation.layout.width
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
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.pm.PackageInfoCompat
import com.umbra.scanner.UmbraApp
import com.umbra.scanner.core.Project
import com.umbra.scanner.engine.UpdateCenter
import com.umbra.scanner.unlockMaxRefreshRate
import com.umbra.scanner.ui.components.GradientButton
import com.umbra.scanner.ui.components.NeonCard
import com.umbra.scanner.ui.components.OutlineButton
import com.umbra.scanner.ui.components.PulsingDot
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
import com.umbra.scanner.ui.theme.OkMint
import com.umbra.scanner.ui.theme.SlateLine
import com.umbra.scanner.ui.theme.WarnAmber
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
    val update = app.updateCenter
    val updateState by update.state.collectAsState()
    val autoUpdate by app.settings.autoUpdate.collectAsState()
    val clipboard = LocalClipboardManager.current

    val versionLabel = remember {
        runCatching {
            val pi = context.packageManager.getPackageInfo(context.packageName, 0)
            "${pi.versionName} · build ${PackageInfoCompat.getLongVersionCode(pi)}"
        }.getOrDefault("unknown")
    }

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
            SectionLabel("UPDATE CHANNEL")
            Spacer(Modifier.height(6.dp))
            ToggleRow(
                title = "AUTO CHECK",
                subtitle = "silent background check on launch · every 24 h",
                checked = autoUpdate,
                onChange = { app.settings.setAutoUpdate(it) },
            )
            Spacer(Modifier.height(8.dp))
            Row(
                Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                when (val s = updateState) {
                    UpdateCenter.State.Checking -> {
                        PulsingDot(color = accent.primary, sizeDp = 8.dp)
                        Spacer(Modifier.width(8.dp))
                        Text(
                            "contacting github…",
                            style = MonoStyleSmall,
                            color = accent.tint,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }

                    is UpdateCenter.State.Available -> {
                        PulsingDot(color = OkMint, sizeDp = 8.dp)
                        Spacer(Modifier.width(8.dp))
                        Text(
                            "v${s.release.tag.removePrefix("v")} ready — you are on ${s.currentVersion}",
                            style = MonoStyleSmall,
                            color = OkMint,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }

                    is UpdateCenter.State.UpToDate -> Text(
                        "up to date · latest is v${s.latestTag.removePrefix("v")}",
                        style = MonoStyleSmall,
                        color = OkMint,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )

                    is UpdateCenter.State.Unreachable -> Text(
                        s.reason,
                        style = MonoStyleSmall,
                        color = WarnAmber,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )

                    UpdateCenter.State.Idle -> Text(
                        "checks github releases for newer builds",
                        style = MonoStyleSmall,
                        color = Fade,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
            if (updateState is UpdateCenter.State.Available) {
                Spacer(Modifier.height(8.dp))
                val release = (updateState as UpdateCenter.State.Available).release
                GradientButton(
                    text = "GET v${release.tag.removePrefix("v")}",
                    onClick = {
                        runCatching {
                            context.startActivity(
                                Intent(Intent.ACTION_VIEW, Uri.parse(release.pageUrl))
                                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            )
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    height = 40.dp,
                )
            }
            Spacer(Modifier.height(8.dp))
            OutlineButton(
                text = "CHECK NOW",
                onClick = { update.checkNow() },
                modifier = Modifier.fillMaxWidth(),
                height = 40.dp,
            )
        }

        Spacer(Modifier.height(14.dp))
        NeonCard(glow = false, modifier = Modifier.staggerIn(5)) {
            SectionLabel("ABOUT UMBRA")
            Spacer(Modifier.height(8.dp))
            Row(Modifier.fillMaxWidth()) {
                Text("VERSION", style = MaterialTheme.typography.labelMedium, color = Fade, modifier = Modifier.weight(1f))
                Text(versionLabel, style = MonoStyleSmall, color = accent.tint, maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis)
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

        Spacer(Modifier.height(14.dp))

        // ── project & creator card ─────────────────────────────────
        NeonCard(glow = true, modifier = Modifier.staggerIn(6)) {
            SectionLabel("PROJECT")
            Spacer(Modifier.height(10.dp))
            Row(
                Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(11.dp))
                    .background(accent.primary.copy(alpha = 0.08f))
                    .border(1.dp, accent.primary.copy(alpha = 0.35f), RoundedCornerShape(11.dp))
                    .bouncyClickable(pressedScale = 0.98f) {
                        runCatching {
                            context.startActivity(
                                Intent(Intent.ACTION_VIEW, Uri.parse(Project.REPO_URL))
                                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            )
                        }
                    }
                    .padding(horizontal = 12.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Box(
                    Modifier
                        .size(34.dp)
                        .clip(CircleShape)
                        .background(Brush.linearGradient(listOf(accent.primary, accent.secondary)))
                )
                Spacer(Modifier.width(12.dp))
                Column {
                    Text(
                        Project.CREATOR,
                        style = MaterialTheme.typography.titleMedium,
                        color = accent.tint,
                        maxLines = 1,
                        softWrap = false,
                    )
                    Text(
                        "creator & maintainer",
                        style = MaterialTheme.typography.bodySmall,
                        color = Fade,
                        maxLines = 1,
                    )
                }
            }
            Spacer(Modifier.height(10.dp))
            Row(Modifier.fillMaxWidth()) {
                Text("SOURCE", style = MaterialTheme.typography.labelMedium, color = Fade, modifier = Modifier.weight(1f))
                Text(
                    "github.com/${Project.GITHUB_USER}/${Project.GITHUB_REPO}",
                    style = MonoStyleSmall,
                    color = Fog,
                    maxLines = 1,
                    softWrap = false,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.bouncyClickable(pressedScale = 0.96f) {
                        clipboard.setText(AnnotatedString(Project.REPO_URL))
                    },
                )
            }
            Spacer(Modifier.height(5.dp))
            Row(Modifier.fillMaxWidth()) {
                Text("LICENSE", style = MaterialTheme.typography.labelMedium, color = Fade, modifier = Modifier.weight(1f))
                Text("MIT · open source", style = MonoStyleSmall, color = Fog, maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis)
            }
            Spacer(Modifier.height(12.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                GradientButton(
                    text = "OPEN ON GITHUB",
                    onClick = {
                        runCatching {
                            context.startActivity(
                                Intent(Intent.ACTION_VIEW, Uri.parse(Project.REPO_URL))
                                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            )
                        }
                    },
                    modifier = Modifier.weight(1f),
                    height = 42.dp,
                )
                OutlineButton(
                    text = "COPY LINK",
                    onClick = { clipboard.setText(AnnotatedString(Project.REPO_URL)) },
                    modifier = Modifier.weight(1f),
                    height = 42.dp,
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
