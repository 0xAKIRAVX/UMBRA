package com.umbra.scanner.ui.screens

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.background
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.umbra.scanner.UmbraApp
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanPhase
import com.umbra.scanner.core.ScanStats
import com.umbra.scanner.core.ScanSummary
import com.umbra.scanner.core.ScanUi
import com.umbra.scanner.core.ScanResult
import com.umbra.scanner.i18n.LocalStrings
import com.umbra.scanner.ui.components.AnimatedCountText
import com.umbra.scanner.ui.components.GradientButton
import com.umbra.scanner.ui.components.NetStatusCard
import com.umbra.scanner.ui.components.NeonCard
import com.umbra.scanner.ui.components.OrbitGlobe
import com.umbra.scanner.ui.components.OutlineButton
import com.umbra.scanner.ui.components.PulsingDot
import com.umbra.scanner.ui.components.RadarPulse
import com.umbra.scanner.ui.components.StatCell
import com.umbra.scanner.ui.components.UmbraProgress
import com.umbra.scanner.ui.components.staggerIn
import com.umbra.scanner.ui.theme.Fade
import com.umbra.scanner.ui.theme.LocalAccent
import com.umbra.scanner.ui.theme.Mist
import com.umbra.scanner.ui.theme.MonoStyle
import com.umbra.scanner.ui.theme.MonoStyleLarge
import com.umbra.scanner.ui.theme.MonoStyleSmall
import com.umbra.scanner.ui.theme.OkMint
import com.umbra.scanner.ui.theme.WarnAmber
import com.umbra.scanner.ui.theme.Fog

@Composable
fun ScanScreen(app: UmbraApp, onGoResults: () -> Unit) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val controller = app.controller
    val ui by controller.ui.collectAsState()
    val stats by controller.stats.collectAsState()
    val top by controller.top.collectAsState()
    val log by controller.log.collectAsState()
    val notice by controller.notice.collectAsState()

    Column(
        Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp)
    ) {
        Spacer(Modifier.height(10.dp))
        Hero(
            running = ui is ScanUi.Running,
            done = ui is ScanUi.Done,
            idle = ui is ScanUi.Idle,
            modifier = Modifier.staggerIn(0),
        )

        Spacer(Modifier.height(14.dp))

        AnimatedContent(
            targetState = ui,
            transitionSpec = {
                (fadeIn(tween(240)) + slideInVertically(tween(260)) { it / 22 }) togetherWith
                    (fadeOut(tween(150)) + slideOutVertically(tween(200)) { -it / 28 })
            },
            label = "scanState",
        ) { st ->
            when (st) {
                is ScanUi.Running -> {
                    LivePanel(stats = stats, top = top, log = log, mode = st.params.mode) { controller.stopScan() }
                    Spacer(Modifier.height(24.dp))
                }

                is ScanUi.Done -> {
                    DonePanel(summary = st.summary, onGoResults = onGoResults) { controller.resetUi() }
                    Spacer(Modifier.height(24.dp))
                }

                ScanUi.Idle -> {
                    NetStatusCard(app = app, modifier = Modifier.staggerIn(1))
                    Spacer(Modifier.height(12.dp))
                    // v3.3.1: a refused/deferred scan start is now VISIBLE —
                    // previously the reason only entered the engine log, which
                    // the idle screen never showed, so the button looked dead.
                    notice?.let { reason ->
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(10.dp))
                                .background(WarnAmber.copy(alpha = 0.10f))
                                .padding(horizontal = 12.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            PulsingDot(color = WarnAmber, sizeDp = 5.dp)
                            Spacer(Modifier.width(8.dp))
                            Text(
                                reason,
                                style = MaterialTheme.typography.bodySmall,
                                color = WarnAmber,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                        Spacer(Modifier.height(12.dp))
                    }
                    ConfigPanel(app = app, onStart = { params -> startScan(context, app, params) })
                    Spacer(Modifier.height(24.dp))
                }
            }
        }
    }
}

private fun startScan(
    context: android.content.Context,
    app: UmbraApp,
    params: ScanParams,
) {
    app.settings.saveParams(params)
    if (Build.VERSION.SDK_INT >= 33 &&
        !app.settings.notifAsked.value &&
        ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
    ) {
        // v3.1.1 fix: asked exactly ONCE per install — the old code re-popped
        // the system dialog on every single scan start
        runCatching {
            (context as? android.app.Activity)?.let { activity ->
                activity.requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 4711)
            }
        }
        app.settings.setNotifAsked()
    }
    app.controller.start(context, params)
}

/**
 * v3 hero — gradient wordmark plus, in idle, the live crimson orbit globe
 * that echoes the launcher icon. Status pill stays on the right.
 */
@Composable
private fun Hero(running: Boolean, done: Boolean, idle: Boolean, modifier: Modifier = Modifier) {
    val accent = LocalAccent.current
    val s = LocalStrings.current
    Row(
        modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (idle) {
            OrbitGlobe(sizeDp = 58.dp)
            Spacer(Modifier.width(14.dp))
        }
        Column(Modifier.weight(1f)) {
            Text(
                text = "UMBRA",
                style = MaterialTheme.typography.displayLarge.copy(
                    brush = Brush.verticalGradient(
                        listOf(accent.glow, accent.primary)
                    )
                ),
                color = androidx.compose.ui.graphics.Color.Unspecified,
                maxLines = 1,
                softWrap = false,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                s.brandTagline,
                style = MaterialTheme.typography.labelSmall,
                color = Fade,
                letterSpacing = if (s.brandTagline.all { it.code < 0x590 }) 3.4.sp else 0.sp,
                maxLines = 1,
                softWrap = false,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Spacer(Modifier.width(8.dp))
        val (dotColor, label) = when {
            running -> accent.primary to s.live
            done -> OkMint to s.done
            else -> Fog to s.idle
        }
        // status pill
        Row(
            Modifier
                .clip(RoundedCornerShape(9.dp))
                .background(dotColor.copy(alpha = 0.12f))
                .padding(horizontal = 10.dp, vertical = 5.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            PulsingDot(color = dotColor, sizeDp = 6.dp)
            Spacer(Modifier.width(6.dp))
            Text(
                label,
                style = MaterialTheme.typography.labelSmall,
                color = Fog,
                maxLines = 1,
                softWrap = false,
            )
        }
    }
}

@Composable
private fun LivePanel(
    stats: ScanStats,
    top: List<ScanResult>,
    log: List<String>,
    mode: ScanMode,
    onStop: () -> Unit,
) {
    val accent = LocalAccent.current
    val s = LocalStrings.current
    NeonCard {
        PhaseBar(current = stats.phase, mode = mode)
        Spacer(Modifier.height(14.dp))
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            RadarPulse(sizeDp = 96.dp)
            Column(Modifier.weight(1f)) {
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    StatCell(s.tested, "${stats.tested}/${stats.candidates}", Modifier.weight(1f))
                    StatCell(s.alive, stats.alive.toString(), tint = OkMint, modifier = Modifier.weight(1f))
                }
                Spacer(Modifier.height(9.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    StatCell(s.rate, "${"%.1f".format(java.util.Locale.US, stats.ratePerSec)}${s.perSec}", Modifier.weight(1f))
                    StatCell(s.active, stats.active.toString(), Modifier.weight(1f))
                }
                Spacer(Modifier.height(9.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    StatCell(s.elapsed, formatElapsed(stats.elapsedMs), Modifier.weight(1f))
                    StatCell(
                        s.eta,
                        stats.etaSec?.let { formatElapsed((it * 1000).toLong()) } ?: "—",
                        Modifier.weight(1f),
                    )
                }
            }
        }
        Spacer(Modifier.height(14.dp))
        UmbraProgress(progress = stats.progress)
        Spacer(Modifier.height(12.dp))
        if (top.isNotEmpty()) {
            Text(s.liveTopEndpoints, style = MaterialTheme.typography.labelSmall, color = Fade)
            Spacer(Modifier.height(6.dp))
            top.take(5).forEach { r ->
                Row(
                    Modifier
                        .fillMaxWidth()
                        .padding(vertical = 3.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        r.ip,
                        style = MonoStyle.copy(fontSize = 11.5.sp),
                        color = Mist,
                        maxLines = 1,
                        softWrap = false,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f),
                    )
                    Text(
                        r.latencyMs?.let { "%.0f ms".format(java.util.Locale.US, it) } ?: "—",
                        style = MonoStyleSmall,
                        color = accent.tint,
                        maxLines = 1,
                        softWrap = false,
                    )
                }
            }
            Spacer(Modifier.height(8.dp))
        }
        Text(
            text = log.firstOrNull() ?: s.warmingUp,
            style = MaterialTheme.typography.bodySmall,
            color = Fog,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
        Spacer(Modifier.height(14.dp))
        GradientButton(text = s.stopScan, onClick = onStop, danger = true)
    }
}

/**
 * Compact phase progress: a six-segment step bar plus the current phase
 * name. WARP scans swap the TCP/TLS segments for the real WireGuard flow.
 */
@Composable
private fun PhaseBar(current: ScanPhase, mode: ScanMode) {
    val accent = LocalAccent.current
    val phases = if (mode == ScanMode.WARP) {
        listOf(
            ScanPhase.GENERATING,
            ScanPhase.REGISTER,
            ScanPhase.WG,
            ScanPhase.RANKING,
            ScanPhase.SPEED,
            ScanPhase.DONE,
        )
    } else {
        listOf(
            ScanPhase.GENERATING,
            ScanPhase.TCP,
            ScanPhase.PROBE,
            ScanPhase.RANKING,
            ScanPhase.SPEED,
            ScanPhase.DONE,
        )
    }
    Row(
        Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Row(
            Modifier.weight(1f),
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            phases.forEach { phase ->
                val done = phase.order <= current.order
                val activeNow = phase == current
                Box(
                    Modifier
                        .weight(1f)
                        .height(4.dp)
                        .clip(RoundedCornerShape(2.dp))
                        .background(
                            if (done) accent.primary.copy(
                                alpha = if (activeNow) 0.95f else 0.40f
                            ) else com.umbra.scanner.ui.theme.SlateLine
                        )
                )
            }
        }
        Spacer(Modifier.width(8.dp))
        AnimatedContent(
            targetState = current.label,
            transitionSpec = { fadeIn(tween(180)) togetherWith fadeOut(tween(120)) },
            label = "phaseName",
        ) { label ->
            Text(
                label,
                style = MonoStyleSmall,
                color = accent.tint,
                maxLines = 1,
                softWrap = false,
            )
        }
    }
}

@Composable
private fun DonePanel(
    summary: ScanSummary,
    onGoResults: () -> Unit,
    onNewScan: () -> Unit,
) {
    val accent = LocalAccent.current
    val s = LocalStrings.current
    NeonCard {
        Text(
            if (summary.cancelled) s.scanStopped else s.scanComplete,
            style = MaterialTheme.typography.displayMedium,
            color = if (summary.cancelled) WarnAmber else accent.primary,
            maxLines = 1,
            softWrap = false,
            overflow = TextOverflow.Ellipsis,
        )
        Spacer(Modifier.height(10.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                AnimatedCountText(
                    value = summary.alive,
                    style = MonoStyle.copy(fontSize = 12.sp),
                    color = Mist,
                )
                Text(
                    s.alive,
                    style = MaterialTheme.typography.labelSmall.copy(
                        letterSpacing = if (s.alive.all { it.code < 0x590 }) 1.2.sp else 0.sp
                    ),
                    color = Fade,
                    maxLines = 1,
                    softWrap = false,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            StatCell(
                s.tested,
                "${summary.tested}/${summary.candidates}",
                Modifier.weight(1f),
            )
            StatCell(s.time, formatElapsed(summary.elapsedMs), Modifier.weight(1f))
        }
        Spacer(Modifier.height(14.dp))
        // v3.3: a zero-result scan now explains ITSELF — the engine's last
        // word (blocked registration, capped budget, engine failure) is
        // shown right in the panel instead of a silent empty result.
        summary.error?.let { reason ->
            Text(
                reason,
                style = MonoStyleSmall.copy(color = WarnAmber, fontSize = 10.5.sp),
                maxLines = 3,
                overflow = TextOverflow.Ellipsis,
            )
            Spacer(Modifier.height(12.dp))
        }
        summary.best?.let { best ->
            Column {
                Text(s.bestEndpoint, style = MaterialTheme.typography.labelSmall, color = Fade)
                Spacer(Modifier.height(4.dp))
                Text(
                    best.ip,
                    style = MonoStyleLarge,
                    color = accent.tint,
                    maxLines = 1,
                    softWrap = false,
                    overflow = TextOverflow.Ellipsis,
                )
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    StatCell(s.lat, best.latencyMs?.let { "%.0fms".format(java.util.Locale.US, it) } ?: "—", Modifier.weight(1f))
                    StatCell(s.jit, best.jitterMs?.let { "%.0fms".format(java.util.Locale.US, it) } ?: "—", Modifier.weight(1f))
                    StatCell(s.loss, "${best.lossPct}%", Modifier.weight(1f))
                    StatCell(s.speed, best.speedMbps?.let { "%.1fM".format(java.util.Locale.US, it) } ?: "—", Modifier.weight(1f))
                }
                Spacer(Modifier.height(16.dp))
            }
        }
        GradientButton(text = s.viewResults, onClick = onGoResults)
        Spacer(Modifier.height(9.dp))
        OutlineButton(text = s.configureNewScan, onClick = onNewScan, modifier = Modifier.fillMaxWidth())
    }
}

internal fun formatElapsed(ms: Long): String {
    val s = ms / 1000
    return when {
        s < 60 -> "${s}s"
        s < 3600 -> "%d:%02d".format(java.util.Locale.US, s / 60, s % 60)
        else -> "%d:%02d:%02d".format(java.util.Locale.US, s / 3600, (s % 3600) / 60, s % 60)
    }
}
