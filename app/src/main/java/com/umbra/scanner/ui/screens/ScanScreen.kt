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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.umbra.scanner.UmbraApp
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.core.ScanPhase
import com.umbra.scanner.core.ScanStats
import com.umbra.scanner.core.ScanSummary
import com.umbra.scanner.core.ScanUi
import com.umbra.scanner.core.ScanResult
import com.umbra.scanner.ui.components.AnimatedCountText
import com.umbra.scanner.ui.components.GradientButton
import com.umbra.scanner.ui.components.NeonCard
import com.umbra.scanner.ui.components.OutlineButton
import com.umbra.scanner.ui.components.PulsingDot
import com.umbra.scanner.ui.components.RadarPulse
import com.umbra.scanner.ui.components.StatCell
import com.umbra.scanner.ui.components.UmbraProgress
import com.umbra.scanner.ui.components.staggerIn
import com.umbra.scanner.ui.theme.Fade
import com.umbra.scanner.ui.theme.Fog
import com.umbra.scanner.ui.theme.LocalAccent
import com.umbra.scanner.ui.theme.Mist
import com.umbra.scanner.ui.theme.MonoStyle
import com.umbra.scanner.ui.theme.MonoStyleLarge
import com.umbra.scanner.ui.theme.MonoStyleSmall
import com.umbra.scanner.ui.theme.OkMint
import com.umbra.scanner.ui.theme.WarnAmber

@Composable
fun ScanScreen(app: UmbraApp, onGoResults: () -> Unit) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val controller = app.controller
    val ui by controller.ui.collectAsState()
    val stats by controller.stats.collectAsState()
    val top by controller.top.collectAsState()
    val log by controller.log.collectAsState()

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
                    LivePanel(stats = stats, top = top, log = log) { controller.stopScan() }
                    Spacer(Modifier.height(24.dp))
                }

                is ScanUi.Done -> {
                    DonePanel(summary = st.summary, onGoResults = onGoResults) { controller.resetUi() }
                    Spacer(Modifier.height(24.dp))
                }

                ScanUi.Idle -> {
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
        ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
    ) {
        // asked politely once; the scan itself runs regardless of the answer
        runCatching {
            (context as? android.app.Activity)?.let { activity ->
                activity.requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 4711)
            }
        }
    }
    app.controller.start(context, params)
}

@Composable
private fun Hero(running: Boolean, done: Boolean, modifier: Modifier = Modifier) {
    val accent = LocalAccent.current
    Row(
        modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                text = "UMBRA",
                style = MaterialTheme.typography.displayLarge,
                color = Mist,
                maxLines = 1,
                softWrap = false,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                "CLOUDFLARE DEEP SCANNER",
                style = MaterialTheme.typography.labelSmall,
                color = Fade,
                letterSpacing = 3.4.sp,
                maxLines = 1,
                softWrap = false,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Spacer(Modifier.width(8.dp))
        val (dotColor, label) = when {
            running -> accent.primary to "LIVE"
            done -> OkMint to "DONE"
            else -> Fog to "IDLE"
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
    onStop: () -> Unit,
) {
    val accent = LocalAccent.current
    NeonCard {
        PhaseBar(current = stats.phase)
        Spacer(Modifier.height(14.dp))
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            RadarPulse(sizeDp = 96.dp)
            Column(Modifier.weight(1f)) {
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    StatCell("TESTED", "${stats.tested}/${stats.candidates}", Modifier.weight(1f))
                    StatCell("ALIVE", stats.alive.toString(), tint = OkMint, modifier = Modifier.weight(1f))
                }
                Spacer(Modifier.height(9.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    StatCell("RATE", "${"%.1f".format(stats.ratePerSec)}/s", Modifier.weight(1f))
                    StatCell("ACTIVE", stats.active.toString(), Modifier.weight(1f))
                }
                Spacer(Modifier.height(9.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    StatCell("ELAPSED", formatElapsed(stats.elapsedMs), Modifier.weight(1f))
                    StatCell(
                        "ETA",
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
            Text("LIVE TOP ENDPOINTS", style = MaterialTheme.typography.labelSmall, color = Fade)
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
                        r.latencyMs?.let { "%.0f ms".format(it) } ?: "—",
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
            text = log.firstOrNull() ?: "warming up…",
            style = MaterialTheme.typography.bodySmall,
            color = Fog,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
        Spacer(Modifier.height(14.dp))
        GradientButton(text = "STOP SCAN", onClick = onStop, danger = true)
    }
}

/**
 * Compact phase progress: a six-segment step bar plus the current phase
 * name. Replaces the old six squeezed text labels that clipped on
 * narrow screens.
 */
@Composable
private fun PhaseBar(current: ScanPhase) {
    val accent = LocalAccent.current
    val phases = listOf(
        ScanPhase.GENERATING,
        ScanPhase.TCP,
        ScanPhase.PROBE,
        ScanPhase.RANKING,
        ScanPhase.SPEED,
        ScanPhase.DONE,
    )
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
    NeonCard {
        Text(
            if (summary.cancelled) "SCAN STOPPED" else "SCAN COMPLETE",
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
                    "ALIVE",
                    style = MaterialTheme.typography.labelSmall.copy(letterSpacing = 1.2.sp),
                    color = Fade,
                    maxLines = 1,
                    softWrap = false,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            StatCell(
                "TESTED",
                "${summary.tested}/${summary.candidates}",
                Modifier.weight(1f),
            )
            StatCell("TIME", formatElapsed(summary.elapsedMs), Modifier.weight(1f))
        }
        Spacer(Modifier.height(14.dp))
        summary.best?.let { best ->
            Column {
                Text("BEST ENDPOINT", style = MaterialTheme.typography.labelSmall, color = Fade)
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
                    StatCell("LAT", best.latencyMs?.let { "%.0fms".format(it) } ?: "—", Modifier.weight(1f))
                    StatCell("JIT", best.jitterMs?.let { "%.0fms".format(it) } ?: "—", Modifier.weight(1f))
                    StatCell("LOSS", "${best.lossPct}%", Modifier.weight(1f))
                    StatCell("SPEED", best.speedMbps?.let { "%.1fM".format(it) } ?: "—", Modifier.weight(1f))
                }
                Spacer(Modifier.height(16.dp))
            }
        }
        GradientButton(text = "VIEW RESULTS", onClick = onGoResults)
        Spacer(Modifier.height(9.dp))
        OutlineButton(text = "CONFIGURE NEW SCAN", onClick = onNewScan, modifier = Modifier.fillMaxWidth())
    }
}

internal fun formatElapsed(ms: Long): String {
    val s = ms / 1000
    return when {
        s < 60 -> "${s}s"
        s < 3600 -> "%d:%02d".format(s / 60, s % 60)
        else -> "%d:%02d:%02d".format(s / 3600, (s % 3600) / 60, s % 60)
    }
}
