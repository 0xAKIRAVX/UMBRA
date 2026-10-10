package com.umbra.scanner.ui.components

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Insights
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.umbra.scanner.UmbraApp
import com.umbra.scanner.i18n.LocalStrings
import com.umbra.scanner.net.NetGrade
import com.umbra.scanner.net.NetworkProfile
import com.umbra.scanner.ui.theme.DangerRose
import com.umbra.scanner.ui.theme.Fade
import com.umbra.scanner.ui.theme.Fog
import com.umbra.scanner.ui.theme.Graphite
import com.umbra.scanner.ui.theme.LocalAccent
import com.umbra.scanner.ui.theme.Mist
import com.umbra.scanner.ui.theme.MonoStyle
import com.umbra.scanner.ui.theme.MonoStyleSmall
import com.umbra.scanner.ui.theme.OkMint
import com.umbra.scanner.ui.theme.SlateLine
import com.umbra.scanner.ui.theme.WarnAmber

/**
 * NETSENSE card (v3.1) — the "وضعیت نت من" measurement entry point.
 *
 * Idle → invite + MEASURE button · Measuring → live step line · Measured →
 * grade ring + the full metric grid (ping / jitter / loss / down / up / IPv6)
 * + DPI warning when the line fakes TCP handshakes. The stored profile is
 * what SmartRanking weighs every result against.
 */
@Composable
fun NetStatusCard(app: UmbraApp, modifier: Modifier = Modifier) {
    val accent = LocalAccent.current
    val s = LocalStrings.current
    val center = app.netStatus
    val profile by center.profile.collectAsState()
    val measuring by center.measuring.collectAsState()
    val step by center.step.collectAsState()

    NeonCard(modifier = modifier) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                Icons.Rounded.Insights,
                null,
                tint = if (measuring) accent.primary else accent.tint,
                modifier = Modifier.size(17.dp),
            )
            Spacer(Modifier.width(8.dp))
            Text(
                s.netCheck,
                style = MaterialTheme.typography.labelMedium,
                color = accent.tint,
                modifier = Modifier.weight(1f),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (!measuring) {
                profile?.let { p ->
                    GradeChip(p.grade)
                }
            }
        }
        Spacer(Modifier.height(4.dp))
        Text(
            s.netCheckHint,
            style = MaterialTheme.typography.bodySmall,
            color = Fade,
        )
        Spacer(Modifier.height(10.dp))

        AnimatedContent(
            targetState = measuring,
            transitionSpec = { fadeIn(tween(220)) togetherWith fadeOut(tween(150)) },
            label = "netState",
        ) { busy ->
            when {
                busy -> MeasuringBody(step)
                profile != null -> MeasuredBody(
                    profile = profile!!,
                    onReMeasure = { center.startMeasure() },
                )
                else -> IdleBody { center.startMeasure() }
            }
        }
    }
}

@Composable
private fun IdleBody(onMeasure: () -> Unit) {
    GradientButton(
        text = LocalStrings.current.measureMyNet,
        onClick = onMeasure,
        modifier = Modifier.fillMaxWidth(),
        height = 44.dp,
    )
}

@Composable
private fun MeasuringBody(step: String?) {
    val accent = LocalAccent.current
    val s = LocalStrings.current
    Row(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(11.dp))
            .background(Graphite.copy(alpha = 0.7f))
            .padding(horizontal = 12.dp, vertical = 11.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        PulsingDot(color = accent.primary, sizeDp = 7.dp)
        Spacer(Modifier.width(9.dp))
        Column(Modifier.weight(1f)) {
            Text(
                s.measuringNet,
                style = MaterialTheme.typography.labelMedium,
                color = Mist,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            step?.let {
                Spacer(Modifier.height(2.dp))
                Text(
                    "▸ $it",
                    style = MonoStyleSmall.copy(fontSize = 10.5.sp),
                    color = Fog,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}

@Composable
private fun MeasuredBody(profile: NetworkProfile, onReMeasure: () -> Unit) {
    val s = LocalStrings.current
    val accent = LocalAccent.current

    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        GradeRing(profile.grade)
        Column(Modifier.weight(1f)) {
            Text(
                gradeLabel(profile.grade),
                style = MaterialTheme.typography.titleMedium,
                color = gradeColor(profile.grade),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Spacer(Modifier.height(2.dp))
            Text(
                s.measuredAgoMin(profile.ageMinutes),
                style = MaterialTheme.typography.labelSmall,
                color = Fade,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (profile.dpiSuspected) {
                Spacer(Modifier.height(5.dp))
                Text(
                    s.dpiDetected,
                    style = MonoStyleSmall.copy(fontSize = 9.5.sp, color = WarnAmber),
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis,
                )
            } else if (profile.latencyMs == null) {
                Spacer(Modifier.height(5.dp))
                Text(
                    s.netOffline,
                    style = MonoStyleSmall.copy(fontSize = 9.5.sp, color = DangerRose),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
    Spacer(Modifier.height(10.dp))
    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        StatCell(s.lat, profile.latencyMs?.let { "${"%.0f".format(java.util.Locale.US, it)}ms" } ?: "—", Modifier.weight(1f))
        StatCell(s.jit, profile.jitterMs?.let { "${"%.0f".format(java.util.Locale.US, it)}ms" } ?: "—", Modifier.weight(1f))
        StatCell(s.loss, "${(profile.packetLoss * 100).toInt()}%", Modifier.weight(1f))
    }
    Spacer(Modifier.height(9.dp))
    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        StatCell(
            s.netDown,
            profile.downloadMbps?.let { "${"%.1f".format(java.util.Locale.US, it)}M" } ?: "—",
            Modifier.weight(1f),
            tint = OkMint,
        )
        StatCell(
            s.netUp,
            profile.uploadMbps?.let { "${"%.1f".format(java.util.Locale.US, it)}M" } ?: "—",
            Modifier.weight(1f),
            tint = OkMint,
        )
        StatCell(
            if (profile.v6Ok) s.ipv6Live else s.ipv6Dead,
            if (profile.v6Ok) "●" else "○",
            Modifier.weight(1f),
            tint = if (profile.v6Ok) OkMint else Fog,
        )
    }
    Spacer(Modifier.height(10.dp))
    OutlineButton(
        text = s.reMeasure,
        onClick = onReMeasure,
        modifier = Modifier.fillMaxWidth(),
        height = 38.dp,
    )
}

// ── grade visuals ────────────────────────────────────────────────────

@Composable
private fun gradeColor(g: NetGrade): Color = when (g) {
    NetGrade.EXCELLENT -> OkMint
    NetGrade.GOOD -> LocalAccent.current.primary
    NetGrade.FAIR -> WarnAmber
    NetGrade.POOR -> DangerRose
}

@Composable
private fun gradeLabel(g: NetGrade): String {
    val s = LocalStrings.current
    return when (g) {
        NetGrade.EXCELLENT -> s.gradeExcellent
        NetGrade.GOOD -> s.gradeGood
        NetGrade.FAIR -> s.gradeFair
        NetGrade.POOR -> s.gradePoor
    }
}

/** Compact pill with the grade initial — used in the card header. */
@Composable
internal fun GradeChip(g: NetGrade) {
    val color = gradeColor(g)
    Box(
        Modifier
            .clip(RoundedCornerShape(8.dp))
            .background(color.copy(alpha = 0.13f))
            .border(1.dp, color.copy(alpha = 0.65f), RoundedCornerShape(8.dp))
            .padding(horizontal = 8.dp, vertical = 3.dp),
    ) {
        Text(
            gradeLabel(g),
            style = MaterialTheme.typography.labelSmall,
            color = color,
            maxLines = 1,
            softWrap = false,
        )
    }
}

/** 40dp ring with the network's grade letter breathing in the middle. */
@Composable
private fun GradeRing(g: NetGrade) {
    val color = gradeColor(g)
    val letter = gradeLabel(g).take(1)
    val lightFx = com.umbra.scanner.ui.theme.LocalLightFx.current
    val breath = if (lightFx) 1f else rememberInfiniteTransition(label = "gradeBreath")
        .animateFloat(
            initialValue = 0.75f,
            targetValue = 1f,
            animationSpec = infiniteRepeatable(tween(1400, easing = LinearEasing), RepeatMode.Reverse),
            label = "gradeBreathA",
        ).value
    Box(
        Modifier
            .size(44.dp)
            .graphicsLayer { alpha = 0.55f + 0.45f * breath }
            .border(2.dp, color.copy(alpha = 0.8f), RoundedCornerShape(22.dp))
            .background(color.copy(alpha = 0.10f), RoundedCornerShape(22.dp)),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            letter,
            style = MonoStyle.copy(fontSize = 15.sp, color = color),
            maxLines = 1,
            softWrap = false,
        )
    }
}
