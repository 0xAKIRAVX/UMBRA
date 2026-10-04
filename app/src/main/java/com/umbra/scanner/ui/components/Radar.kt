package com.umbra.scanner.ui.components

import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.umbra.scanner.ui.theme.LocalAccent
import com.umbra.scanner.ui.theme.LocalLightFx
import com.umbra.scanner.ui.theme.SlateLine
import kotlin.math.cos
import kotlin.math.sin

/**
 * Animated radar reticle: rotating sweep wedge, two expanding echo rings,
 * a breathing core and a trailing node. Single Canvas, cached brushes —
 * no layout passes and no per-frame allocations. Freezes under LIGHTWEIGHT FX.
 */
@Composable
fun RadarPulse(
    modifier: Modifier = Modifier,
    sizeDp: Dp = 124.dp,
    spinning: Boolean = true,
) {
    val accent = LocalAccent.current
    val lightFx = LocalLightFx.current

    if (lightFx) {
        Canvas(modifier.size(sizeDp)) {
            drawStaticRadar(accent.primary, accent.secondary)
        }
        return
    }

    val transition = rememberInfiniteTransition(label = "radar")
    val sweep by transition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(tween(1900, easing = LinearEasing), RepeatMode.Restart),
        label = "sweep",
    )
    val pulse by transition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(1500, easing = FastOutSlowInEasing), RepeatMode.Restart),
        label = "pulse",
    )
    val sweepBrush = remember(accent) {
        Brush.sweepGradient(
            listOf(
                Color.Transparent,
                accent.primary.copy(alpha = 0.0f),
                accent.primary.copy(alpha = 0.40f),
                Color.Transparent,
            )
        )
    }

    Canvas(modifier.size(sizeDp)) {
        drawStaticRadar(accent.primary, accent.secondary)
        // sweep wedge
        rotate(sweep, pivot = center) {
            drawArc(
                brush = sweepBrush,
                startAngle = -90f,
                sweepAngle = 95f,
                useCenter = true,
            )
        }
        // two expanding echo rings, offset half a cycle apart
        for (k in 0..1) {
            val ph = (pulse + k * 0.5f) % 1f
            drawCircle(
                color = accent.primary.copy(alpha = (1f - ph) * 0.30f),
                radius = size.minDimension * (0.22f + 0.26f * ph),
                style = Stroke(1.2.dp.toPx()),
            )
        }
        // breathing core
        drawCircle(
            color = accent.glow.copy(alpha = 0.22f + 0.30f * pulse),
            radius = this.size.minDimension * (0.055f + 0.05f * pulse),
        )
        drawCircle(color = accent.primary, radius = this.size.minDimension * 0.032f)
        // trailing node
        val rad = Math.toRadians(sweep.toDouble())
        val r = this.size.minDimension * 0.40f
        drawCircle(
            color = accent.secondary,
            radius = 2.6.dp.toPx(),
            center = Offset(center.x + (r * cos(rad)).toFloat(), center.y + (r * sin(rad)).toFloat()),
        )
    }
}

private fun androidx.compose.ui.graphics.drawscope.DrawScope.drawStaticRadar(
    primary: Color,
    secondary: Color,
) {
    val r = size.minDimension / 2f
    val c = center
    val ring = Stroke(1.1.dp.toPx())
    for (i in 1..3) {
        drawCircle(SlateLine, radius = r * i / 3f, center = c, style = ring)
    }
    drawLine(SlateLine, Offset(c.x - r, c.y), Offset(c.x + r, c.y), 1f)
    drawLine(SlateLine, Offset(c.x, c.y - r), Offset(c.x, c.y + r), 1f)
    drawCircle(color = primary, radius = r * 0.032f, center = c)
    drawCircle(color = secondary.copy(alpha = 0.7f), radius = 2.6.dp.toPx(), center = Offset(c.x + r * 0.78f, c.y - r * 0.32f))
}

/** Status dot with a soft halo — used in headers and empty states. */
@Composable
fun PulsingDot(color: Color, modifier: Modifier = Modifier, sizeDp: Dp = 9.dp) {
    val lightFx = LocalLightFx.current
    if (lightFx) {
        Box(
            modifier
                .size(sizeDp)
                .clip(CircleShape)
                .background(color)
        )
        return
    }
    val transition = rememberInfiniteTransition(label = "dot")
    val alpha by transition.animateFloat(
        initialValue = 0.35f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(900, easing = FastOutSlowInEasing), RepeatMode.Reverse),
        label = "alpha",
    )
    Box(modifier, contentAlignment = androidx.compose.ui.Alignment.Center) {
        // soft halo
        Box(
            Modifier
                .size(sizeDp * 1.6f)
                .clip(CircleShape)
                .background(color.copy(alpha = 0.22f * alpha))
        )
        Box(
            Modifier
                .size(sizeDp)
                .clip(CircleShape)
                .background(color.copy(alpha = alpha))
        )
    }
}
