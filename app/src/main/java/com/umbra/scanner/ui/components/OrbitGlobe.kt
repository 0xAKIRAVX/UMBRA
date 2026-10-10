package com.umbra.scanner.ui.components

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.umbra.scanner.ui.theme.LocalAccent
import com.umbra.scanner.ui.theme.LocalLightFx
import kotlin.math.cos
import kotlin.math.sin

/**
 * The UMBRA v3 signature visual — a wireframe cyber-globe echoing the
 * launcher icon: projected latitude/longitude lines, two counter-rotating
 * orbital rings, traveling nodes, and a soft crimson halo. Single Canvas,
 * draw-phase animations only (no recomposition, no layout, no allocations).
 * Freezes into a static render under LIGHTWEIGHT FX.
 */
@Composable
fun OrbitGlobe(
    modifier: Modifier = Modifier,
    sizeDp: Dp = 128.dp,
    spinning: Boolean = true,
) {
    val accent = LocalAccent.current
    val lightFx = LocalLightFx.current

    if (lightFx || !spinning) {
        Canvas(modifier.size(sizeDp)) { drawGlobe(accent, 0f, 0.18f, 0f, 0f) }
        return
    }

    val t = rememberInfiniteTransition(label = "globe")
    val meridian by t.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(tween(24000, easing = LinearEasing), RepeatMode.Restart),
        label = "meridian",
    )
    val ring1 by t.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(tween(9500, easing = LinearEasing), RepeatMode.Restart),
        label = "ring1",
    )
    val ring2 by t.animateFloat(
        initialValue = 360f,
        targetValue = 0f,
        animationSpec = infiniteRepeatable(tween(13500, easing = LinearEasing), RepeatMode.Restart),
        label = "ring2",
    )

    Canvas(modifier.size(sizeDp)) {
        drawGlobe(
            accent, meridian,
            0.18f + 0.05f * sin(Math.toRadians((meridian * 6.0).toDouble())).toFloat(),
            ring1, ring2,
        )
    }
}

private fun DrawScope.drawGlobe(
    accent: com.umbra.scanner.ui.theme.AccentScheme,
    meridianDeg: Float,
    corePulse: Float,
    node1Deg: Float,
    node2Deg: Float,
) {
    val c = center
    val r = size.minDimension / 2f * 0.66f // globe radius (rings reach beyond)

    // ── halo behind everything ─────────────────────────────────────
    drawCircle(
        brush = Brush.radialGradient(
            colors = listOf(accent.primary.copy(alpha = 0.13f), Color.Transparent),
            center = c,
            radius = size.minDimension * 0.55f,
        ),
        radius = size.minDimension * 0.55f,
        center = c,
    )

    // ── sphere body: dark fill + rim ───────────────────────────────
    drawCircle(
        brush = Brush.radialGradient(
            colors = listOf(
                Color(0xFF070B10),
                Color(0xFF0B1017),
                accent.primary.copy(alpha = 0.10f),
            ),
            center = Offset(c.x, c.y - r * 0.25f),
            radius = r,
        ),
        radius = r,
        center = c,
    )

    val line = 1.15.dp.toPx()
    val wire = accent.primary.copy(alpha = 0.55f)
    val wireDim = accent.primary.copy(alpha = 0.30f)

    // ── latitude lines (projected as ellipses) ─────────────────────
    // three bands: north, equator, south — widths follow sphere projection
    val latRatios = listOf(0.32f to 0.80f, 0.0f to 1f, -0.34f to 0.74f)
    for ((yRatio, wRatio) in latRatios) {
        val ry = r * 0.24f * (1f - kotlin.math.abs(yRatio)) + r * 0.05f
        val rect = androidx.compose.ui.geometry.Rect(
            left = c.x - r * wRatio,
            top = c.y + r * yRatio - ry,
            right = c.x + r * wRatio,
            bottom = c.y + r * yRatio + ry,
        )
        drawOval(
            color = if (yRatio == 0f) wire else wireDim,
            topLeft = Offset(rect.left, rect.top),
            size = rect.size,
            style = androidx.compose.ui.graphics.drawscope.Stroke(line, cap = StrokeCap.Round),
        )
    }

    // ── longitude lines: a wide and a narrow meridian, slowly rotating ──
    rotate(meridianDeg, pivot = c) {
        for ((w, alpha) in listOf(1f to 0.55f, 0.55f to 0.32f, 0.18f to 0.22f)) {
            drawOval(
                color = accent.primary.copy(alpha = alpha),
                topLeft = Offset(c.x - r * w, c.y - r),
                size = androidx.compose.ui.geometry.Size(r * 2f * w, r * 2f),
                style = androidx.compose.ui.graphics.drawscope.Stroke(line, cap = StrokeCap.Round),
            )
        }
    }

    // ── equator + vertical axis accents ────────────────────────────
    drawOval(
        color = accent.glow.copy(alpha = 0.42f),
        topLeft = Offset(c.x - r, c.y - r * 0.12f),
        size = androidx.compose.ui.geometry.Size(r * 2f, r * 0.24f),
        style = androidx.compose.ui.graphics.drawscope.Stroke(1.3.dp.toPx(), cap = StrokeCap.Round),
    )

    // ── core (breathing) ───────────────────────────────────────────
    drawCircle(
        brush = Brush.radialGradient(
            colors = listOf(accent.glow.copy(alpha = 0.85f), accent.primary.copy(alpha = 0.25f), Color.Transparent),
            center = c,
            radius = r * 0.16f * corePulse * 4f,
        ),
        radius = r * 0.14f,
        center = c,
    )
    drawCircle(color = accent.glow.copy(alpha = 0.9f), radius = r * 0.045f, center = c)

    // ── orbital rings + traveling nodes ────────────────────────────
    for ((rotDeg, nodeDeg, ringAlpha, nodePhase) in listOf(
        listOf(-24f, node1Deg, 0.50f, 0f),
        listOf(22f, node2Deg, 0.40f, 0.55f),
    )) {
        val rr = r * 1.28f
        rotate(rotDeg, pivot = c) {
            drawOval(
                color = accent.primary.copy(alpha = ringAlpha.toFloat()),
                topLeft = Offset(c.x - rr, c.y - rr * 0.34f),
                size = androidx.compose.ui.geometry.Size(rr * 2f, rr * 0.68f),
                style = androidx.compose.ui.graphics.drawscope.Stroke(1.05.dp.toPx(), cap = StrokeCap.Round),
            )
            // node riding the ring
            val a = Math.toRadians(nodeDeg.toDouble() + nodePhase.toDouble() * 360)
            val nx = c.x + rr * cos(a)
            val ny = c.y + rr * 0.34f * sin(a)
            drawCircle(
                brush = Brush.radialGradient(
                    colors = listOf(accent.glow, accent.primary.copy(alpha = 0.0f)),
                    center = Offset(nx.toFloat(), ny.toFloat()),
                    radius = 4.5.dp.toPx(),
                ),
                radius = 4.5.dp.toPx(),
                center = Offset(nx.toFloat(), ny.toFloat()),
            )
            drawCircle(
                color = accent.glow,
                radius = 1.7.dp.toPx(),
                center = Offset(nx.toFloat(), ny.toFloat()),
            )
        }
    }

    // fixed polar node — the "satellite" the icon also carries
    drawCircle(
        color = accent.secondary.copy(alpha = 0.85f),
        radius = 1.9.dp.toPx(),
        center = Offset(c.x + r * 0.78f, c.y - r * 0.55f),
    )
}
