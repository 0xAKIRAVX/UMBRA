package com.umbra.scanner.ui.components

import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.animateIntAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.material3.Text
import com.umbra.scanner.ui.theme.LocalAccent
import com.umbra.scanner.ui.theme.LocalLightFx

// ── press feedback ─────────────────────────────────────────────────────
// State is read inside the graphicsLayer lambda → animation stays in the
// draw phase, zero recomposition, zero layout passes. 120 fps friendly.

@Composable
fun Modifier.bouncyClickable(
    enabled: Boolean = true,
    pressedScale: Float = 0.955f,
    onClick: () -> Unit,
): Modifier {
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val scale = animateFloatAsState(
        targetValue = if (pressed) pressedScale else 1f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioMediumBouncy,
            stiffness = Spring.StiffnessMediumLow,
        ),
        label = "press",
    )
    return this
        .graphicsLayer { scaleX = scale.value; scaleY = scale.value }
        .clickable(interactionSource = interaction, indication = null, enabled = enabled) { onClick() }
}

// ── staggered entrance ─────────────────────────────────────────────────

@Composable
fun Modifier.staggerIn(
    index: Int,
    key: Any = Unit,
    delayMs: Long = 55L,
    rise: Float = 26f,
): Modifier {
    var shown by remember(key) { mutableStateOf(false) }
    LaunchedEffect(key) {
        kotlinx.coroutines.delay(index * delayMs)
        shown = true
    }
    val progress = animateFloatAsState(
        targetValue = if (shown) 1f else 0f,
        animationSpec = tween(430, easing = FastOutSlowInEasing),
        label = "stagger",
    )
    return graphicsLayer {
        alpha = progress.value
        translationY = (1f - progress.value) * rise
    }
}

// ── shimmer sweep ──────────────────────────────────────────────────────
// A diagonal light band that periodically travels across the element.
// Drawn behind the content (under text), over the background.

@Composable
fun Modifier.shimmerSweep(
    enabled: Boolean = true,
    bandAlpha: Float = 0.15f,
    periodMs: Int = 3600,
): Modifier {
    if (!enabled) return this
    val lightFx = LocalLightFx.current
    if (lightFx) return this
    val t = rememberInfiniteTransition(label = "shimmer")
    val f = t.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(periodMs, easing = LinearEasing), RepeatMode.Restart),
        label = "shf",
    )
    return drawWithContent {
        drawContent()
        val w = size.width.coerceAtLeast(1f)
        val h = size.height
        val band = w * 0.55f
        val x = f.value * (w + band * 2f) - band
        val brush = Brush.linearGradient(
            colors = listOf(
                Color.Transparent,
                Color.White.copy(alpha = bandAlpha),
                Color.Transparent,
            ),
            start = Offset(x, 0f),
            end = Offset(x + band, h),
        )
        drawRect(brush)
    }
}

// ── aurora background ──────────────────────────────────────────────────
// Two huge, ultra-faint accent orbs that slowly orbit the screen center.
// A single drawWithCache pass — brushes allocated once, motion is a pure
// rotation matrix. Freezes into a static gradient under LIGHTWEIGHT FX.

@Composable
fun AuroraBackground(modifier: Modifier = Modifier) {
    val accent = LocalAccent.current
    val lightFx = LocalLightFx.current
    val drift = rememberInfiniteTransition(label = "aurora")
    val a1 = drift.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(tween(38000, easing = LinearEasing), RepeatMode.Restart),
        label = "a1",
    )
    val a2 = drift.animateFloat(
        initialValue = 360f,
        targetValue = 0f,
        animationSpec = infiniteRepeatable(tween(52000, easing = LinearEasing), RepeatMode.Restart),
        label = "a2",
    )
    Box(
        modifier
            .fillMaxSize()
            .drawWithCache {
                val r = size.maxDimension
                val orb1 = Brush.radialGradient(
                    colors = listOf(accent.primary.copy(alpha = 0.055f), Color.Transparent),
                    center = Offset(size.width * 0.30f, size.height * 0.20f),
                    radius = r * 0.80f,
                )
                val orb2 = Brush.radialGradient(
                    colors = listOf(accent.secondary.copy(alpha = 0.045f), Color.Transparent),
                    center = Offset(size.width * 0.72f, size.height * 0.80f),
                    radius = r * 0.90f,
                )
                onDrawBehind {
                    if (lightFx) {
                        drawRect(orb1)
                        drawRect(orb2)
                    } else {
                        // slow orbit: rotating the cached gradient rect around
                        // the center — a matrix transform, no allocations.
                        rotate(a1.value) { drawRect(orb1) }
                        rotate(a2.value) { drawRect(orb2) }
                    }
                }
            },
    )
}

// ── count-up value ─────────────────────────────────────────────────────

@Composable
fun AnimatedCountText(
    value: Int,
    style: TextStyle,
    color: Color,
    modifier: Modifier = Modifier,
    prefix: String = "",
    suffix: String = "",
) {
    val a = animateIntAsState(
        targetValue = value,
        animationSpec = tween(700, easing = FastOutSlowInEasing),
        label = "count",
    )
    Text(
        text = "$prefix${a.value}$suffix",
        style = style,
        color = color,
        maxLines = 1,
        softWrap = false,
        overflow = TextOverflow.Ellipsis,
        modifier = modifier,
    )
}

// ── soft breathing alpha (finite, cheap) ───────────────────────────────

@Composable
fun rememberBreath(periodMs: Int = 3200): Float {
    val lightFx = LocalLightFx.current
    if (lightFx) return 1f
    val t = rememberInfiniteTransition(label = "breath")
    val v by t.animateFloat(
        initialValue = 0.82f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            tween(periodMs, easing = FastOutSlowInEasing),
            RepeatMode.Reverse,
        ),
        label = "b",
    )
    return v
}
