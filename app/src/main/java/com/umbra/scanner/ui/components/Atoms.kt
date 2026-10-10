package com.umbra.scanner.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Slider
import androidx.compose.material3.SliderDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.umbra.scanner.ui.theme.Fade
import com.umbra.scanner.ui.theme.Fog
import com.umbra.scanner.ui.theme.Graphite
import com.umbra.scanner.ui.theme.LocalAccent
import com.umbra.scanner.ui.theme.LocalLightFx
import com.umbra.scanner.ui.theme.Mist
import com.umbra.scanner.ui.theme.MonoStyle
import com.umbra.scanner.ui.theme.SlateLine
import com.umbra.scanner.ui.theme.Ultraviolet

// ── design tokens (uniform system) ────────────────────────────────────
// One radius scale for the whole app so every box visually matches:
//   cards 22 · inner panels 12 · chips / small controls 9
val CardShape = RoundedCornerShape(22.dp)
val PanelShape = RoundedCornerShape(12.dp)
val ChipShape = RoundedCornerShape(9.dp)

private val CardPadding = PaddingValues(16.dp)

// ── neon primitives ───────────────────────────────────────────────────

fun Modifier.neonOutline(
    brush: Brush,
    width: Dp = 1.dp,
    shape: Shape = CardShape,
): Modifier = this.then(Modifier.border(width = width, brush = brush, shape = shape))

fun Modifier.softGlow(color: Color, alpha: Float = 0.22f): Modifier =
    this.drawWithCache {
        val radius = size.maxDimension
        val brush = Brush.radialGradient(
            colors = listOf(color.copy(alpha = alpha), Color.Transparent),
            center = Offset(size.width / 2f, size.height / 2f),
            radius = radius,
        )
        onDrawBehind { drawRect(brush) }
    }

/**
 * The app-wide card. Gradient surface + inner accent glow (top-left) +
 * hairline gradient border. Sizes animate smoothly when content grows
 * (advanced panel, auto-tune report, QR reveal) — no more jumpy pops.
 */
@Composable
fun NeonCard(
    modifier: Modifier = Modifier,
    glow: Boolean = true,
    animateContent: Boolean = true,
    contentPadding: PaddingValues = CardPadding,
    content: @Composable ColumnScope.() -> Unit,
) {
    val accent = LocalAccent.current
    val lightFx = LocalLightFx.current
    val topCol = MaterialTheme.colorScheme.surfaceVariant
    val bottomCol = MaterialTheme.colorScheme.surface
    val border = Brush.linearGradient(
        listOf(
            accent.primary.copy(alpha = 0.45f),
            Ultraviolet.copy(alpha = 0.22f),
            accent.primary.copy(alpha = 0.08f),
        )
    )
    Box(modifier) {
        Column(
            Modifier
                .clip(CardShape)
                .drawWithCache {
                    val bg = Brush.verticalGradient(listOf(topCol, bottomCol))
                    val glowAlpha = if (glow && !lightFx) 0.10f else 0.05f
                    val halo = Brush.radialGradient(
                        colors = listOf(accent.primary.copy(alpha = glowAlpha), Color.Transparent),
                        center = Offset(size.width * 0.16f, size.height * 0.02f),
                        radius = size.maxDimension * 1.15f,
                    )
                    onDrawBehind {
                        drawRect(bg)
                        drawRect(halo)
                    }
                }
                .neonOutline(border, shape = CardShape)
                .then(
                    if (animateContent) {
                        Modifier.animateContentSize(
                            animationSpec = spring(
                                dampingRatio = Spring.DampingRatioLowBouncy,
                                stiffness = 340f,
                            )
                        )
                    } else Modifier
                )
                .padding(contentPadding),
            content = content,
        )
    }
}

// ── chips & cells ─────────────────────────────────────────────────────

@Composable
fun SelectChip(
    text: String,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val accent = LocalAccent.current
    val haptic = LocalHapticFeedback.current
    val bg by animateColorAsState(
        if (selected) accent.primary.copy(alpha = 0.16f) else Graphite,
        tween(190), label = "chipBg",
    )
    val bd by animateColorAsState(
        if (selected) accent.primary.copy(alpha = 0.75f) else SlateLine,
        tween(190), label = "chipBd",
    )
    val fg by animateColorAsState(
        if (selected) accent.tint else Fog,
        tween(190), label = "chipFg",
    )
    Box(
        modifier
            .clip(ChipShape)
            .background(bg)
            .border(1.dp, bd, ChipShape)
            .bouncyClickable {
                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                onClick()
            }
            .padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelMedium,
            color = fg,
            maxLines = 1,
            softWrap = false,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

/** Segmented control with a spring-sliding selection pill — never clips. */
@Composable
fun Segmented(
    options: List<String>,
    selected: Int,
    onSelect: (Int) -> Unit,
    modifier: Modifier = Modifier,
) {
    val accent = LocalAccent.current
    BoxWithConstraints(
        modifier
            .height(42.dp)
            .clip(RoundedCornerShape(13.dp))
            .background(Graphite)
            .padding(4.dp)
    ) {
        val itemW = maxWidth / options.size.coerceAtLeast(1)
        val x by animateDpAsState(
            targetValue = itemW * selected,
            animationSpec = spring(
                dampingRatio = Spring.DampingRatioMediumBouncy,
                stiffness = Spring.StiffnessMediumLow,
            ),
            label = "segX",
        )
        // selection pill (behind the labels)
        Box(
            Modifier
                .offset(x = x)
                .width(itemW)
                .fillMaxHeight()
                .clip(RoundedCornerShape(10.dp))
                .background(accent.primary.copy(alpha = 0.18f))
                .border(1.dp, accent.primary.copy(alpha = 0.8f), RoundedCornerShape(10.dp))
        )
        Row(Modifier.fillMaxSize()) {
            options.forEachIndexed { i, opt ->
                val isSel = i == selected
                Box(
                    Modifier
                        .weight(1f)
                        .fillMaxHeight()
                        .bouncyClickable(pressedScale = 0.97f) { onSelect(i) },
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        opt,
                        style = MaterialTheme.typography.labelMedium,
                        color = if (isSel) accent.tint else Fog,
                        maxLines = 1,
                        softWrap = false,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
        }
    }
}

/** Stat readout — value on top, label under. Both single-line ellipsized
 *  so a long value can never blow out of its cell or wrap the layout. */
@Composable
fun StatCell(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
    tint: Color = Mist,
    valueSize: Int = 12,
) {
    Column(modifier, verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(
            value,
            style = MonoStyle.copy(fontSize = valueSize.sp),
            color = tint,
            maxLines = 1,
            softWrap = false,
            overflow = TextOverflow.Ellipsis,
        )
        Text(
            label,
            style = MaterialTheme.typography.labelSmall.copy(
                // v3.8.1 (Persian glyph-breaking fix): a fixed 1.2sp tracking
                // visually tears connected Arabic-script letters apart — the
                // Hero/tagline rows already guard on script range, this most-
                // used cell component missed it. Latin/technical labels keep
                // the tracked look; Persian labels render untracked.
                letterSpacing = if (label.all { it.code < 0x590 }) 1.2.sp else 0.sp
            ),
            color = Fade,
            maxLines = 1,
            softWrap = false,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
fun SectionLabel(text: String, modifier: Modifier = Modifier) {
    val accent = LocalAccent.current
    Row(modifier, verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier
                .size(width = 3.dp, height = 13.dp)
                .background(accent.primary, RoundedCornerShape(2.dp))
        )
        Spacer(Modifier.width(8.dp))
        Text(
            text,
            style = MaterialTheme.typography.labelSmall,
            color = Fog,
            maxLines = 1,
            softWrap = false,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

// ── buttons ───────────────────────────────────────────────────────────

@Composable
fun GradientButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    height: Dp = 52.dp,
    enabled: Boolean = true,
    danger: Boolean = false,
) {
    val accent = LocalAccent.current
    val haptic = LocalHapticFeedback.current
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val scale = animateFloatAsState(
        targetValue = if (pressed) 0.97f else 1f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioMediumBouncy,
            stiffness = Spring.StiffnessMediumLow,
        ),
        label = "btnPress",
    )
    val colors = if (danger) {
        listOf(Color(0xFFFF4D8D), Color(0xFFB22B62))
    } else {
        listOf(accent.primary, accent.secondary.copy(alpha = 0.85f))
    }
    Box(
        modifier
            .height(height)
            .graphicsLayer {
                scaleX = scale.value
                scaleY = scale.value
                alpha = if (enabled) 1f else 0.5f
            }
            .clip(RoundedCornerShape(15.dp))
            .background(Brush.horizontalGradient(colors))
            .shimmerSweep(enabled = enabled, bandAlpha = 0.13f)
            .clickable(interactionSource = interaction, indication = null, enabled = enabled) {
                haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                onClick()
            },
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text,
            style = MaterialTheme.typography.labelLarge,
            color = if (danger) Color(0xFFFFF0F5) else Color(0xFF04110C),
            maxLines = 1,
            softWrap = false,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(horizontal = 14.dp),
        )
    }
}

@Composable
fun OutlineButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    height: Dp = 44.dp,
) {
    val accent = LocalAccent.current
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val scale = animateFloatAsState(
        targetValue = if (pressed) 0.97f else 1f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioMediumBouncy,
            stiffness = Spring.StiffnessMediumLow,
        ),
        label = "oPress",
    )
    Box(
        modifier
            .height(height)
            .graphicsLayer { scaleX = scale.value; scaleY = scale.value }
            .clip(RoundedCornerShape(13.dp))
            .border(1.dp, accent.primary.copy(alpha = 0.6f), RoundedCornerShape(13.dp))
            .clickable(interactionSource = interaction, indication = null) { onClick() },
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text,
            style = MaterialTheme.typography.labelLarge,
            color = accent.tint,
            maxLines = 1,
            softWrap = false,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(horizontal = 12.dp),
        )
    }
}

@Composable
fun ActionRow(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    tint: Color = Mist,
    onClick: () -> Unit,
) {
    val accent = LocalAccent.current
    Row(
        Modifier
            .fillMaxWidth()
            .clip(PanelShape)
            .background(Graphite)
            .bouncyClickable(pressedScale = 0.98f) { onClick() }
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        androidx.compose.material3.Icon(
            icon, contentDescription = null,
            tint = if (tint == Mist) accent.primary else tint,
            modifier = Modifier.size(17.dp),
        )
        Spacer(Modifier.width(10.dp))
        Text(
            label,
            style = MaterialTheme.typography.labelLarge,
            color = tint,
            maxLines = 1,
            softWrap = false,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

// ── progress ──────────────────────────────────────────────────────────
// Fully draw-phase animated (value + shimmer read inside onDrawBehind):
// no fillMaxWidth() layout animation, no recomposition per frame.

@Composable
fun UmbraProgress(progress: Float, modifier: Modifier = Modifier) {
    val accent = LocalAccent.current
    val lightFx = LocalLightFx.current
    val animated = animateFloatAsState(
        targetValue = progress.coerceIn(0f, 1f),
        animationSpec = tween(350, easing = FastOutSlowInEasing),
        label = "progress",
    )
    val shimmer = if (lightFx) null else rememberInfiniteTransition(label = "pShim")
        .animateFloat(
            initialValue = 0f,
            targetValue = 1f,
            animationSpec = infiniteRepeatable(tween(1700, easing = LinearEasing), RepeatMode.Restart),
            label = "pShf",
        )
    Box(
        modifier
            .height(6.dp)
            .fillMaxWidth()
            .clip(RoundedCornerShape(3.dp))
            .background(SlateLine)
            .drawWithCache {
                val fill = Brush.horizontalGradient(listOf(accent.secondary, accent.primary))
                onDrawBehind {
                    val w = size.width * animated.value
                    if (w <= 0f) return@onDrawBehind
                    drawRect(fill, size = Size(w, size.height))
                    // glow head at the leading edge
                    drawCircle(
                        color = accent.primary.copy(alpha = 0.60f),
                        radius = size.height * 1.1f,
                        center = Offset(w, size.height / 2f),
                    )
                    // travelling light band inside the filled part
                    shimmer?.let { s ->
                        val band = w * 0.5f
                        val x = s.value * (w + band) - band
                        val bandBrush = Brush.horizontalGradient(
                            colors = listOf(
                                Color.Transparent,
                                Color.White.copy(alpha = 0.22f),
                                Color.Transparent,
                            ),
                            startX = x,
                            endX = x + band,
                        )
                        drawRect(bandBrush, size = Size(w, size.height))
                    }
                }
            }
    )
}

// ── toggles ───────────────────────────────────────────────────────────

@Composable
fun ToggleRow(
    title: String,
    subtitle: String?,
    checked: Boolean,
    onChange: (Boolean) -> Unit,
) {
    val accent = LocalAccent.current
    Row(
        Modifier
            .fillMaxWidth()
            .clip(PanelShape)
            .clickable { onChange(!checked) }
            .padding(vertical = 9.dp, horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                title,
                style = MaterialTheme.typography.titleMedium,
                color = Mist,
                maxLines = 1,
                softWrap = false,
                overflow = TextOverflow.Ellipsis,
            )
            if (subtitle != null) {
                Text(
                    subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = Fade,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        Spacer(Modifier.width(8.dp))
        Switch(
            checked = checked,
            onCheckedChange = onChange,
            colors = SwitchDefaults.colors(
                checkedThumbColor = accent.tint,
                checkedTrackColor = accent.primary.copy(alpha = 0.45f),
                uncheckedThumbColor = Fog,
                uncheckedTrackColor = Graphite,
                uncheckedBorderColor = SlateLine,
            ),
        )
    }
}

// ── sliders ───────────────────────────────────────────────────────────

@Composable
fun LabeledSlider(
    label: String,
    value: Int,
    onValueChange: (Int) -> Unit,
    valueRange: IntProgression,
    modifier: Modifier = Modifier,
    valueText: String = value.toString(),
) {
    val accent = LocalAccent.current
    Column(modifier) {
        Row(Modifier.fillMaxWidth()) {
            Text(
                label,
                style = MaterialTheme.typography.labelMedium,
                color = Fog,
                maxLines = 1,
                softWrap = false,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
            Text(
                valueText,
                style = MonoStyle.copy(fontSize = 12.sp),
                color = accent.tint,
                maxLines = 1,
                softWrap = false,
            )
        }
        Slider(
            value = value.toFloat(),
            onValueChange = { onValueChange(it.toInt()) },
            valueRange = valueRange.first.toFloat()..valueRange.last.toFloat(),
            colors = SliderDefaults.colors(
                thumbColor = accent.primary,
                activeTrackColor = accent.primary.copy(alpha = 0.7f),
                inactiveTrackColor = SlateLine,
            ),
        )
    }
}
