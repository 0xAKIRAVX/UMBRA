package com.umbra.scanner.ui

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.Leaderboard
import androidx.compose.material.icons.rounded.Radar
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.umbra.scanner.UmbraApp
import com.umbra.scanner.engine.UpdateCenter
import com.umbra.scanner.i18n.LocalStrings
import com.umbra.scanner.ui.components.AuroraBackground
import com.umbra.scanner.ui.components.UpdateDialog
import com.umbra.scanner.ui.components.bouncyClickable
import com.umbra.scanner.ui.screens.ResultsScreen
import com.umbra.scanner.ui.screens.ScanScreen
import com.umbra.scanner.ui.screens.SettingsScreen
import com.umbra.scanner.ui.screens.VlessScreen
import com.umbra.scanner.ui.theme.Fade
import com.umbra.scanner.ui.theme.Fog
import com.umbra.scanner.ui.theme.Graphite
import com.umbra.scanner.ui.theme.LocalAccent
import com.umbra.scanner.ui.theme.SlateLine

private data class Dest(
    val label: (com.umbra.scanner.i18n.AppStrings) -> String,
    val icon: ImageVector,
)

private val DESTS = listOf(
    Dest({ it.navScan }, Icons.Rounded.Radar),
    Dest({ it.navResults }, Icons.Rounded.Leaderboard),
    Dest({ it.navVless }, Icons.Rounded.Key),
    Dest({ it.navSystem }, Icons.Rounded.Tune),
)

@Composable
fun UmbraRoot(app: UmbraApp) {
    var destIdx by rememberSaveable { mutableIntStateOf(0) }
    val controller = app.controller
    val results by controller.results.collectAsState()
    val updateState by app.updateCenter.state.collectAsState()
    val dismissedTag by app.settings.dismissedUpdateTag.collectAsState()

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        bottomBar = { UmbraNav(selected = destIdx, resultCount = results.size) { destIdx = it } },
    ) { pad ->
        Box(
            Modifier
                .fillMaxSize()
                .padding(bottom = pad.calculateBottomPadding())
        ) {
            // ambient drifting glow behind everything
            AuroraBackground()
            AnimatedContent(
                targetState = destIdx,
                transitionSpec = {
                    val dir = if (targetState > initialState) 1 else -1
                    (fadeIn(tween(230)) + slideInHorizontally(tween(260)) { dir * it / 8 }) togetherWith
                        (fadeOut(tween(140)) + slideOutHorizontally(tween(190)) { -dir * it / 12 })
                },
                label = "dest",
            ) { d ->
                when (d) {
                    0 -> ScanScreen(app = app, onGoResults = { destIdx = 1 })
                    1 -> ResultsScreen(app = app, onGoScan = { destIdx = 0 }, onGoVless = { destIdx = 2 })
                    2 -> VlessScreen(app = app)
                    else -> SettingsScreen(app = app)
                }
            }

            // new-version announcement, layered above every screen
            val announce = updateState is UpdateCenter.State.Available &&
                (updateState as UpdateCenter.State.Available).release.tag != dismissedTag
            if (announce) {
                UpdateDialog(
                    state = updateState as UpdateCenter.State.Available,
                    onDismiss = { app.updateCenter.dismiss() },
                )
            }
        }
    }
}

/**
 * v3 floating dock — the nav detaches from the screen edge into an elevated
 * rounded slab with a gradient hairline crest and the sliding selection pill.
 */
@Composable
private fun UmbraNav(
    selected: Int,
    resultCount: Int,
    onSelect: (Int) -> Unit,
) {
    val accent = LocalAccent.current
    val s = LocalStrings.current
    val haptic = LocalHapticFeedback.current
    Column(Modifier.fillMaxWidth()) {
        Box(
            Modifier
                .fillMaxWidth()
                .height(1.dp)
                .background(
                    Brush.horizontalGradient(
                        listOf(
                            SlateLine,
                            accent.primary.copy(alpha = 0.45f),
                            SlateLine,
                        )
                    )
                )
        )
        Box(Modifier.fillMaxWidth().background(Graphite.copy(alpha = 0.86f))) {
            Box(Modifier.navigationBarsPadding().padding(vertical = 7.dp, horizontal = 10.dp)) {
                BoxWithConstraints(Modifier.fillMaxWidth().height(54.dp)) {
                    val itemW = maxWidth / DESTS.size
                    val pillX by animateDpAsState(
                        targetValue = itemW * selected,
                        animationSpec = spring(
                            dampingRatio = Spring.DampingRatioMediumBouncy,
                            stiffness = Spring.StiffnessMediumLow,
                        ),
                        label = "navPill",
                    )
                    // sliding selection pill behind the items
                    Box(
                        Modifier
                            .offset(x = pillX)
                            .width(itemW)
                            .fillMaxSize()
                            .padding(vertical = 3.dp, horizontal = 8.dp)
                            .clip(RoundedCornerShape(13.dp))
                            .background(
                                Brush.verticalGradient(
                                    listOf(
                                        accent.primary.copy(alpha = 0.16f),
                                        accent.primary.copy(alpha = 0.09f),
                                    )
                                )
                            )
                            .border(
                                1.dp,
                                accent.primary.copy(alpha = 0.50f),
                                RoundedCornerShape(13.dp),
                            )
                    )
                    Row(
                        Modifier.fillMaxSize(),
                        horizontalArrangement = Arrangement.SpaceEvenly,
                    ) {
                        DESTS.forEachIndexed { i, d ->
                            val isSel = i == selected
                            val iconScale = animateFloatAsState(
                                targetValue = if (isSel) 1.15f else 1f,
                                animationSpec = spring(
                                    dampingRatio = Spring.DampingRatioMediumBouncy,
                                    stiffness = Spring.StiffnessMediumLow,
                                ),
                                label = "navIcon",
                            )
                            Column(
                                Modifier
                                    .weight(1f)
                                    .fillMaxSize()
                                    .bouncyClickable(pressedScale = 0.90f) {
                                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                        onSelect(i)
                                    },
                                verticalArrangement = Arrangement.Center,
                                horizontalAlignment = Alignment.CenterHorizontally,
                            ) {
                                Box {
                                    Icon(
                                        imageVector = d.icon,
                                        contentDescription = null,
                                        tint = if (isSel) accent.primary else Fog,
                                        modifier = Modifier
                                            .size(19.dp)
                                            .graphicsLayerScale(iconScale.value),
                                    )
                                    if (i == 1 && resultCount > 0) {
                                        Box(
                                            Modifier
                                                .align(Alignment.TopEnd)
                                                .offset(x = 4.dp, y = (-2).dp)
                                                .size(5.dp)
                                                .clip(CircleShape)
                                                .background(accent.secondary)
                                        )
                                    }
                                }
                                Spacer(Modifier.height(3.dp))
                                Text(
                                    d.label(s),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = if (isSel) accent.tint else Fade,
                                    maxLines = 1,
                                    softWrap = false,
                                    overflow = TextOverflow.Ellipsis,
                                )
                                Spacer(Modifier.height(3.dp))
                                // animated underline
                                Box(
                                    Modifier
                                        .width(20.dp)
                                        .height(2.dp)
                                        .graphicsLayerScaleX(if (isSel) 1f else 0.05f)
                                        .clip(RoundedCornerShape(1.dp))
                                        .background(accent.primary)
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

private fun Modifier.graphicsLayerScale(scale: Float): Modifier =
    graphicsLayer { scaleX = scale; scaleY = scale }

private fun Modifier.graphicsLayerScaleX(scaleX: Float): Modifier =
    graphicsLayer { this.scaleX = scaleX }
