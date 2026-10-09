package com.umbra.scanner.ui.components

import android.content.Intent
import android.net.Uri
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.umbra.scanner.core.Project
import com.umbra.scanner.engine.UpdateCenter
import com.umbra.scanner.i18n.LocalStrings
import com.umbra.scanner.ui.theme.Fade
import com.umbra.scanner.ui.theme.Fog
import com.umbra.scanner.ui.theme.LocalAccent
import com.umbra.scanner.ui.theme.MonoStyle
import com.umbra.scanner.ui.theme.MonoStyleSmall

/**
 * Full-screen "new version" announcement, shown when UpdateCenter reports a
 * release the user has not dismissed yet. Spring-scaled entrance, version
 * delta chip, release notes and a one-tap hop to the GitHub release page.
 */
@Composable
fun UpdateDialog(
    state: UpdateCenter.State.Available,
    onDismiss: () -> Unit,
) {
    val accent = LocalAccent.current
    val s = LocalStrings.current
    val context = LocalContext.current

    Box(
        Modifier
            .fillMaxSize()
            .background(Color(0xB204070A)) // dim the app behind the announcement
            .pointerInput(Unit) { awaitEachGesture { awaitFirstDown(requireUnconsumed = false); } }, // v3.2: consume taps — was a see-through scrim
        contentAlignment = Alignment.Center,
    ) {
        AnimatedVisibility(
            visible = true,
            enter = fadeIn(tween(180)) + scaleIn(
                spring(
                    dampingRatio = Spring.DampingRatioLowBouncy,
                    stiffness = Spring.StiffnessMediumLow,
                ),
                initialScale = 0.86f,
            ),
            exit = fadeOut(tween(140)) + scaleOut(tween(160), targetScale = 0.9f),
        ) {
            Column(
                Modifier
                    .padding(horizontal = 26.dp)
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(22.dp))
                    .background(
                        Brush.verticalGradient(
                            listOf(
                                Color(0xFF121820),
                                Color(0xFF0B0F14),
                            )
                        )
                    )
                    .neonOutline(
                        Brush.linearGradient(
                            listOf(
                                accent.primary.copy(alpha = 0.75f),
                                accent.secondary.copy(alpha = 0.45f),
                                accent.primary.copy(alpha = 0.2f),
                            )
                        ),
                        shape = RoundedCornerShape(22.dp),
                    )
                    .padding(20.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    PulsingDot(color = accent.primary, sizeDp = 8.dp)
                    Spacer(Modifier.width(8.dp))
                    Text(
                        s.incomingTransmission,
                        style = MaterialTheme.typography.labelMedium,
                        color = accent.primary,
                        maxLines = 1,
                        softWrap = false,
                    )
                }

                Spacer(Modifier.height(10.dp))
                Text(
                    s.newVersionAvailable,
                    style = MaterialTheme.typography.displayMedium,
                    color = com.umbra.scanner.ui.theme.Mist,
                    maxLines = 1,
                    softWrap = false,
                    overflow = TextOverflow.Ellipsis,
                )

                Spacer(Modifier.height(10.dp))
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(11.dp))
                        .background(Color(0xFF05070A))
                        .padding(horizontal = 12.dp, vertical = 9.dp),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        state.currentVersion,
                        style = MonoStyle,
                        color = Fade,
                        maxLines = 1,
                        softWrap = false,
                    )
                    Spacer(Modifier.width(10.dp))
                    Text("→", style = MonoStyle, color = accent.primary)
                    Spacer(Modifier.width(10.dp))
                    Text(
                        state.release.tag.removePrefix("v"),
                        style = MonoStyle,
                        color = accent.tint,
                        maxLines = 1,
                        softWrap = false,
                    )
                }

                if (!state.release.notes.isNullOrBlank()) {
                    Spacer(Modifier.height(12.dp))
                    Text(
                        state.release.notes.trim(),
                        style = MaterialTheme.typography.bodySmall,
                        color = Fog,
                        maxLines = 8,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(max = 140.dp)
                            .verticalScroll(rememberScrollState()),
                    )
                }

                Spacer(Modifier.height(16.dp))
                GradientButton(
                    text = s.downloadFromGithub,
                    onClick = {
                        runCatching {
                            val url = state.release.apkUrl ?: state.release.pageUrl
                            context.startActivity(
                                Intent(Intent.ACTION_VIEW, Uri.parse(url))
                                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            )
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    height = 48.dp,
                )
                Spacer(Modifier.height(10.dp))
                OutlineButton(
                    text = s.later,
                    onClick = onDismiss,
                    modifier = Modifier.fillMaxWidth(),
                    height = 40.dp,
                )
                Spacer(Modifier.height(12.dp))
                Text(
                    "github.com/${Project.GITHUB_USER}/${Project.GITHUB_REPO}",
                    style = MonoStyleSmall,
                    color = Fade,
                    maxLines = 1,
                    softWrap = false,
                    overflow = TextOverflow.Ellipsis,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }
}
