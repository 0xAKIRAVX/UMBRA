package com.umbra.scanner.ui.components

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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Bolt
import androidx.compose.material.icons.rounded.Public
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material.icons.rounded.Verified
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.umbra.scanner.core.ScanResult
import com.umbra.scanner.core.SmartRanking
import com.umbra.scanner.i18n.LocalStrings
import com.umbra.scanner.net.NetGrade
import com.umbra.scanner.net.NetworkProfile
import com.umbra.scanner.ui.theme.Fade
import com.umbra.scanner.ui.theme.Fog
import com.umbra.scanner.ui.theme.Graphite
import com.umbra.scanner.ui.theme.LocalAccent
import com.umbra.scanner.ui.theme.Mist
import com.umbra.scanner.ui.theme.MonoStyle
import com.umbra.scanner.ui.theme.MonoStyleSmall
import com.umbra.scanner.ui.theme.OkMint
import com.umbra.scanner.ui.theme.SlateLine

/**
 * SMART PICK BOARD (v3.1) — the answer to «پرسرعت‌ترین · پایدارترین · کمترین
 * پینگ، با توجه به نت من».
 *
 * One row per family (WARP + CF EDGE), each carrying the four picks computed
 * with the measured network profile: adaptive BEST, lowest PING, most STABLE,
 * and FASTEST. Tapping a pick opens its full detail sheet. When both buckets
 * have data the user sees the best of BOTH worlds on one screen.
 */
@Composable
fun SmartPickBoard(
    profile: NetworkProfile?,
    warpResults: List<ScanResult>,
    edgeResults: List<ScanResult>,
    onPick: (ScanResult) -> Unit,
    modifier: Modifier = Modifier,
) {
    val accent = LocalAccent.current
    val s = LocalStrings.current

    val warpPicks = SmartRanking.picks(warpResults, profile)
    val edgePicks = SmartRanking.picks(edgeResults, profile)
    if (warpPicks.best == null && edgePicks.best == null) return

    Column(modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier
                    .width(3.dp)
                    .height(13.dp)
                    .background(accent.primary, RoundedCornerShape(2.dp))
            )
            Spacer(Modifier.width(8.dp))
            Text(
                s.smartPicks,
                style = MaterialTheme.typography.labelSmall,
                color = Fog,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
            profile?.let { GradeChip(it.grade) }
        }
        Spacer(Modifier.height(4.dp))
        Text(
            smartWhyLine(profile) ?: s.smartNoProfile,
            style = MonoStyleSmall.copy(fontSize = 9.5.sp),
            color = if (profile == null) Fade else accent.tint,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
        Spacer(Modifier.height(9.dp))

        if (warpPicks.best != null) {
            PickRow(
                title = "WARP",
                icon = Icons.Rounded.Verified,
                picks = warpPicks,
                profile = profile,
                onPick = onPick,
            )
            Spacer(Modifier.height(8.dp))
        }
        if (edgePicks.best != null) {
            PickRow(
                title = "CF EDGE",
                icon = Icons.Rounded.Public,
                picks = edgePicks,
                profile = profile,
                onPick = onPick,
            )
        }
    }
}

@Composable
private fun PickRow(
    title: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    picks: SmartRanking.Picks,
    profile: NetworkProfile?,
    onPick: (ScanResult) -> Unit,
) {
    val accent = LocalAccent.current
    val s = LocalStrings.current

    Column(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(13.dp))
            .background(Graphite.copy(alpha = 0.75f))
            .border(1.dp, SlateLine, RoundedCornerShape(13.dp))
            .padding(horizontal = 10.dp, vertical = 9.dp),
    ) {
        // headline pick — the adaptive BEST for this family
        picks.best?.let { best ->
            Row(
                Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(9.dp))
                    .background(accent.primary.copy(alpha = 0.09f))
                    .bouncyClickable(pressedScale = 0.985f) { onPick(best) }
                    .padding(horizontal = 9.dp, vertical = 7.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(icon, null, tint = accent.primary, modifier = Modifier.padding(0.dp).width(14.dp).height(14.dp))
                Spacer(Modifier.width(7.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        best.ip,
                        style = MonoStyle.copy(fontSize = 12.sp),
                        color = Mist,
                        maxLines = 1,
                        softWrap = false,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        pickValue(best),
                        style = MonoStyleSmall.copy(fontSize = 9.5.sp),
                        color = Fog,
                        maxLines = 1,
                        softWrap = false,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                Box(
                    Modifier
                        .clip(RoundedCornerShape(7.dp))
                        .background(accent.primary.copy(alpha = 0.16f))
                        .border(1.dp, accent.primary.copy(alpha = 0.55f), RoundedCornerShape(7.dp))
                        .padding(horizontal = 7.dp, vertical = 3.dp),
                ) {
                    Text(
                        "${s.pickBest} · ${"%.0f".format(SmartRanking.score(best, profile))}",
                        style = MaterialTheme.typography.labelSmall,
                        color = accent.tint,
                        maxLines = 1,
                        softWrap = false,
                    )
                }
            }
        }
        Spacer(Modifier.height(7.dp))

        // the three specialist picks — کم‌ترین پینگ · پایدارترین · پرسرعت‌ترین
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            PickCell(
                label = s.pickPing,
                icon = Icons.Rounded.Speed,
                tint = accent.secondary,
                result = picks.ping,
                value = picks.ping?.latencyMs?.let { "${"%.0f".format(it)}ms" },
                onPick = onPick,
                modifier = Modifier.weight(1f),
            )
            PickCell(
                label = s.pickStable,
                icon = Icons.Rounded.Verified,
                tint = OkMint,
                result = picks.stable,
                value = picks.stable?.let {
                    "jit ${it.jitterMs?.let { j -> "${"%.0f".format(j)}ms" } ?: "—"} · ${it.lossPct}%"
                },
                onPick = onPick,
                modifier = Modifier.weight(1f),
            )
            PickCell(
                label = s.pickFast,
                icon = Icons.Rounded.Bolt,
                tint = accent.primary,
                result = picks.fast,
                value = picks.fast?.speedMbps?.let { "${"%.1f".format(it)}M" },
                onPick = onPick,
                modifier = Modifier.weight(1f),
            )
        }
    }
}

@Composable
private fun PickCell(
    label: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    tint: Color,
    result: ScanResult?,
    value: String?,
    onPick: (ScanResult) -> Unit,
    modifier: Modifier = Modifier,
) {
    val enabled = result != null
    Column(
        modifier
            .clip(RoundedCornerShape(9.dp))
            .background(if (enabled) Graphite else Graphite.copy(alpha = 0.4f))
            .border(1.dp, if (enabled) tint.copy(alpha = 0.35f) else SlateLine, RoundedCornerShape(9.dp))
            .then(if (enabled) Modifier.bouncyClickable(pressedScale = 0.96f) { onPick(result!!) } else Modifier)
            .padding(horizontal = 7.dp, vertical = 6.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, null, tint = if (enabled) tint else Fade, modifier = Modifier.width(11.dp).height(11.dp))
            Spacer(Modifier.width(4.dp))
            Text(
                label,
                style = MaterialTheme.typography.labelSmall.copy(fontSize = 8.5.sp),
                color = if (enabled) tint else Fade,
                maxLines = 1,
                softWrap = false,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Spacer(Modifier.height(3.dp))
        Text(
            result?.ip ?: "—",
            style = MonoStyleSmall.copy(fontSize = 9.sp, color = if (enabled) Mist else Fade),
            maxLines = 1,
            softWrap = false,
            overflow = TextOverflow.Ellipsis,
        )
        Spacer(Modifier.height(1.dp))
        Text(
            value ?: "—",
            style = MonoStyleSmall.copy(fontSize = 8.5.sp, color = Fog),
            maxLines = 1,
            softWrap = false,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
private fun smartWhyLine(profile: NetworkProfile?): String? {
    val s = LocalStrings.current
    return when (profile?.grade) {
        null -> null
        NetGrade.EXCELLENT -> s.smartWhyExcellent
        NetGrade.GOOD -> s.smartWhyGood
        NetGrade.FAIR -> s.smartWhyFair
        NetGrade.POOR -> s.smartWhyPoor
    }
}

/** One compact value line for the headline pick: ping · speed · proof. */
@Composable
private fun pickValue(r: ScanResult): String {
    val sb = StringBuilder()
    r.latencyMs?.let { sb.append("${"%.0f".format(it)}ms") }
    r.speedMbps?.let {
        if (sb.isNotEmpty()) sb.append(" · ")
        sb.append("${"%.1f".format(it)} Mbps")
    }
    if (sb.isEmpty()) sb.append("—")
    return sb.toString()
}
