package com.umbra.scanner.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.umbra.scanner.UmbraApp
import com.umbra.scanner.core.IpProtocol
import com.umbra.scanner.core.IpText
import com.umbra.scanner.core.Ranking
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanResult
import com.umbra.scanner.core.ScanUi
import com.umbra.scanner.core.SortKey
import com.umbra.scanner.export.Exporters
import com.umbra.scanner.i18n.LocalStrings
import com.umbra.scanner.ui.components.ActionRow
import com.umbra.scanner.ui.components.NeonCard
import com.umbra.scanner.ui.components.OrbitGlobe
import com.umbra.scanner.ui.components.OutlineButton
import com.umbra.scanner.ui.components.PulsingDot
import com.umbra.scanner.ui.components.SectionLabel
import com.umbra.scanner.ui.components.SelectChip
import com.umbra.scanner.ui.components.StatCell
import com.umbra.scanner.ui.components.bouncyClickable
import com.umbra.scanner.ui.components.staggerIn
import com.umbra.scanner.ui.theme.BronzeMedal
import com.umbra.scanner.ui.theme.Fade
import com.umbra.scanner.ui.theme.Fog
import com.umbra.scanner.ui.theme.GoldMedal
import com.umbra.scanner.ui.theme.Graphite
import com.umbra.scanner.ui.theme.LocalAccent
import com.umbra.scanner.ui.theme.Mist
import com.umbra.scanner.ui.theme.MonoStyle
import com.umbra.scanner.ui.theme.MonoStyleLarge
import com.umbra.scanner.ui.theme.MonoStyleSmall
import com.umbra.scanner.ui.theme.OkMint
import com.umbra.scanner.ui.theme.SilverMedal
import com.umbra.scanner.ui.theme.SlateLine
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun ResultsScreen(
    app: UmbraApp,
    onGoScan: () -> Unit,
    onGoVless: () -> Unit,
) {
    val context = LocalContext.current
    val controller = app.controller
    val ui by controller.ui.collectAsState()
    val results by controller.results.collectAsState()
    val clipboard = LocalClipboardManager.current
    val scope = rememberCoroutineScope()
    val accent = LocalAccent.current
    val s = LocalStrings.current

    var sortIdx by rememberSaveable { mutableIntStateOf(0) }
    var filterIdx by rememberSaveable { mutableIntStateOf(0) }
    var query by rememberSaveable { mutableStateOf("") }
    var visible by rememberSaveable { mutableIntStateOf(150) }
    var detail by remember { mutableStateOf<ScanResult?>(null) }

    val params = (ui as? ScanUi.Done)?.summary?.params

    val filtered = remember(results, sortIdx, filterIdx, query) {
        val base = results.asSequence().filter { it.alive }
        val family = when (filterIdx) {
            1 -> base.filter { it.protocol == IpProtocol.IPv4 }
            2 -> base.filter { it.protocol == IpProtocol.IPv6 }
            3 -> base.filter { it.tlsSuccess }
            else -> base
        }
        val q = query.trim()
        val searched = if (q.isEmpty()) family else family.filter { it.ip.contains(q, ignoreCase = true) }
        Ranking.sort(searched.toList(), SortKey.entries.getOrElse(sortIdx) { SortKey.SCORE })
    }
    fun stampName(ext: String): String =
        "umbra_scan_" + SimpleDateFormat("yyyyMMdd_HHmm", Locale.US).format(Date()) + "." + ext

    fun export(uri: Uri?, build: () -> String, label: String) {
        uri ?: return
        val content = build()
        scope.launch {
            val ok = Exporters.writeToUri(context, uri, content)
            Toast.makeText(context, if (ok) "$label exported" else "export failed", Toast.LENGTH_SHORT).show()
        }
    }

    val csvLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/csv")) {
        export(it, { Exporters.csv(filtered) }, "CSV")
    }
    val txtLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) {
        export(it, { Exporters.txt(filtered, params) }, "TXT")
    }
    val jsonLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) {
        export(it, { Exporters.json(filtered, params) }, "JSON")
    }

    fun copy(text: String, label: String) {
        clipboard.setText(AnnotatedString(text))
        Toast.makeText(context, "$label copied", Toast.LENGTH_SHORT).show()
    }

    Column(
        Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(horizontal = 16.dp)
    ) {
        Spacer(Modifier.height(10.dp))
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.staggerIn(0)) {
            Text(
                s.scanResults,
                style = MaterialTheme.typography.displayMedium,
                color = Mist,
                modifier = Modifier.weight(1f),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (results.isNotEmpty()) {
                PulsingDot(color = accent.primary, sizeDp = 7.dp)
                Spacer(Modifier.width(6.dp))
                Text("${results.size}", style = MonoStyleSmall, color = accent.tint)
            }
        }

        if (results.isEmpty()) {
            Spacer(Modifier.height(40.dp))
            EmptyResults(onGoScan)
            return@Column
        }

        Spacer(Modifier.height(12.dp))

        // summary
        val best = filtered.firstOrNull()
        val medLat = remember(results) {
            results.mapNotNull { it.latencyMs }.sorted().let { if (it.isEmpty()) null else it[it.size / 2] }
        }
        Row(
            Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(14.dp))
                .background(Graphite)
                .padding(horizontal = 14.dp, vertical = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            StatCell(s.alive, results.size.toString(), Modifier.weight(1f))
            StatCell(
                s.bestLat,
                best?.latencyMs?.let { "%.0fms".format(it) } ?: "—",
                Modifier.weight(1f),
            )
            StatCell(s.median, medLat?.let { "%.0fms".format(it) } ?: "—", Modifier.weight(1f))
            StatCell(
                s.topSpeed,
                filtered.maxOfOrNull { it.speedMbps ?: 0.0 }?.let { if (it > 0) "%.1fM".format(it) else "—" } ?: "—",
                Modifier.weight(1f),
            )
        }

        Spacer(Modifier.height(12.dp))

        // sort + filter
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(7.dp),
            verticalArrangement = Arrangement.spacedBy(7.dp),
        ) {
            SortKey.entries.forEachIndexed { i, k ->
                SelectChip(text = k.label, selected = sortIdx == i, onClick = { sortIdx = i })
            }
        }
        Spacer(Modifier.height(8.dp))
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(7.dp),
            verticalArrangement = Arrangement.spacedBy(7.dp),
        ) {
            listOf(s.all, "IPv4", "IPv6", s.tlsOk).forEachIndexed { i, f ->
                // v3.0.1: switching family/tls filters also resets the reveal window
                SelectChip(text = f, selected = filterIdx == i, onClick = { filterIdx = i; visible = 150 })
            }
        }

        Spacer(Modifier.height(10.dp))

        OutlinedTextField(
            value = query,
            onValueChange = { query = it; visible = 150 },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            placeholder = { Text(s.searchIp, style = MonoStyleSmall, color = Fade) },
            textStyle = MonoStyleSmall.copy(color = Mist),
            leadingIcon = { Icon(Icons.Rounded.Search, null, tint = Fog, modifier = Modifier.size(16.dp)) },
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = accent.primary.copy(alpha = 0.8f),
                unfocusedBorderColor = SlateLine,
                cursorColor = accent.primary,
            ),
        )

        Spacer(Modifier.height(12.dp))

        // export row
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlineButton("CSV", { csvLauncher.launch(stampName("csv")) }, Modifier.weight(1f), height = 38.dp)
            OutlineButton("TXT", { txtLauncher.launch(stampName("txt")) }, Modifier.weight(1f), height = 38.dp)
            OutlineButton("JSON", { jsonLauncher.launch(stampName("json")) }, Modifier.weight(1f), height = 38.dp)
            OutlineButton(s.share, {
                Exporters.shareText(context, Exporters.txt(filtered.take(60), params))
            }, Modifier.weight(1f), height = 38.dp)
        }

        Spacer(Modifier.height(12.dp))

        LazyColumn(
            Modifier
                .fillMaxWidth()
                .weight(1f),
            verticalArrangement = Arrangement.spacedBy(7.dp),
        ) {
            itemsIndexed(
                items = filtered.take(visible),
                key = { _, r -> r.id },
                contentType = { _, _ -> "result" },
            ) { idx, r ->
                Box(
                    Modifier.animateItem(
                        placementSpec = spring(stiffness = 380f, dampingRatio = Spring.DampingRatioLowBouncy)
                    )
                ) {
                    ResultRow(rank = idx + 1, r = r, onClick = { detail = r })
                }
            }
            if (filtered.size > visible) {
                item(key = "loadmore") {
                    OutlineButton(
                        text = s.revealMore(filtered.size - visible),
                        onClick = { visible += 150 },
                        modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                        height = 40.dp,
                    )
                }
            }
            item(key = "tail") { Spacer(Modifier.height(16.dp)) }
        }
    }

    detail?.let { r ->
        ModalBottomSheet(
            onDismissRequest = { detail = null },
            containerColor = Graphite,
        ) {
            DetailSheet(
                r = r,
                onCopy = ::copy,
                onVless = {
                    controller.pendingVlessIp = r.ip
                    detail = null
                    onGoVless()
                },
                onShare = {
                    val line = "${r.ip}:${r.port} · lat ${r.latencyMs?.let { "%.0fms".format(it) }} · loss ${r.lossPct}%" +
                        (r.speedMbps?.let { " · ${"%.1f".format(it)} Mbps" } ?: "")
                    val intent = Intent(Intent.ACTION_SEND).apply {
                        type = "text/plain"
                        putExtra(Intent.EXTRA_TEXT, line)
                    }
                    context.startActivity(Intent.createChooser(intent, "Share endpoint"))
                },
            )
        }
    }
}

@Composable
private fun ResultRow(rank: Int, r: ScanResult, onClick: () -> Unit) {
    val accent = LocalAccent.current
    val top3 = rank <= 3
    // v3 medal tints — gold / silver / bronze for the podium
    val medal: androidx.compose.ui.graphics.Color = when (rank) {
        1 -> GoldMedal
        2 -> SilverMedal
        3 -> BronzeMedal
        else -> accent.primary
    }
    Row(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(13.dp))
            .background(MaterialTheme.colorScheme.surface)
            .bouncyClickable(pressedScale = 0.985f) { onClick() }
            .padding(horizontal = 10.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // rank medal — uniform 30dp square with podium tint
        Box(
            Modifier
                .size(30.dp)
                .clip(RoundedCornerShape(9.dp))
                .background(if (top3) medal.copy(alpha = 0.15f) else Graphite)
                .then(if (top3) Modifier.border(1.dp, medal.copy(alpha = 0.65f), RoundedCornerShape(9.dp)) else Modifier),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                "$rank",
                style = MonoStyleSmall.copy(fontSize = 10.sp),
                color = if (top3) medal else Fade,
                maxLines = 1,
                softWrap = false,
            )
        }
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Text(
                r.ip,
                style = MonoStyle.copy(fontSize = 12.sp),
                color = Mist,
                maxLines = 1,
                softWrap = false,
                overflow = TextOverflow.Ellipsis,
            )
            Spacer(Modifier.height(3.dp))
            // meta line: protocol · port · tls · warp — one ellipsized line
            Text(
                metaLine(r, accent.secondary),
                style = MaterialTheme.typography.labelSmall.copy(
                    fontSize = 8.5.sp,
                    letterSpacing = if (r.protocol.label.all { it.code < 0x590 }) 1.sp else 0.sp,
                ),
                color = Fog,
                maxLines = 1,
                softWrap = false,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Spacer(Modifier.width(8.dp))
        Column(horizontalAlignment = Alignment.End, modifier = Modifier.width(54.dp)) {
            Text(
                r.latencyMs?.let { "%.0fms".format(it) } ?: "—",
                style = MonoStyleSmall,
                color = accent.tint,
                maxLines = 1,
                softWrap = false,
                overflow = TextOverflow.Ellipsis,
            )
            Spacer(Modifier.height(2.dp))
            Text(
                "${r.lossPct}%",
                style = MonoStyleSmall.copy(fontSize = 8.5.sp),
                color = Fog,
                maxLines = 1,
                softWrap = false,
            )
        }
        Spacer(Modifier.width(6.dp))
        Column(horizontalAlignment = Alignment.End, modifier = Modifier.width(46.dp)) {
            Text(
                r.speedMbps?.let { "%.1fM".format(it) } ?: "· · ·",
                style = MonoStyleSmall,
                color = OkMint,
                maxLines = 1,
                softWrap = false,
                overflow = TextOverflow.Ellipsis,
            )
            Spacer(Modifier.height(4.dp))
            ScoreBar(score = (Ranking.scoreOf(r) / 110.0).toFloat())
        }
    }
}

private fun metaLine(r: ScanResult, warpColor: Color): AnnotatedString = buildAnnotatedString {
    withStyle(SpanStyle(color = Fog)) {
        append(r.protocol.label)
        append("  ·  :")
        append(r.port.toString())
    }
    if (r.mode == ScanMode.WARP) {
        // WARP rows carry the REAL proof: WG handshake + in-tunnel ping
        append("  ·  ")
        withStyle(SpanStyle(color = if (r.wgHandshakes > 0) OkMint else Fog)) { append("WG") }
        if (r.wgHandshakes > 0 && r.successfulAttempts > 0) {
            append("  ·  ")
            withStyle(SpanStyle(color = OkMint)) { append("PING") }
        }
    } else if (r.tlsSuccess) {
        append("  ·  ")
        withStyle(SpanStyle(color = OkMint)) { append("TLS") }
    }
    if (r.mode == ScanMode.WARP) {
        append("  ·  ")
        withStyle(SpanStyle(color = warpColor)) { append("WARP") }
    }
}

@Composable
private fun ScoreBar(score: Float) {
    val accent = LocalAccent.current
    Box(
        Modifier
            .width(38.dp)
            .height(3.dp)
            .clip(RoundedCornerShape(2.dp))
            .background(SlateLine),
    ) {
        Box(
            Modifier
                .fillMaxWidth(score.coerceIn(0.04f, 1f))
                .height(3.dp)
                .background(accent.primary),
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DetailSheet(
    r: ScanResult,
    onCopy: (String, String) -> Unit,
    onVless: () -> Unit,
    onShare: () -> Unit,
) {
    val accent = LocalAccent.current
    val s = LocalStrings.current
    Column(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp)
            .verticalScroll(rememberScrollState())
    ) {
        Text(
            r.ip,
            style = MonoStyleLarge,
            color = accent.tint,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        Spacer(Modifier.height(4.dp))
        SectionLabel(if (r.mode == ScanMode.WARP) s.warpProfile else s.edgeProfile)
        Spacer(Modifier.height(12.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatCell(s.latency, r.latencyMs?.let { "%.1f ms".format(it) } ?: "—", Modifier.weight(1f))
            StatCell(s.jitter, r.jitterMs?.let { "%.1f ms".format(it) } ?: "—", Modifier.weight(1f))
            StatCell(s.loss, "${r.lossPct}%", Modifier.weight(1f))
        }
        Spacer(Modifier.height(10.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatCell(s.speed, r.speedMbps?.let { "%.2f Mbps".format(it) } ?: "—", Modifier.weight(1f))
            if (r.mode == ScanMode.WARP) {
                StatCell(s.wgHs, "${r.wgHandshakes}×", Modifier.weight(1f))
                StatCell(s.inTunnelPing, "${r.successfulAttempts}/${r.tcpAttempts}", Modifier.weight(1f))
            } else {
                StatCell("TLS", if (r.tlsSuccess) "OK" else "—", Modifier.weight(1f))
                StatCell(s.score, "%.0f".format(Ranking.scoreOf(r)), Modifier.weight(1f))
            }
        }
        Spacer(Modifier.height(10.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatCell(s.attempts, "${r.successfulAttempts}/${r.tcpAttempts}", Modifier.weight(1f))
            StatCell(s.http, r.httpStatus?.toString() ?: "—", Modifier.weight(1f))
            StatCell(s.data, "%,.1f MB".format(r.downloadedBytes / 1048576.0), Modifier.weight(1f))
        }
        if (r.mode == ScanMode.WARP) {
            Spacer(Modifier.height(10.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                StatCell(s.score, "%.0f".format(Ranking.scoreOf(r)), Modifier.weight(1f))
                StatCell(s.port, r.port.toString(), Modifier.weight(1f))
                StatCell(s.family, r.protocol.label, Modifier.weight(1f))
            }
            Spacer(Modifier.height(4.dp))
            Text(
                s.warpValidatedNote,
                style = MaterialTheme.typography.bodySmall,
                color = Fade,
            )
        } else {
            r.tlsHandshakeMs?.let {
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    StatCell(s.tlsTime, "%.0f ms".format(it), Modifier.weight(1f))
                    StatCell(s.port, r.port.toString(), Modifier.weight(1f))
                    StatCell(s.family, r.protocol.label, Modifier.weight(1f))
                }
            }
        }
        r.error?.let { err ->
            Spacer(Modifier.height(10.dp))
            Text(
                s.lastError(err),
                style = MaterialTheme.typography.bodySmall,
                color = Fog,
            )
        }
        Spacer(Modifier.height(16.dp))
        ActionRow(Icons.Rounded.ContentCopy, s.copyIp) { onCopy(r.ip, "IP") }
        Spacer(Modifier.height(7.dp))
        ActionRow(Icons.Rounded.ContentCopy, s.copyIpPort) { onCopy("${r.ip}:${r.port}", "Endpoint") }
        Spacer(Modifier.height(7.dp))
        if (r.mode == ScanMode.WARP) {
            ActionRow(Icons.Rounded.ContentCopy, s.copyWgEndpoint) {
                onCopy("Endpoint = ${IpText.forUrl(r.ip)}:${r.port}", "Endpoint line")
            }
            Spacer(Modifier.height(7.dp))
        } else {
            // VLESS only makes sense for TLS-able edge ports (:443 etc)
            ActionRow(Icons.Rounded.Key, s.createVless, tint = accent.tint) { onVless() }
            Spacer(Modifier.height(7.dp))
        }
        ActionRow(Icons.Rounded.Share, s.shareEndpoint) { onShare() }
        Spacer(Modifier.height(26.dp))
    }
}

@Composable
private fun EmptyResults(onGoScan: () -> Unit) {
    val accent = LocalAccent.current
    val s = LocalStrings.current
    NeonCard {
        Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
            OrbitGlobe(sizeDp = 96.dp)
        }
        Spacer(Modifier.height(14.dp))
        Text(
            s.noScanDataYet,
            style = MaterialTheme.typography.displayMedium,
            color = Fog,
            modifier = Modifier.align(Alignment.CenterHorizontally),
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        Spacer(Modifier.height(8.dp))
        Text(
            s.emptyResultsHint,
            style = MaterialTheme.typography.bodySmall,
            color = Fade,
            modifier = Modifier.align(Alignment.CenterHorizontally),
        )
        Spacer(Modifier.height(18.dp))
        OutlineButton(s.runAScan, onGoScan, Modifier.fillMaxWidth())
    }
}
