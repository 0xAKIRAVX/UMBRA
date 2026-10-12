package com.umbra.scanner.ui.screens

import android.widget.Toast
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.umbra.scanner.UmbraApp
import com.umbra.scanner.debug.DebugLog
import com.umbra.scanner.debug.DeepEndpointTest
import com.umbra.scanner.debug.DeepEndpointTest.DeepTestReport
import com.umbra.scanner.debug.DiagCenter
import com.umbra.scanner.debug.DiagCenter.DiagState
import com.umbra.scanner.debug.DbgEntry
import com.umbra.scanner.debug.DbgLevel
import com.umbra.scanner.export.Exporters
import com.umbra.scanner.i18n.LocalStrings
import com.umbra.scanner.ui.components.GradientButton
import com.umbra.scanner.ui.components.NeonCard
import com.umbra.scanner.ui.components.OutlineButton
import com.umbra.scanner.ui.components.PulsingDot
import com.umbra.scanner.ui.components.SectionLabel
import com.umbra.scanner.ui.components.SelectChip
import com.umbra.scanner.ui.components.staggerIn
import com.umbra.scanner.ui.theme.Fade
import com.umbra.scanner.ui.theme.Fog
import com.umbra.scanner.ui.theme.LocalAccent
import com.umbra.scanner.ui.theme.Mist
import com.umbra.scanner.ui.theme.MonoStyleSmall
import com.umbra.scanner.ui.theme.OkMint
import com.umbra.scanner.ui.theme.SlateLine
import com.umbra.scanner.ui.theme.WarnAmber
import androidx.compose.ui.graphics.Color
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * v3.12 — the DIAGNOSTICS tab: the user-facing half of the debug system.
 *
 * Three instruments, top to bottom:
 *  1. FULL DIAGNOSTICS — one button runs the environment interrogation
 *     ([DiagCenter]): connectivity / DNS / tcp egress / udp egress / warp
 *     identity / live wg witness / runtime. The verdict banner names the
 *     failure class in plain words, the check board carries the evidence.
 *  2. DEEP ENDPOINT TEST — the microscope: type any ip:port, watch the
 *     exact WireGuard handshake attempt with raw packet hex and per-stage
 *     timings ([DeepEndpointTest]).
 *  3. LIVE DEBUG CONSOLE — the [DebugLog] journal every layer mirrors
 *     into (scan lines, crashes, netsense steps, update checks), filterable
 *     by tag, copyable/sharable as a plain-text report.
 */
@Composable
fun DiagnosticsScreen(app: UmbraApp) {
    val context = LocalContext.current
    val s = LocalStrings.current
    val accent = LocalAccent.current
    val clipboard = LocalClipboardManager.current
    val scope = rememberCoroutineScope()

    val diagState by DiagCenter.state.collectAsState()
    val entries by DebugLog.flow.collectAsState()

    var deepInput by rememberSaveable { mutableStateOf("162.159.192.1:2408") }
    var deepBusy by remember { mutableStateOf(false) }
    var deepReport by remember { mutableStateOf<DeepTestReport?>(null) }
    var tagFilter by rememberSaveable { mutableStateOf<String?>(null) }

    val running = diagState is DiagCenter.DiagUi.Running

    Column(
        Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp)
    ) {
        Spacer(Modifier.height(10.dp))
        // header
        Text(
            s.diagTitle,
            style = MaterialTheme.typography.displayMedium,
            color = Mist,
            modifier = Modifier.staggerIn(0),
            maxLines = 1,
            softWrap = false,
            overflow = TextOverflow.Ellipsis,
        )
        Spacer(Modifier.height(4.dp))
        Text(
            s.diagTagline,
            style = MaterialTheme.typography.bodySmall,
            color = Fade,
            modifier = Modifier.staggerIn(1),
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        Spacer(Modifier.height(16.dp))

        // ── 1. full diagnostics ──────────────────────────────────────
        NeonCard(modifier = Modifier.staggerIn(2)) {
            AnimatedContent(
                targetState = diagState,
                transitionSpec = {
                    (fadeIn(tween(220))) togetherWith (fadeOut(tween(140)))
                },
                label = "diagState",
            ) { st ->
                when (st) {
                    is DiagCenter.DiagUi.Running -> Row(
                        Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        PulsingDot(color = accent.primary, sizeDp = 7.dp)
                        Spacer(Modifier.width(10.dp))
                        Text(
                            s.diagRunning(st.step),
                            style = MaterialTheme.typography.titleSmall,
                            color = Mist,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }

                    is DiagCenter.DiagUi.Done -> VerdictBanner(
                        level = st.report.level,
                        verdict = st.report.verdict,
                        answered = st.report.witnessAnswered,
                        total = st.report.witnessTotal,
                    )

                    DiagCenter.DiagUi.Idle -> Text(
                        s.diagNoReport,
                        style = MaterialTheme.typography.bodySmall,
                        color = Fade,
                    )
                }
            }
            Spacer(Modifier.height(12.dp))
            GradientButton(
                text = if (diagState is DiagCenter.DiagUi.Done) s.diagRerun else s.diagRunFull,
                onClick = {
                    scope.launch {
                        val report = withContext(Dispatchers.IO) { DiagCenter.run() }
                        if (report == null) {
                            Toast.makeText(context, s.diagRefusedScan, Toast.LENGTH_SHORT).show()
                        }
                    }
                },
                enabled = !running,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        Spacer(Modifier.height(14.dp))

        // ── check board (last report) ────────────────────────────────
        (diagState as? DiagCenter.DiagUi.Done)?.let { done ->
            NeonCard(modifier = Modifier.staggerIn(3), glow = false) {
                SectionLabel(s.diagChecks)
                Spacer(Modifier.height(10.dp))
                done.report.checks.forEach { check ->
                    CheckRow(check = check)
                    Spacer(Modifier.height(7.dp))
                }
            }
            Spacer(Modifier.height(14.dp))
        }

        // ── 2. deep endpoint test ────────────────────────────────────
        NeonCard(modifier = Modifier.staggerIn(4)) {
            SectionLabel(s.diagDeepTest)
            Spacer(Modifier.height(6.dp))
            Text(
                s.diagDeepHint,
                style = MaterialTheme.typography.bodySmall,
                color = Fade,
            )
            Spacer(Modifier.height(10.dp))
            OutlinedTextField(
                value = deepInput,
                onValueChange = { deepInput = it.trim() },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                placeholder = { Text(s.diagDeepPlaceholder, style = MonoStyleSmall, color = Fade) },
                textStyle = MonoStyleSmall.copy(color = Mist),
                keyboardOptions = KeyboardOptions(keyboardType = androidx.compose.ui.text.input.KeyboardType.Ascii),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = accent.primary.copy(alpha = 0.8f),
                    unfocusedBorderColor = SlateLine,
                    cursorColor = accent.primary,
                ),
            )
            Spacer(Modifier.height(10.dp))
            GradientButton(
                text = if (deepBusy) s.diagDeepRunning else s.diagDeepRun,
                onClick = {
                    if (deepBusy || deepInput.isBlank()) return@GradientButton
                    deepBusy = true
                    deepReport = null
                    scope.launch {
                        val report = withContext(Dispatchers.IO) {
                            runCatching {
                                DeepEndpointTest.run(deepInput, timeoutMs = 3000, attempts = 2)
                            }.getOrNull()
                        }
                        deepReport = report
                        deepBusy = false
                        // the console carries the outcome too — a shared log
                        // from this tab tells the whole story on its own
                        report?.let {
                            DebugLog.log(levelOf(it), DebugLog.TAG_DIAG,
                                "deep test · ${it.ip}:${it.port} · ${it.outcome.name} · ${it.outcomeDetail}")
                        }
                    }
                },
                enabled = !deepBusy,
                modifier = Modifier.fillMaxWidth(),
            )
            deepReport?.let { r ->
                Spacer(Modifier.height(14.dp))
                OutcomeCard(report = r)
            }
        }
        Spacer(Modifier.height(14.dp))

        // ── 3. live debug console ────────────────────────────────────
        NeonCard(modifier = Modifier.staggerIn(5), glow = false) {
            SectionLabel(s.diagConsole)
            Spacer(Modifier.height(8.dp))
            // tag filter chips
            Row(horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                ConsoleChip(null, tagFilter == null, s.all) { tagFilter = null }
                ConsoleChip(DebugLog.TAG_SCAN, tagFilter == DebugLog.TAG_SCAN, "scan") { tagFilter = DebugLog.TAG_SCAN }
                ConsoleChip(DebugLog.TAG_NET, tagFilter == DebugLog.TAG_NET, "net") { tagFilter = DebugLog.TAG_NET }
                ConsoleChip(DebugLog.TAG_DIAG, tagFilter == DebugLog.TAG_DIAG, "diag") { tagFilter = DebugLog.TAG_DIAG }
                ConsoleChip(DebugLog.TAG_CRASH, tagFilter == DebugLog.TAG_CRASH, "crash") { tagFilter = DebugLog.TAG_CRASH }
            }
            Spacer(Modifier.height(10.dp))
            val shown = if (tagFilter == null) entries else entries.filter { it.tag == tagFilter }
            if (shown.isEmpty()) {
                Text(
                    s.diagConsoleEmpty,
                    style = MaterialTheme.typography.bodySmall,
                    color = Fade,
                )
            } else {
                // newest-first; the 20 most recent keep the card bounded
                shown.take(20).forEach { e ->
                    ConsoleLine(e)
                    Spacer(Modifier.height(5.dp))
                }
            }
            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlineButton(
                    text = s.diagCopy,
                    onClick = {
                        clipboard.setText(androidx.compose.ui.text.AnnotatedString(DebugLog.dump()))
                        Toast.makeText(context, s.diagCopied, Toast.LENGTH_SHORT).show()
                    },
                    modifier = Modifier.weight(1f),
                )
                OutlineButton(
                    text = s.diagShare,
                    onClick = { Exporters.shareText(context, DebugLog.dump(), "UMBRA debug journal") },
                    modifier = Modifier.weight(1f),
                )
                OutlineButton(
                    text = s.diagClear,
                    onClick = { DebugLog.clear() },
                    modifier = Modifier.weight(0.7f),
                )
            }
        }
        Spacer(Modifier.height(24.dp))
    }
}

// ── sub-composables ───────────────────────────────────────────────────

@Composable
private fun VerdictBanner(level: DbgLevel, verdict: String, answered: Int, total: Int) {
    val color = when (level) {
        DbgLevel.INFO -> OkMint
        DbgLevel.WARN -> WarnAmber
        else -> Color(0xFFFF5D6E)
    }
    Column(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(color.copy(alpha = 0.10f))
            .padding(12.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            PulsingDot(color = color, sizeDp = 7.dp)
            Spacer(Modifier.width(8.dp))
            Text(
                s_label(level),
                style = MaterialTheme.typography.labelLarge,
                color = color,
            )
            Spacer(Modifier.width(8.dp))
            if (total > 0) {
                Text(
                    "· $answered/$total",
                    style = MaterialTheme.typography.labelMedium,
                    color = Fog,
                )
            }
        }
        Spacer(Modifier.height(6.dp))
        Text(
            verdict,
            style = MaterialTheme.typography.bodySmall,
            color = Mist,
        )
    }
}

@Composable
private fun s_label(level: DbgLevel): String {
    val s = LocalStrings.current
    return when (level) {
        DbgLevel.INFO -> s.diagOk
        DbgLevel.WARN -> s.diagWarn
        else -> s.diagFail
    }
}

@Composable
private fun CheckRow(check: DiagCenter.DiagCheck) {
    val s = LocalStrings.current
    val color = when (check.state) {
        DiagState.OK -> OkMint
        DiagState.WARN -> WarnAmber
        DiagState.FAIL -> Color(0xFFFF5D6E)
        DiagState.UNKNOWN -> Fog
    }
    val chip = when (check.state) {
        DiagState.OK -> s.diagOk
        DiagState.WARN -> s.diagWarn
        DiagState.FAIL -> s.diagFail
        DiagState.UNKNOWN -> s.diagUnknown
    }
    Row(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(color.copy(alpha = 0.06f))
            .padding(horizontal = 10.dp, vertical = 8.dp)
    ) {
        Box(
            Modifier
                .align(Alignment.Top)
                .padding(top = 3.dp)
                .size(7.dp)
                .clip(CircleShape)
                .background(color)
        )
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    check.label,
                    style = MaterialTheme.typography.labelMedium,
                    color = Mist,
                    maxLines = 1,
                    softWrap = false,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f, fill = false),
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    chip,
                    style = MaterialTheme.typography.labelSmall,
                    color = color,
                    maxLines = 1,
                    softWrap = false,
                )
            }
            if (check.detail.isNotBlank()) {
                Spacer(Modifier.height(3.dp))
                Text(
                    check.detail,
                    style = MaterialTheme.typography.bodySmall,
                    color = Fog,
                )
            }
        }
    }
}

@Composable
private fun OutcomeCard(report: DeepTestReport) {
    val s = LocalStrings.current
    val color = when (report.outcome) {
        DeepEndpointTest.DeepOutcome.HANDSHAKE_OK -> OkMint
        DeepEndpointTest.DeepOutcome.COOKIE_REPLY -> OkMint
        DeepEndpointTest.DeepOutcome.PARSE_ERROR,
        DeepEndpointTest.DeepOutcome.DNS_FAILED,
        DeepEndpointTest.DeepOutcome.IDENTITY_FAILED,
        DeepEndpointTest.DeepOutcome.SOCKET_ERROR -> Color(0xFFFF5D6E)
        else -> WarnAmber
    }
    Column(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(color.copy(alpha = 0.08f))
            .padding(12.dp)
    ) {
        Text(
            "${report.outcome.name}" +
                (report.rttMs?.let { " · ${it} ms" } ?: "") +
                (if (report.aeadVerified) " · aead verified" else ""),
            style = MaterialTheme.typography.labelLarge,
            color = color,
        )
        Spacer(Modifier.height(5.dp))
        Text(
            report.outcomeDetail,
            style = MaterialTheme.typography.bodySmall,
            color = Mist,
        )
        Spacer(Modifier.height(10.dp))
        SectionLabel("${s.diagStages} · ${report.stages.size}")
        Spacer(Modifier.height(6.dp))
        report.stages.forEach { st ->
            Row {
                Text(
                    "${st.name} — ${st.detail}",
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    color = Fog,
                    modifier = Modifier.weight(1f),
                )
                Text(
                    "${st.ms}ms",
                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                    color = Fade,
                )
            }
            Spacer(Modifier.height(4.dp))
        }
        report.sentHex?.let {
            Spacer(Modifier.height(8.dp))
            SectionLabel(s.diagSentPacket)
            Spacer(Modifier.height(6.dp))
            Text(
                it,
                style = MonoStyleSmall.copy(color = Fog),
            )
        }
        report.receivedHex?.let {
            Spacer(Modifier.height(8.dp))
            SectionLabel(s.diagReceived)
            Spacer(Modifier.height(6.dp))
            Text(
                it,
                style = MonoStyleSmall.copy(color = Fog),
            )
        }
    }
}

@Composable
private fun ConsoleChip(tag: String?, selected: Boolean, label: String, onClick: () -> Unit) {
    SelectChip(text = label, selected = selected, onClick = onClick)
}

@Composable
private fun ConsoleLine(e: DbgEntry) {
    val color = when (e.level) {
        DbgLevel.ERROR -> Color(0xFFFF5D6E)
        DbgLevel.WARN -> WarnAmber
        DbgLevel.INFO -> Fog
        DbgLevel.TRACE -> Fade
    }
    Row {
        Text(
            e.tag,
            style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
            color = color.copy(alpha = 0.8f),
            modifier = Modifier.width(46.dp),
            maxLines = 1,
        )
        Text(
            e.message,
            style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            color = if (e.level == DbgLevel.INFO) Mist else color,
        )
    }
}

private fun levelOf(r: DeepTestReport): DbgLevel = when (r.outcome) {
    DeepEndpointTest.DeepOutcome.HANDSHAKE_OK,
    DeepEndpointTest.DeepOutcome.COOKIE_REPLY -> DbgLevel.INFO
    DeepEndpointTest.DeepOutcome.REPLY_UNPARSEABLE,
    DeepEndpointTest.DeepOutcome.SILENT -> DbgLevel.WARN
    else -> DbgLevel.ERROR
}
