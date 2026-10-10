package com.umbra.scanner.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Bolt
import androidx.compose.material.icons.rounded.ExpandMore
import androidx.compose.material.icons.rounded.Public
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
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
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.umbra.scanner.UmbraApp
import com.umbra.scanner.core.IpGenerator
import com.umbra.scanner.core.NetFamily
import com.umbra.scanner.core.Presets
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.engine.AutoTune
import com.umbra.scanner.i18n.LocalStrings
import com.umbra.scanner.ui.components.GradientButton
import com.umbra.scanner.ui.components.LabeledSlider
import com.umbra.scanner.ui.components.NeonCard
import com.umbra.scanner.ui.components.OutlineButton
import com.umbra.scanner.ui.components.SectionLabel
import com.umbra.scanner.ui.components.SelectChip
import com.umbra.scanner.ui.components.Segmented
import com.umbra.scanner.ui.components.ToggleRow
import com.umbra.scanner.ui.components.bouncyClickable
import com.umbra.scanner.ui.components.staggerIn
import com.umbra.scanner.ui.theme.Fade
import com.umbra.scanner.ui.theme.Fog
import com.umbra.scanner.ui.theme.Graphite
import com.umbra.scanner.ui.theme.LocalAccent
import com.umbra.scanner.ui.theme.Mist
import com.umbra.scanner.ui.theme.MonoStyle
import com.umbra.scanner.ui.theme.MonoStyleSmall
import com.umbra.scanner.ui.theme.OkMint
import com.umbra.scanner.ui.theme.SlateLine
import kotlinx.coroutines.launch

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ConfigPanel(app: UmbraApp, onStart: (ScanParams) -> Unit) {
    val accent = LocalAccent.current
    val s = LocalStrings.current
    val saved = remember { app.settings.loadParams() }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    // v3.8: UI mode order — ENDPOINT first (the app's headline mode), then the
    // classic pair. The standalone WARP mode is GONE (user request); its
    // validation machinery lives INSIDE endpoint mode now. ScanMode's enum
    // ordinals are persisted via the v3.8 migration; this list only drives
    // the segmented control.
    val uiModes = listOf(ScanMode.ENDPOINT, ScanMode.CF_EDGE, ScanMode.CUSTOM)
    var modeIdx by rememberSaveable {
        mutableIntStateOf(uiModes.indexOf(saved.mode).let { if (it < 0) 0 else it })
    }
    var familyIdx by rememberSaveable { mutableIntStateOf(saved.family.ordinal) }
    var port by rememberSaveable { mutableIntStateOf(saved.port) }
    // v3.7: ENDPOINT-mode knob — how many random ip:port endpoints to test
    var endpoints by rememberSaveable { mutableIntStateOf(saved.endpointsCount) }
    var udpNoise by rememberSaveable { mutableStateOf(saved.udpNoise) }
    var customCidrs by rememberSaveable {
        mutableStateOf(saved.cidrs.filter { it.contains('/') }.joinToString("\n"))
    }
    var samples by rememberSaveable { mutableIntStateOf(saved.samplesPerPrefix) }
    // v3.4 fix: the retries slider now starts from the value the mode actually
    // uses — an ENDPOINT session restored warpAttempts=7 (set by auto-tune) but
    // the slider showed tcpAttempts=3 and every relaunched scan silently ran ×3.
    var attempts by rememberSaveable {
        mutableIntStateOf(
            if (saved.mode == ScanMode.ENDPOINT) saved.warpAttempts else saved.tcpAttempts
        )
    }
    var timeoutMs by rememberSaveable { mutableIntStateOf(saved.tcpTimeoutMs) }
    var concurrency by rememberSaveable { mutableIntStateOf(saved.concurrency) }
    var verifyTopN by rememberSaveable { mutableIntStateOf(saved.verifyTopN) }
    var speedOn by rememberSaveable { mutableStateOf(saved.speedTest) }
    var speedTopN by rememberSaveable { mutableIntStateOf(saved.speedTopN) }
    var speedConc by rememberSaveable { mutableIntStateOf(saved.speedConcurrency) }
    var dlMb by rememberSaveable { mutableIntStateOf(saved.downloadMbLabel) }
    var tlsOn by rememberSaveable { mutableStateOf(saved.tlsVerify) }
    var advanced by rememberSaveable { mutableStateOf(false) }

    // v3.8.1 fix (the toggle-poisoning bug): entering ENDPOINT mode silently
    // forced TLS + speed OFF (endpoint mode has no TLS phase), but switching
    // BACK to EDGE/CUSTOM never restored them — an EDGE scan then ran with
    // tlsVerify=false, and on DPI-filtered networks (this app's whole
    // audience) alive = "tcpAlive && tlsSkipped" reports FAKE endpoints:
    // the exact v3.7 complaint reborn through the mode switcher. Worse,
    // saveParams persisted the poisoned state, so restarts inherited it.
    // The user's pre-ENDPOINT choices are now snapshotted and restored.
    var savedTls by rememberSaveable { mutableStateOf<Boolean?>(null) }
    var savedSpeed by rememberSaveable { mutableStateOf<Boolean?>(null) }

    // transient auto-tune state
    var tuning by remember { mutableStateOf(false) }
    var tuneStep by remember { mutableStateOf<String?>(null) }
    var tuneNotes by remember { mutableStateOf<List<String>>(emptyList()) }

    val mode = uiModes.getOrElse(modeIdx) { ScanMode.ENDPOINT }
    val family = NetFamily.entries.getOrElse(familyIdx) { NetFamily.BOTH }
    val cidrs = if (mode == ScanMode.CUSTOM) {
        customCidrs.lines().map { it.trim() }.filter { it.isNotBlank() }
    } else {
        Presets.cidrsFor(mode, family)
    }

    val estimate = remember(mode, cidrs, family, samples, endpoints) {
        if (mode == ScanMode.ENDPOINT) {
            // v3.8: one endpoint = one WG probe — the count IS the estimate
            // (plus the live-verified seeds the engine prepends)
            endpoints + Presets.WARP_SEED_ENDPOINTS.size
        } else {
            IpGenerator.estimate(cidrs, family, samples)
        }
    }

    NeonCard(modifier = Modifier.staggerIn(1)) {
        Text(s.mode, style = MaterialTheme.typography.labelSmall, color = Fade)
        Spacer(Modifier.height(7.dp))
        Segmented(
            options = listOf(s.modeEndpoint, s.modeCfEdge, s.modeCustom),
            selected = modeIdx,
            onSelect = { i ->
                val m = uiModes[i]
                // v3.8.1: snapshot/restore the TLS + speed toggles around a
                // pass through ENDPOINT mode — see onModeSwitchToggles below.
                val restored = onModeSwitchToggles(m, mode, tlsOn, speedOn, savedTls, savedSpeed)
                tlsOn = restored.tls
                speedOn = restored.speed
                savedTls = restored.savedTls
                savedSpeed = restored.savedSpeed
                modeIdx = i
                port = Presets.defaultPort(m)
                // v3.4 fix: the endpoint probe path clamps wg retries to 1..7 —
                // an EDGE slider value of 8..10 carried into endpoint mode would
                // put the slider out of its own range.
                if (m == ScanMode.ENDPOINT) attempts = attempts.coerceAtMost(7)
                // v3.7: endpoint mode opens as a pure BPB-style latency scan —
                // no TLS phase (random warp ports don't serve speed.cloudflare.com)
                // and no throughput pass unless the user turns it on.
                // (The v3.8.1 restore above re-enables them when the user
                //  leaves endpoint mode for EDGE/CUSTOM.)
            },
        )
        Spacer(Modifier.height(6.dp))
        Text(
            when (mode) {
                ScanMode.CF_EDGE -> s.taglineCfEdge
                ScanMode.CUSTOM -> s.taglineCustom
                ScanMode.ENDPOINT -> s.taglineEndpoint
            },
            style = MaterialTheme.typography.bodySmall,
            color = Fade,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        if (mode == ScanMode.ENDPOINT) {
            Spacer(Modifier.height(6.dp))
            // v3.8: the trust line — endpoints are handshake-validated, never
            // tcp-only (the exact complaint behind this release).
            Text(
                s.endpointValidationHint,
                style = MaterialTheme.typography.bodySmall,
                color = OkMint,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }

        Spacer(Modifier.height(14.dp))
        if (mode == ScanMode.CUSTOM) {
            SectionLabel(s.cidrList)
            Spacer(Modifier.height(7.dp))
            OutlinedTextField(
                value = customCidrs,
                onValueChange = { customCidrs = it },
                modifier = Modifier.fillMaxWidth(),
                placeholder = {
                    Text("104.16.0.0/13\n2606:4700::/32", style = MonoStyleSmall, color = Fade)
                },
                textStyle = MonoStyleSmall.copy(color = Mist),
                minLines = 4,
                maxLines = 10,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = accent.primary.copy(alpha = 0.8f),
                    unfocusedBorderColor = SlateLine,
                    cursorColor = accent.primary,
                ),
            )
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlineButton(
                    text = s.addCfSet,
                    onClick = {
                        customCidrs = (customCidrs.lines() + Presets.CF_EDGE_V4 + Presets.CF_EDGE_V6)
                            .filter { it.isNotBlank() }.distinct().joinToString("\n")
                    },
                    height = 36.dp,
                )
                OutlineButton(
                    text = s.addWarpSet,
                    onClick = {
                        customCidrs = (customCidrs.lines() + Presets.WARP_V4 + Presets.WARP_V6)
                            .filter { it.isNotBlank() }.distinct().joinToString("\n")
                    },
                    height = 36.dp,
                )
            }
            Spacer(Modifier.height(14.dp))
        } else {
            // v3.7: ENDPOINT-mode count presets (BPB quick 100 / normal 1000 / deep)
            if (mode == ScanMode.ENDPOINT) {
                SectionLabel(s.endpointsCountLabel)
                Spacer(Modifier.height(7.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                    listOf(100, 500, 1000, 5000).forEach { n ->
                        SelectChip(
                            text = n.toString(),
                            selected = endpoints == n,
                            onClick = { endpoints = n },
                        )
                    }
                }
                Spacer(Modifier.height(14.dp))
            }
            Text(s.family, style = MaterialTheme.typography.labelSmall, color = Fade)
            Spacer(Modifier.height(7.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                NetFamily.entries.forEachIndexed { i, f ->
                    SelectChip(
                        text = f.label,
                        selected = familyIdx == i,
                        onClick = { familyIdx = i },
                    )
                }
            }
            Spacer(Modifier.height(14.dp))
        }

        // ── AUTO-TUNE ────────────────────────────────────────────────
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                Icons.Rounded.Bolt,
                null,
                tint = if (tuning) accent.primary else accent.tint,
            )
            Spacer(Modifier.padding(start = 8.dp))
            Text(
                s.autoTune,
                style = MaterialTheme.typography.labelMedium,
                color = accent.tint,
                modifier = Modifier.weight(1f),
            )
        }
        Spacer(Modifier.height(4.dp))
        Text(
            s.autoTuneHint,
            style = MaterialTheme.typography.bodySmall,
            color = Fade,
        )
        Spacer(Modifier.height(8.dp))
        OutlineButton(
            text = when {
                tuning -> s.calibrating
                else -> s.pickBestSettings
            },
            onClick = {
                if (tuning) return@OutlineButton
                scope.launch {
                    tuning = true
                    tuneNotes = emptyList()
                    tuneStep = "starting calibration"
                    try {
                        val result = AutoTune.calibrate(context, mode) { step -> tuneStep = step }
                        familyIdx = result.family.ordinal
                        port = result.port
                        samples = result.samplesPerPrefix
                        if (mode == ScanMode.ENDPOINT) endpoints = result.endpointsCount
                        attempts = if (mode == ScanMode.ENDPOINT) result.warpAttempts else result.tcpAttempts
                        timeoutMs = result.tcpTimeoutMs
                        concurrency = result.concurrency
                        tlsOn = result.tlsVerify
                        verifyTopN = result.verifyTopN
                        speedOn = result.speedTest
                        speedTopN = result.speedTopN
                        speedConc = result.speedConcurrency
                        dlMb = result.downloadMb
                        tuneNotes = result.notes
                    } catch (e: Exception) {
                        tuneNotes = listOf("auto-tune failed: ${e.message ?: e.javaClass.simpleName}")
                    } finally {
                        tuning = false
                        tuneStep = null
                    }
                }
            },
            height = 44.dp,
        )
        AnimatedVisibility(visible = tuning && tuneStep != null) {
            Column {
                Spacer(Modifier.height(6.dp))
                Text(
                    "▸ $tuneStep",
                    style = MonoStyleSmall.copy(fontSize = 11.sp),
                    color = accent.tint,
                )
            }
        }
        AnimatedVisibility(visible = tuneNotes.isNotEmpty()) {
            Column {
                Spacer(Modifier.height(10.dp))
                Column(
                    Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(Graphite.copy(alpha = 0.65f), RoundedCornerShape(12.dp))
                        .padding(12.dp),
                ) {
                    SectionLabel(s.autoTuneReport)
                    Spacer(Modifier.height(8.dp))
                    tuneNotes.forEach { note ->
                        Text(
                            "· $note",
                            style = MonoStyleSmall.copy(fontSize = 11.sp, color = Mist),
                            modifier = Modifier.padding(vertical = 1.dp),
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(9.dp))
                            .clickable { tuneNotes = emptyList() }
                            .padding(vertical = 5.dp),
                        horizontalArrangement = Arrangement.End,
                    ) {
                        Text(s.dismiss, style = MaterialTheme.typography.labelSmall, color = Fade)
                    }
                }
            }
        }

        Spacer(Modifier.height(14.dp))
        Text(s.port, style = MaterialTheme.typography.labelSmall, color = Fade)
        Spacer(Modifier.height(7.dp))
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(7.dp),
            verticalArrangement = Arrangement.spacedBy(7.dp),
        ) {
            if (mode == ScanMode.ENDPOINT) {
                // v3.7: RANDOM — port 0 = each endpoint draws its own port from
                // the canonical WARP list (BPB behavior)
                SelectChip(
                    text = s.randomPortLabel,
                    selected = port == 0,
                    onClick = { port = 0 },
                )
            }
            Presets.portsFor(mode).forEach { p ->
                SelectChip(
                    text = p.toString(),
                    selected = port == p,
                    onClick = {
                        port = p
                    },
                )
            }
        }
        if (mode == ScanMode.ENDPOINT) {
            Spacer(Modifier.height(10.dp))
            ToggleRow(
                title = s.udpNoise,
                subtitle = s.udpNoiseHint,
                checked = udpNoise,
                onChange = { udpNoise = it },
            )
            Spacer(Modifier.height(8.dp))
            Text(
                s.endpointPortHint,
                style = MaterialTheme.typography.bodySmall,
                color = Fog,
            )
        }

        Spacer(Modifier.height(16.dp))
        SectionLabel(s.engine)
        Spacer(Modifier.height(4.dp))
        Row(
            Modifier.fillMaxWidth().padding(vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(Icons.Rounded.Public, null, tint = accent.primary.copy(alpha = 0.7f))
            Spacer(Modifier.padding(start = 8.dp))
            Text(
                if (mode == ScanMode.ENDPOINT) s.endpointsEstimate(estimate)
                else s.probesEstimate(estimate, cidrs.size),
                style = MonoStyle.copy(fontSize = 12.sp),
                color = Fog,
                maxLines = 1,
                softWrap = false,
                overflow = TextOverflow.Ellipsis,
            )
        }

        val chevRot by animateFloatAsState(
            targetValue = if (advanced) 180f else 0f,
            animationSpec = spring(
                dampingRatio = Spring.DampingRatioMediumBouncy,
                stiffness = Spring.StiffnessMediumLow,
            ),
            label = "chev",
        )
        Row(
            Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(10.dp))
                .bouncyClickable(pressedScale = 0.98f) { advanced = !advanced }
                .padding(vertical = 8.dp, horizontal = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                Icons.Rounded.ExpandMore,
                null,
                tint = accent.primary,
                modifier = Modifier.graphicsLayer { rotationZ = chevRot },
            )
            Spacer(Modifier.padding(start = 8.dp))
            Text(
                if (advanced) s.hideAdvanced else s.advancedEngine,
                style = MaterialTheme.typography.labelMedium,
                color = accent.tint,
                maxLines = 1,
                softWrap = false,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
        }
        AnimatedVisibility(
            visible = advanced,
            enter = expandVertically(spring(stiffness = 300f)) + fadeIn(),
            exit = shrinkVertically(tween(220)) + fadeOut(tween(160)),
        ) {
            Column {
                Spacer(Modifier.height(8.dp))
                if (mode == ScanMode.ENDPOINT) {
                    // v3.7: endpoint count replaces samples-per-prefix — one
                    // endpoint = one probe in this mode
                    LabeledSlider(
                        s.endpointsCountLabel, endpoints, { endpoints = it },
                        50..20000 step 50, valueText = endpoints.toString(),
                    )
                } else {
                    LabeledSlider(s.samplesPerPrefix, samples, { samples = it }, 50..3000, valueText = samples.toString())
                }
                LabeledSlider(
                    if (mode == ScanMode.ENDPOINT) s.wgRetries else s.tcpAttempts,
                    attempts, { attempts = it },
                    // v3.4 fix: the endpoint probe path clamps wg retries to
                    // 1..7 — the slider used to offer 8..10 there, silently capped.
                    if (mode == ScanMode.ENDPOINT) 1..7 else 1..10,
                    valueText = s.retryLabel(attempts),
                )
                LabeledSlider(s.timeout, timeoutMs, { timeoutMs = it }, 300..6000 step 100, valueText = s.milliseconds(timeoutMs))
                LabeledSlider(s.concurrency, concurrency, { concurrency = it }, 10..400, valueText = concurrency.toString())
                if (mode != ScanMode.ENDPOINT) {
                    // v3.7: TLS verification never runs in endpoint mode (the
                    // WireGuard handshake is its proof) — its budget and toggle
                    // are EDGE/CUSTOM controls only.
                    LabeledSlider(
                        s.tlsVerifyBudget,
                        verifyTopN, { verifyTopN = it }, 50..2000,
                        valueText = verifyTopN.toString(),
                    )
                }
                LabeledSlider(s.speedTopN, speedTopN, { speedTopN = it }, 5..300, valueText = speedTopN.toString())
                LabeledSlider(s.speedLanes, speedConc, { speedConc = it }, 1..8, valueText = s.retryLabel(speedConc))
                ToggleRow(
                    title = s.tlsVerify,
                    subtitle = s.tlsVerifyHint,
                    checked = tlsOn,
                    onChange = { tlsOn = it },
                )
                ToggleRow(
                    title = s.speedTest,
                    subtitle = when (mode) {
                        ScanMode.ENDPOINT -> s.speedTestHintEndpoint
                        else -> s.speedTestHintEdge
                    },
                    checked = speedOn,
                    onChange = { speedOn = it },
                )
                if (speedOn) {
                    Spacer(Modifier.height(8.dp))
                    SectionLabel(s.downloadSize)
                    Spacer(Modifier.height(7.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                        listOf(1, 5, 10, 20, 50).forEach { mb ->
                            SelectChip(
                                text = s.megabytes(mb),
                                selected = dlMb == mb,
                                onClick = { dlMb = mb },
                            )
                        }
                    }
                }
            }
        }

        Spacer(Modifier.height(18.dp))
        GradientButton(
            text = s.initiateDeepScan,
            enabled = !tuning,
            onClick = {
                val params = ScanParams(
                    mode = mode,
                    cidrs = cidrs,
                    family = family,
                    port = port,
                    samplesPerPrefix = samples,
                    endpointsCount = endpoints,
                    tcpAttempts = attempts,
                    tcpTimeoutMs = timeoutMs,
                    concurrency = concurrency,
                    tlsVerify = tlsOn,
                    verifyTopN = verifyTopN,
                    speedTest = speedOn,
                    speedTopN = speedTopN,
                    speedConcurrency = speedConc,
                    downloadBytes = dlMb.toLong() * 1024 * 1024,
                    warpAttempts = attempts,
                    udpNoise = udpNoise,
                    noiseCount = 5,
                )
                onStart(params)
            },
        )
        Spacer(Modifier.height(4.dp))
        Text(
            s.dnsNeverUsed,
            style = MaterialTheme.typography.bodySmall,
            color = Fade,
            modifier = Modifier.padding(horizontal = 2.dp),
        )
    }
}

/**
 * v3.8.1 (the toggle-poisoning fix) — pure state transition for the TLS +
 * SPEED toggles when the user switches scan modes. Pure function so the
 * regression test can pin the exact contract:
 *
 *  - ENTERING ENDPOINT: both toggles go OFF (endpoint mode has no TLS phase
 *    and opens as a pure BPB latency scan); the user's previous EDGE/CUSTOM
 *    choices are snapshotted (only the FIRST entry snapshots — a later
 *    re-entry after a restore re-snapshots the restored values).
 *  - LEAVING ENDPOINT: the snapshot is restored (default true — TLS verify
 *    is EDGE/CUSTOM's honest aliveness filter; running it off was exactly
 *    how DPI-fake endpoints came back through the mode switcher).
 *  - Any other switch (EDGE↔CUSTOM, same-mode): toggles untouched.
 */
internal data class ToggleRestore(
    val tls: Boolean,
    val speed: Boolean,
    val savedTls: Boolean?,
    val savedSpeed: Boolean?,
)

internal fun onModeSwitchToggles(
    newMode: ScanMode,
    prevMode: ScanMode,
    tls: Boolean,
    speed: Boolean,
    savedTls: Boolean?,
    savedSpeed: Boolean?,
): ToggleRestore = when {
    newMode == ScanMode.ENDPOINT && prevMode != ScanMode.ENDPOINT ->
        ToggleRestore(
            tls = false,
            speed = false,
            savedTls = savedTls ?: tls,
            savedSpeed = savedSpeed ?: speed,
        )

    newMode != ScanMode.ENDPOINT && prevMode == ScanMode.ENDPOINT ->
        ToggleRestore(
            tls = savedTls ?: true,
            speed = savedSpeed ?: true,
            savedTls = null,
            savedSpeed = null,
        )

    else -> ToggleRestore(tls, speed, savedTls, savedSpeed)
}
