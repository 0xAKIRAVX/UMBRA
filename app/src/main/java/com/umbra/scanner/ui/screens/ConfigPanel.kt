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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.shape.RoundedCornerShape
import com.umbra.scanner.UmbraApp
import com.umbra.scanner.core.IpGenerator
import com.umbra.scanner.core.NetFamily
import com.umbra.scanner.core.Presets
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.core.WarpFlavor
import com.umbra.scanner.engine.AutoTune
import com.umbra.scanner.i18n.LocalStrings
import com.umbra.scanner.ui.components.GradientButton
import com.umbra.scanner.ui.components.LabeledSlider
import com.umbra.scanner.ui.components.NeonCard
import com.umbra.scanner.ui.components.OutlineButton
import com.umbra.scanner.ui.components.PanelShape
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

    var modeIdx by rememberSaveable { mutableIntStateOf(saved.mode.ordinal) }
    var familyIdx by rememberSaveable { mutableIntStateOf(saved.family.ordinal) }
    var port by rememberSaveable { mutableIntStateOf(saved.port) }
    var sweep by rememberSaveable { mutableStateOf(saved.portSweep) }
    var sweepPortsStr by rememberSaveable { mutableStateOf(saved.sweepPorts.joinToString(",")) }
    var warpPlus by rememberSaveable { mutableStateOf(saved.warpFlavor == WarpFlavor.WARP_PLUS) }
    var udpNoise by rememberSaveable { mutableStateOf(saved.udpNoise) }
    var customCidrs by rememberSaveable {
        mutableStateOf(saved.cidrs.filter { it.contains('/') }.joinToString("\n"))
    }
    var samples by rememberSaveable { mutableIntStateOf(saved.samplesPerPrefix) }
    var attempts by rememberSaveable { mutableIntStateOf(saved.tcpAttempts) }
    var timeoutMs by rememberSaveable { mutableIntStateOf(saved.tcpTimeoutMs) }
    var concurrency by rememberSaveable { mutableIntStateOf(saved.concurrency) }
    var verifyTopN by rememberSaveable { mutableIntStateOf(saved.verifyTopN) }
    var speedOn by rememberSaveable { mutableStateOf(saved.speedTest) }
    var speedTopN by rememberSaveable { mutableIntStateOf(saved.speedTopN) }
    var speedConc by rememberSaveable { mutableIntStateOf(saved.speedConcurrency) }
    var dlMb by rememberSaveable { mutableIntStateOf(saved.downloadMbLabel) }
    var tlsOn by rememberSaveable { mutableStateOf(saved.tlsVerify) }
    var advanced by rememberSaveable { mutableStateOf(false) }

    // transient auto-tune state
    var tuning by remember { mutableStateOf(false) }
    var tuneStep by remember { mutableStateOf<String?>(null) }
    var tuneNotes by remember { mutableStateOf<List<String>>(emptyList()) }

    val mode = ScanMode.entries.getOrElse(modeIdx) { ScanMode.CF_EDGE }
    val family = NetFamily.entries.getOrElse(familyIdx) { NetFamily.BOTH }
    val cidrs = if (mode == ScanMode.CUSTOM) {
        customCidrs.lines().map { it.trim() }.filter { it.isNotBlank() }
    } else {
        Presets.cidrsFor(mode, family)
    }
    val sweepPorts = sweepPortsStr.split(',').mapNotNull { it.trim().toIntOrNull() }.distinct()
    val sweepEnabled = mode == ScanMode.WARP && sweep
    val portFactor = if (sweepEnabled) {
        (if (sweepPorts.isEmpty()) Presets.WARP_PORTS_FULL else sweepPorts).size
    } else 1

    val estimate = remember(mode, cidrs, family, samples, sweepEnabled, sweepPortsStr) {
        // v3.2 fix: WARP used to hand-roll `blocks × samples`, ignoring the
        // small-block enumeration cap (254/24) — with the slider above 256 the
        // displayed probe count was overstated up to 12x. Use the same capped
        // estimator the generator actually honors.
        val base = if (mode == ScanMode.WARP) {
            val v4 = IpGenerator.estimate(Presets.WARP_V4, NetFamily.V4, samples)
            when (family) {
                NetFamily.V4 -> v4
                NetFamily.V6 -> v4 * 2
                else -> v4 * 3
            }
        } else {
            IpGenerator.estimate(cidrs, family, samples)
        }
        base * portFactor
    }

    NeonCard(modifier = Modifier.staggerIn(1)) {
        Text(s.mode, style = MaterialTheme.typography.labelSmall, color = Fade)
        Spacer(Modifier.height(7.dp))
        Segmented(
            options = listOf(s.modeCfEdge, s.modeWarp, s.modeCustom),
            selected = modeIdx,
            onSelect = { i ->
                modeIdx = i
                val m = ScanMode.entries[i]
                port = Presets.defaultPort(m)
                if (m != ScanMode.WARP) sweep = false
            },
        )
        Spacer(Modifier.height(6.dp))
        Text(
            when (mode) {
                ScanMode.CF_EDGE -> s.taglineCfEdge
                ScanMode.WARP -> s.taglineWarp
                ScanMode.CUSTOM -> s.taglineCustom
            },
            style = MaterialTheme.typography.bodySmall,
            color = Fade,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )

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
            if (mode == ScanMode.WARP) {
                SectionLabel(s.flavor)
                Spacer(Modifier.height(7.dp))
                Segmented(
                    options = listOf(s.modeWarp, s.warpPlus),
                    selected = if (warpPlus) 1 else 0,
                    onSelect = { warpPlus = it == 1 },
                )
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
                        sweep = result.portSweep
                        sweepPortsStr = result.sweepPorts.joinToString(",")
                        samples = result.samplesPerPrefix
                        attempts = if (mode == ScanMode.WARP) result.warpAttempts else result.tcpAttempts
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
            if (mode == ScanMode.WARP) {
                SelectChip(
                    text = s.sweepLabel(if (sweepPorts.isEmpty()) Presets.warpPortsCount() else sweepPorts.size),
                    selected = sweep,
                    onClick = {
                        sweep = !sweep
                        if (!sweep) sweepPortsStr = ""
                    },
                )
            }
            Presets.portsFor(mode).forEach { p ->
                SelectChip(
                    text = p.toString(),
                    selected = !sweep && port == p,
                    onClick = {
                        port = p
                        sweep = false
                    },
                )
            }
        }
        if (mode == ScanMode.WARP) {
            Spacer(Modifier.height(10.dp))
            ToggleRow(
                title = s.udpNoise,
                subtitle = s.udpNoiseHint,
                checked = udpNoise,
                onChange = { udpNoise = it },
            )
            Spacer(Modifier.height(8.dp))
            Text(
                if (sweepEnabled) {
                    s.warpSweepHint(if (sweepPorts.isEmpty()) Presets.warpPortsCount() else sweepPorts.size)
                } else {
                    s.warpSingleHint
                },
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
                s.probesEstimate(estimate, cidrs.size) + if (portFactor > 1) s.portsFactor(portFactor) else "",
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
                LabeledSlider(s.samplesPerPrefix, samples, { samples = it }, 50..3000, valueText = samples.toString())
                LabeledSlider(
                    if (mode == ScanMode.WARP) s.wgRetries else s.tcpAttempts,
                    attempts, { attempts = it }, 1..10,
                    valueText = s.retryLabel(attempts),
                )
                LabeledSlider(s.timeout, timeoutMs, { timeoutMs = it }, 300..6000 step 100, valueText = s.milliseconds(timeoutMs))
                LabeledSlider(s.concurrency, concurrency, { concurrency = it }, 10..400, valueText = concurrency.toString())
                LabeledSlider(
                    s.tlsVerifyBudget,
                    verifyTopN, { verifyTopN = it }, 50..2000,
                    valueText = verifyTopN.toString(),
                )
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
                    subtitle = if (mode == ScanMode.WARP) s.speedTestHintWarp else s.speedTestHintEdge,
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
                    tcpAttempts = attempts,
                    tcpTimeoutMs = timeoutMs,
                    concurrency = concurrency,
                    tlsVerify = tlsOn,
                    verifyTopN = verifyTopN,
                    speedTest = speedOn,
                    speedTopN = speedTopN,
                    speedConcurrency = speedConc,
                    downloadBytes = dlMb.toLong() * 1024 * 1024,
                    warpFlavor = if (warpPlus) WarpFlavor.WARP_PLUS else WarpFlavor.WARP,
                    portSweep = sweepEnabled,
                    sweepPorts = if (sweepEnabled) sweepPorts else emptyList(),
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
