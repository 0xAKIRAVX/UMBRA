package com.umbra.scanner.ui.screens

import android.content.Intent
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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.umbra.scanner.UmbraApp
import com.umbra.scanner.bridge.GoClean
import com.umbra.scanner.bridge.UmbraCore
import com.umbra.scanner.engine.ScanEngine
import com.umbra.scanner.i18n.LocalStrings
import com.umbra.scanner.net.WarpRegistration
import com.umbra.scanner.ui.components.GradientButton
import com.umbra.scanner.ui.components.NeonCard
import com.umbra.scanner.ui.components.OutlineButton
import com.umbra.scanner.ui.components.SectionLabel
import com.umbra.scanner.ui.components.ToggleRow
import com.umbra.scanner.ui.theme.MonoStyleSmall
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * v4 (the tri-lingual rebuild): the DEBUG CONSOLE — the on-device window
 * into the Rust + Go cores.
 *
 *   · engine status card — which native cores are live, versions
 *   · per-probe debug stream (WG packet sizes / hex previews / timings,
 *     CLEAN-IP tcp/tls/trace verdicts) from the live scan
 *   · single-endpoint DEEP PROBE — runs one full probe RIGHT NOW and prints
 *     every round: the "why doesn't THIS endpoint work" lens
 *   · export — the whole stream as text (share sheet)
 */
@Composable
fun DebugScreen(app: UmbraApp) {
    val s = LocalStrings.current
    val controller = app.controller
    val debugLines by controller.debugLog.collectAsState()
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    var probeTarget by remember { mutableStateOf("") }
    var probing by remember { mutableStateOf(false) }
    var probeResult by remember { mutableStateOf<List<String>>(emptyList()) }
    var debugOn by remember { mutableStateOf(ScanEngine.debugEnabled) }

    Box(Modifier.fillMaxSize()) {
        LazyColumn(
            state = rememberLazyListState(),
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                Spacer(Modifier.height(56.dp))
                Text(
                    s.debug.debugTitle,
                    style = MaterialTheme.typography.headlineSmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onBackground,
                )
            }

            // engine status
            item {
                NeonCard(Modifier.fillMaxWidth()) {
                    SectionLabel(s.debug.debugEngines)
                    Spacer(Modifier.height(6.dp))
                    Text(
                        controller.engineStatus,
                        style = MonoStyleSmall,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Spacer(Modifier.height(10.dp))
                    ToggleRow(
                        title = s.debug.debugToggle,
                        subtitle = null,
                        checked = debugOn,
                        onChange = {
                            debugOn = it
                            ScanEngine.debugEnabled = it
                            app.settings.setDebugLines(it)
                        },
                    )
                }
            }

            // deep probe
            item {
                NeonCard(Modifier.fillMaxWidth()) {
                    SectionLabel(s.debug.deepProbeTitle)
                    Spacer(Modifier.height(6.dp))
                    OutlinedTextField(
                        value = probeTarget,
                        onValueChange = { probeTarget = it },
                        singleLine = true,
                        placeholder = { Text(s.debug.deepProbeHint, style = MonoStyleSmall) },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                        modifier = Modifier.fillMaxWidth(),
                        textStyle = MonoStyleSmall,
                    )
                    Spacer(Modifier.height(10.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        GradientButton(
                            text = if (probing) s.debug.deepProbeBusy else s.debug.deepProbeWg,
                            onClick = {
                                runDeepProbe(
                                    target = probeTarget.trim(),
                                    clean = false,
                                    setBusy = { probing = it },
                                    setLines = { probeResult = it },
                                    scope = scope,
                                )
                            },
                            modifier = Modifier.weight(1f),
                            height = 48.dp,
                            enabled = !probing && probeTarget.isNotBlank(),
                        )
                        GradientButton(
                            text = if (probing) s.debug.deepProbeBusy else s.debug.deepProbeClean,
                            onClick = {
                                runDeepProbe(
                                    target = probeTarget.trim(),
                                    clean = true,
                                    setBusy = { probing = it },
                                    setLines = { probeResult = it },
                                    scope = scope,
                                )
                            },
                            modifier = Modifier.weight(1f),
                            height = 48.dp,
                            enabled = !probing && probeTarget.isNotBlank(),
                        )
                    }
                    if (probeResult.isNotEmpty()) {
                        Spacer(Modifier.height(10.dp))
                        SectionLabel(s.debug.deepResultTitle)
                        Spacer(Modifier.height(4.dp))
                        probeResult.forEach { line ->
                            Text(
                                line,
                                style = MonoStyleSmall,
                                fontFamily = FontFamily.Monospace,
                                color = MaterialTheme.colorScheme.onSurface,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .background(
                                        MaterialTheme.colorScheme.surface.copy(alpha = 0.55f),
                                        RoundedCornerShape(6.dp),
                                    )
                                    .padding(horizontal = 8.dp, vertical = 4.dp),
                            )
                        }
                    }
                }
            }

            // live stream
            item {
                NeonCard(Modifier.fillMaxWidth()) {
                    SectionLabel(s.debug.debugStream)
                    Spacer(Modifier.height(6.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        OutlineButton(
                            text = s.debug.exportDebug,
                            onClick = {
                                val text = controller.exportDebugLog()
                                val send = Intent(Intent.ACTION_SEND).apply {
                                    type = "text/plain"
                                    putExtra(Intent.EXTRA_TEXT, text)
                                    putExtra(Intent.EXTRA_TITLE, "UMBRA debug log")
                                }
                                context.startActivity(
                                    Intent.createChooser(send, s.debug.exportDebug),
                                )
                            },
                            modifier = Modifier.weight(1f),
                        )
                        OutlineButton(
                            text = s.debug.clearDebug,
                            onClick = { controller.clearDebugLog() },
                            modifier = Modifier.weight(1f),
                        )
                    }
                }
            }

            if (debugLines.isEmpty()) {
                item {
                    Text(
                        s.debug.debugEmpty,
                        style = MonoStyleSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            } else {
                items(debugLines) { line ->
                    Text(
                        line,
                        style = MonoStyleSmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(
                                MaterialTheme.colorScheme.surface.copy(alpha = 0.45f),
                                RoundedCornerShape(6.dp),
                            )
                            .padding(horizontal = 8.dp, vertical = 4.dp),
                    )
                }
            }
            item { Spacer(Modifier.height(88.dp)) }
        }
    }
}

/** Runs one deep probe (WG or CLEAN) off the main thread and prints every
 *  debug round into the result panel. v4.0.1: the whole probe is wrapped in
 *  runCatching — the Compose scope has NO crash net, and an Error (OOM etc.)
 *  escaping deepProbeWg/deepProbeClean would kill the process — the exact
 *  class of failure CrashGuard exists to make survivable everywhere else. */
private fun runDeepProbe(
    target: String,
    clean: Boolean,
    setBusy: (Boolean) -> Unit,
    setLines: (List<String>) -> Unit,
    scope: kotlinx.coroutines.CoroutineScope,
) {
    setBusy(true)
    setLines(emptyList())
    scope.launch(Dispatchers.IO) {
        try {
            val lines = runCatching {
                if (clean) deepProbeClean(target) else deepProbeWg(target)
            }.getOrElse { e ->
                listOf("probe crashed · ${e.javaClass.simpleName}" +
                    (e.message?.let { ": $it" } ?: ""))
            }
            withContext(Dispatchers.Main) { setLines(lines) }
        } finally {
            withContext(Dispatchers.Main) { setBusy(false) }
        }
    }
}

/** Parses "ip" / "ip:port" / "[v6]:port" → (ip, port default).
 *  v4.0.1 fix: the default port is now PROBE-SPECIFIC — a bare IP typed into
 *  the WG deep probe used to default to :443 (the clean-ip default) and the
 *  probe then honestly reported a dead endpoint: WARP speaks 2408/894/928,
 *  not 443. The split stays pure — unit-tested directly. */
internal fun splitTarget(text: String, defaultPort: Int): Pair<String, Int> {
    val t = text.trim()
    return if (t.startsWith("[")) {
        val end = t.indexOf(']')
        if (end > 0 && t.getOrNull(end + 1) == ':') {
            t.substring(0, end + 1) to (t.substring(end + 2).toIntOrNull() ?: defaultPort)
        } else t to defaultPort
    } else if (t.count { it == ':' } == 1 && t.substringAfter(':').toIntOrNull() != null) {
        t.substringBefore(':') to t.substringAfter(':').toInt()
    } else {
        t to defaultPort
    }
}

/** WG deep probes default to the canonical WARP port. */
private const val WG_DEFAULT_PORT = 2408

/** CLEAN-IP deep probes default to the HTTPS edge port. */
private const val CLEAN_DEFAULT_PORT = 443

private fun deepProbeWg(target: String): List<String> {
    val (ip, port) = splitTarget(target, WG_DEFAULT_PORT)
    val out = ArrayList<String>()
    if (!UmbraCore.loaded) {
        out.add("rust core not loaded — cannot run the native WG probe")
        return out
    }
    out.add("wg deep probe · $ip:$port · registering/using identity…")
    val account = try {
        kotlinx.coroutines.runBlocking { WarpRegistration.register() }
    } catch (e: Exception) {
        out.add("identity failed · ${e.message ?: e.javaClass.simpleName}")
        return out
    }
    val cfg = UmbraCore.buildConfig(
        attempts = 2,
        timeoutMs = 4000,
        interMs = 250,
        noise = true,
        noiseCount = 3,
        debug = true,
        identity = UmbraCore.WgIdentity(
            priv = account.privateKey,
            pub = account.publicKey,
            peer = account.responderPublicKey,
            v4 = account.v4,
        ),
    )
    val res = runCatching { UmbraCore.probeOnce(ip, port, cfg) }.getOrNull()
    if (res == null) {
        out.add("native probe failed")
        return out
    }
    res.optJSONArray("dbg")?.let { arr ->
        for (i in 0 until arr.length()) out.add(arr.optString(i))
    }
    out.add(
        "verdict · handshakes ${res.optInt("hs", 0)}/${res.optInt("att", 0)} · " +
            "in-tunnel pings ${res.optInt("png", 0)} · rtt " +
            (if (res.isNull("rtt")) "—" else "%.0f ms".format(java.util.Locale.US, res.optDouble("rtt"))) +
            " · err ${res.optString("err", "")}",
    )
    return out
}

private fun deepProbeClean(target: String): List<String> {
    val (ip, port) = splitTarget(target, CLEAN_DEFAULT_PORT)
    val out = ArrayList<String>()
    if (!GoClean.loaded) {
        out.add("go clean-ip engine not loaded — cannot run the clean probe")
        return out
    }
    out.add("clean deep probe · $ip:$port · tcp latency + tls + trace + speed…")
    val cfg = GoClean.buildConfig(
        cidrs = emptyList(),
        ports = listOf(port),
        samples = 1,
        attempts = 3,
        timeoutMs = 2500,
        speedBytes = 4L * 1024 * 1024,
        sni = "speed.cloudflare.com",
        debug = true,
    )
    val res = runCatching { GoClean.probeOnce(ip, port, cfg) }.getOrNull()
        ?: runCatching {
            // empty cidrs may be rejected — retry with the ip's own /32
            GoClean.probeOnce(
                ip, port,
                GoClean.buildConfig(
                    cidrs = listOf(if (ip.contains(':')) "$ip/128" else "$ip/32"),
                    ports = listOf(port), samples = 1,
                ),
            )
        }.getOrNull()
    if (res == null) {
        out.add("go probe failed")
        return out
    }
    out.add(
        "tcp · ${res.optInt("tcpOk", 0)}/${res.optInt("tcpAtt", 0)} attempts" +
            (if (res.isNull("lat")) "" else " · lat %.0f ms".format(java.util.Locale.US, res.optDouble("lat"))) +
            (if (res.isNull("jit")) "" else " · jitter %.0f ms".format(java.util.Locale.US, res.optDouble("jit"))),
    )
    out.add(
        "tls · " + (if (res.optBoolean("tlsOk")) "VERIFIED" else "failed") +
            (if (res.isNull("tlsMs")) "" else " · handshake %.0f ms".format(java.util.Locale.US, res.optDouble("tlsMs"))) +
            (if (res.optBoolean("tlsOk")) " · colo ${res.optString("colo", "—")}" else " · ${res.optString("err", "")}"),
    )
    out.add(
        "speed · " + (if (res.isNull("mbps")) "—" else "%.1f Mbps".format(java.util.Locale.US, res.optDouble("mbps"))) +
            " · ${res.optLong("bytes", 0L)} bytes",
    )
    return out
}
