package com.umbra.scanner.ui.screens

import android.content.Intent
import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Casino
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.QrCode2
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.umbra.scanner.UmbraApp
import com.umbra.scanner.core.IpText
import com.umbra.scanner.i18n.LocalStrings
import com.umbra.scanner.ui.components.ActionRow
import com.umbra.scanner.ui.components.NeonCard
import com.umbra.scanner.ui.components.SectionLabel
import com.umbra.scanner.ui.components.staggerIn
import com.umbra.scanner.ui.theme.Fade
import com.umbra.scanner.ui.theme.Fog
import com.umbra.scanner.ui.theme.Graphite
import com.umbra.scanner.ui.theme.LocalAccent
import com.umbra.scanner.ui.theme.Mist
import com.umbra.scanner.ui.theme.MonoStyle
import com.umbra.scanner.ui.theme.MonoStyleSmall
import com.umbra.scanner.ui.theme.SlateLine
import com.umbra.scanner.vless.QrGen
import com.umbra.scanner.vless.VlessGenerator

@Composable
fun VlessScreen(app: UmbraApp) {
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    val accent = LocalAccent.current
    val s = LocalStrings.current
    val controller = app.controller

    var uuid by rememberSaveable {
        mutableStateOf(VlessGenerator.randomUuid())
    }
    var host by rememberSaveable { mutableStateOf("") }
    var port by rememberSaveable { mutableStateOf("443") }
    var sni by rememberSaveable { mutableStateOf("") }
    var wsPath by rememberSaveable { mutableStateOf("/") }
    var remark by rememberSaveable { mutableStateOf("UMBRA-node") }
    var showQr by rememberSaveable { mutableStateOf(false) }

    // v3 fix: the pending IP from a results-row tap is consumed on EVERY fresh
    // composition of this screen — the old remember{} capture only worked once
    // per process because rememberSaveable restored the previous host text.
    LaunchedEffect(Unit) {
        controller.pendingVlessIp?.let { prefill ->
            host = prefill
            controller.pendingVlessIp = null
        }
    }

    val portInt = port.toIntOrNull() ?: 443
    val config = VlessGenerator.Config(
        uuid = uuid,
        host = host,
        port = portInt,
        sni = sni,
        wsPath = wsPath,
        remark = remark,
    )
    val link = VlessGenerator.buildLink(config)
    // v3.4 fix: "00000" parsed to port 0 and buildLink silently coerced it to 1 —
    // a garbage port must simply be invalid, not quietly rewritten.
    val valid = host.isNotBlank() && portInt in 1..65535 &&
        VlessGenerator.isValidUuid(uuid) && !VlessGenerator.isTestOnlySni(sni)
    val testOnly = sni.isNotBlank() && VlessGenerator.isTestOnlySni(sni)
    // v3.2 fix: QR encoding (ZXing + 512x512 bitmap) used to run during
    // composition on the main thread and re-ran on every keystroke. It now runs
    // off the main thread and is only produced for a VALID link.
    var qrBitmap by remember { mutableStateOf<android.graphics.Bitmap?>(null) }
    LaunchedEffect(link, showQr, valid) {
        qrBitmap = null
        if (showQr && valid) {
            withContext(Dispatchers.Default) {
                val bmp = runCatching { QrGen.generate(link) }.getOrNull()
                if (bmp != null) qrBitmap = bmp
            }
        }
    }

    Column(
        Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp)
    ) {
        Spacer(Modifier.height(10.dp))
        Text(
            s.vlessForge,
            style = MaterialTheme.typography.displayMedium,
            color = Mist,
            modifier = Modifier.staggerIn(0),
            maxLines = 1,
            softWrap = false,
            overflow = TextOverflow.Ellipsis,
        )
        Spacer(Modifier.height(4.dp))
        Text(
            s.vlessTagline,
            style = MaterialTheme.typography.bodySmall,
            color = Fade,
            modifier = Modifier.staggerIn(1),
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )

        Spacer(Modifier.height(14.dp))
        NeonCard(modifier = Modifier.staggerIn(2)) {
            SectionLabel(s.identity)
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = uuid,
                onValueChange = { uuid = it.trim() },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                placeholder = { Text(s.uuidField, style = MonoStyleSmall, color = Fade) },
                textStyle = MonoStyleSmall.copy(color = Mist),
                trailingIcon = {
                    Box(
                        Modifier
                            .size(26.dp)
                            .clip(RoundedCornerShape(7.dp))
                            .clickable { uuid = VlessGenerator.randomUuid() },
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(Icons.Rounded.Casino, null, tint = accent.primary, modifier = Modifier.size(17.dp))
                    }
                },
                isError = !VlessGenerator.isValidUuid(uuid),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = accent.primary.copy(alpha = 0.8f),
                    unfocusedBorderColor = SlateLine,
                    cursorColor = accent.primary,
                ),
            )

            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = host,
                onValueChange = { host = it.trim() },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                placeholder = { Text(s.hostPlaceholder, style = MonoStyleSmall, color = Fade) },
                textStyle = MonoStyleSmall.copy(color = Mist),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = accent.primary.copy(alpha = 0.8f),
                    unfocusedBorderColor = SlateLine,
                    cursorColor = accent.primary,
                ),
            )
            if (host.contains(':') && host.isNotBlank()) {
                Spacer(Modifier.height(4.dp))
                Text(
                    s.ipv6Detected(host.trim('[', ']')),
                    style = MaterialTheme.typography.bodySmall,
                    color = accent.tint,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = port,
                onValueChange = { port = it.filter(Char::isDigit).take(5) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                placeholder = { Text(s.portField, style = MonoStyleSmall, color = Fade) },
                textStyle = MonoStyleSmall.copy(color = Mist),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = accent.primary.copy(alpha = 0.8f),
                    unfocusedBorderColor = SlateLine,
                    cursorColor = accent.primary,
                ),
            )

            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = sni,
                onValueChange = { sni = it },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                isError = testOnly,
                placeholder = { Text(s.sniPlaceholder, style = MonoStyleSmall, color = Fade) },
                textStyle = MonoStyleSmall.copy(color = Mist),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = accent.primary.copy(alpha = 0.8f),
                    unfocusedBorderColor = SlateLine,
                    cursorColor = accent.primary,
                ),
            )
            if (testOnly) {
                Spacer(Modifier.height(4.dp))
                Text(
                    s.sniTestOnlyWarning,
                    style = MaterialTheme.typography.bodySmall,
                    color = accent.tint,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = wsPath,
                    onValueChange = { wsPath = it },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                    placeholder = { Text(s.wsPathField, style = MonoStyleSmall, color = Fade) },
                    textStyle = MonoStyleSmall.copy(color = Mist),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = accent.primary.copy(alpha = 0.8f),
                        unfocusedBorderColor = SlateLine,
                        cursorColor = accent.primary,
                    ),
                )
                OutlinedTextField(
                    value = remark,
                    onValueChange = { remark = it },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                    placeholder = { Text(s.remarkField, style = MonoStyleSmall, color = Fade) },
                    textStyle = MonoStyleSmall.copy(color = Mist),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = accent.primary.copy(alpha = 0.8f),
                        unfocusedBorderColor = SlateLine,
                        cursorColor = accent.primary,
                    ),
                )
            }
        }

        Spacer(Modifier.height(14.dp))
        NeonCard(glow = false, modifier = Modifier.staggerIn(3)) {
            SectionLabel(s.generatedLink)
            Spacer(Modifier.height(8.dp))
            SelectionContainer {
                Text(
                    if (valid) link else s.fillToForge,
                    style = MonoStyle.copy(fontSize = 10.5.sp),
                    color = if (valid) accent.tint else Fade,
                    maxLines = 6,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Spacer(Modifier.height(14.dp))
            ActionRow(Icons.Rounded.ContentCopy, s.copyLink, tint = if (valid) Mist else Fog) {
                if (valid) {
                    clipboard.setText(AnnotatedString(link))
                    Toast.makeText(context, "vless link copied", Toast.LENGTH_SHORT).show()
                }
            }
            Spacer(Modifier.height(7.dp))
            ActionRow(Icons.Rounded.Share, s.shareLink, tint = if (valid) Mist else Fog) {
                if (valid) {
                    val intent = Intent(Intent.ACTION_SEND).apply {
                        type = "text/plain"
                        putExtra(Intent.EXTRA_TEXT, link)
                    }
                    context.startActivity(Intent.createChooser(intent, "Share vless link"))
                }
            }
            Spacer(Modifier.height(7.dp))
            ActionRow(Icons.Rounded.QrCode2, if (showQr) s.hideQr else s.showQr, tint = if (valid) accent.tint else Fog) {
                if (valid) showQr = !showQr
            }
            AnimatedVisibility(
                visible = showQr,
                enter = scaleIn(
                    initialScale = 0.80f,
                    animationSpec = spring(
                        dampingRatio = Spring.DampingRatioMediumBouncy,
                        stiffness = Spring.StiffnessMediumLow,
                    ),
                ) + fadeIn(),
                exit = scaleOut(targetScale = 0.85f) + fadeOut(),
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    val bmp = qrBitmap
                    if (bmp != null) {
                        Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                            Image(
                                bitmap = bmp.asImageBitmap(),
                                contentDescription = "vless qr",
                                modifier = Modifier
                                    .size(230.dp)
                                    .clip(RoundedCornerShape(14.dp)),
                            )
                        }
                    }
                    Spacer(Modifier.height(10.dp))
                Text(
                    s.qrHint,
                    style = MaterialTheme.typography.bodySmall,
                    color = Fade,
                    modifier = Modifier.align(Alignment.CenterHorizontally),
                )
                }
            }
        }

        Spacer(Modifier.height(14.dp))
        Text(
            s.vlessUsageNote,
            style = MaterialTheme.typography.bodySmall,
            color = Fog,
            modifier = Modifier.padding(horizontal = 4.dp),
        )
        Spacer(Modifier.height(24.dp))
    }
}
