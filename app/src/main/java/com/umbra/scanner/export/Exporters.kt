package com.umbra.scanner.export

import android.content.Context
import android.content.Intent
import android.net.Uri
import com.umbra.scanner.core.Ranking
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.core.ScanResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object Exporters {

    private fun stamp(): String =
        SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date())

    fun csv(results: List<ScanResult>): String {
        val sb = StringBuilder(128 * results.size.coerceAtLeast(1))
        sb.append("ip,protocol,port,latency_ms,jitter_ms,loss_pct,speed_mbps,downloaded_bytes,attempts,ok,tls,tls_handshake_ms,http_status,score,mode,error\n")
        for (r in results) {
            sb.append(r.ip).append(',')
            sb.append(r.protocol.name).append(',')
            sb.append(r.port).append(',')
            sb.append(r.latencyMs?.let { "%.1f".format(java.util.Locale.US, it) } ?: "").append(',')
            sb.append(r.jitterMs?.let { "%.1f".format(java.util.Locale.US, it) } ?: "").append(',')
            sb.append(r.lossPct).append(',')
            sb.append(r.speedMbps?.let { "%.2f".format(java.util.Locale.US, it) } ?: "").append(',')
            sb.append(r.downloadedBytes).append(',')
            sb.append(r.tcpAttempts).append(',')
            sb.append(r.successfulAttempts).append(',')
            sb.append(if (r.tlsSuccess) "yes" else "no").append(',')
            sb.append(r.tlsHandshakeMs?.let { "%.0f".format(java.util.Locale.US, it) } ?: "").append(',')
            sb.append(r.httpStatus ?: "").append(',')
            sb.append("%.1f".format(java.util.Locale.US, Ranking.scoreOf(r))).append(',')
            sb.append(r.mode.name).append(',')
            sb.append(csvEscape(r.error ?: "")).append('\n')
        }
        return sb.toString()
    }

    private fun csvEscape(s: String): String =
        if (s.contains(',') || s.contains('"') || s.contains('\n')) "\"${s.replace("\"", "\"\"")}\"" else s

    fun txt(results: List<ScanResult>, params: ScanParams?): String {
        val sb = StringBuilder()
        sb.append("╔════════════════════════════════════════════════════════╗\n")
        sb.append("║  U M B R A  ·  Cloudflare deep scan report            ║\n")
        sb.append("╚════════════════════════════════════════════════════════╝\n")
        sb.append("exported    : ").append(stamp()).append('\n')
        params?.let {
            sb.append("mode        : ").append(it.mode.name).append('\n')
            sb.append("port        : ").append(it.port).append('\n')
            sb.append("family      : ").append(it.family.label).append('\n')
            sb.append("attempts    : ").append(it.tcpAttempts).append(" × ").append(it.tcpTimeoutMs).append(" ms\n")
            sb.append("concurrency : ").append(it.concurrency).append('\n')
        }
        sb.append("results     : ").append(results.size).append(" alive endpoints\n\n")
        sb.append(String.format(Locale.US, "%-4s %-43s %6s %7s %5s %9s %6s\n",
            "#", "IP", "PORT", "LAT", "LOSS", "SPEED", "SCORE"))
        sb.append("─".repeat(90)).append('\n')
        for ((i, r) in results.withIndex()) {
            sb.append(String.format(Locale.US, "%-4d %-43s %6d %6s %4d%% %9s %6s\n",
                i + 1,
                r.ip,
                r.port,
                r.latencyMs?.let { "%.0fms".format(java.util.Locale.US, it) } ?: "-",
                r.lossPct,
                r.speedMbps?.let { "%.1fM".format(java.util.Locale.US, it) } ?: "-",
                "%.0f".format(java.util.Locale.US, Ranking.scoreOf(r)),
            ))
            r.error?.let { sb.append("     ⚠ ").append(it).append('\n') }
        }
        return sb.toString()
    }

    fun json(results: List<ScanResult>, params: ScanParams?): String {
        val sb = StringBuilder()
        sb.append("{\n  \"app\": \"UMBRA\",\n  \"version\": 2,\n  \"exportedAt\": \"").append(stamp()).append('"')
        params?.let {
            sb.append(",\n  \"params\": {\n")
            sb.append("    \"mode\": \"").append(it.mode.name).append("\",\n")
            sb.append("    \"port\": ").append(it.port).append(",\n")
            sb.append("    \"family\": \"").append(it.family.name).append("\",\n")
            sb.append("    \"tcpAttempts\": ").append(it.tcpAttempts).append(",\n")
            sb.append("    \"tcpTimeoutMs\": ").append(it.tcpTimeoutMs).append(",\n")
            sb.append("    \"concurrency\": ").append(it.concurrency).append(",\n")
            sb.append("    \"samplesPerPrefix\": ").append(it.samplesPerPrefix).append(",\n")
            sb.append("    \"downloadBytes\": ").append(it.downloadBytes).append("\n  }")
        }
        sb.append(",\n  \"results\": [")
        if (results.isNotEmpty()) sb.append('\n')
        for ((i, r) in results.withIndex()) {
            sb.append("    {\n")
            sb.append("      \"ip\": \"").append(jsonStr(r.ip)).append("\",\n")
            sb.append("      \"protocol\": \"").append(r.protocol.name).append("\",\n")
            sb.append("      \"port\": ").append(r.port).append(",\n")
            sb.append("      \"latencyMs\": ").append(r.latencyMs?.let { "%.1f".format(java.util.Locale.US, it) } ?: "null").append(",\n")
            sb.append("      \"jitterMs\": ").append(r.jitterMs?.let { "%.1f".format(java.util.Locale.US, it) } ?: "null").append(",\n")
            sb.append("      \"packetLoss\": ").append(r.packetLoss).append(",\n")
            sb.append("      \"speedMbps\": ").append(r.speedMbps?.let { "%.3f".format(java.util.Locale.US, it) } ?: "null").append(",\n")
            sb.append("      \"downloadedBytes\": ").append(r.downloadedBytes).append(",\n")
            sb.append("      \"tcpAttempts\": ").append(r.tcpAttempts).append(",\n")
            sb.append("      \"successfulAttempts\": ").append(r.successfulAttempts).append(",\n")
            sb.append("      \"tlsSuccess\": ").append(r.tlsSuccess).append(",\n")
            sb.append("      \"httpStatus\": ").append(r.httpStatus ?: "null").append(",\n")
            sb.append("      \"score\": ").append("%.1f".format(java.util.Locale.US, Ranking.scoreOf(r))).append(",\n")
            sb.append("      \"error\": ").append(r.error?.let { "\"${jsonStr(it)}\"" } ?: "null").append("\n")
            sb.append("    }").append(if (i < results.size - 1) ",\n" else "\n")
        }
        sb.append("  ]\n}")
        return sb.toString()
    }

    private fun jsonStr(s: String): String = s
        .replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\n", " ")
        .replace("\r", "")
        .replace("\t", " ")

    suspend fun writeToUri(context: Context, uri: Uri, content: String): Boolean =
        withContext(Dispatchers.IO) {
            try {
                context.contentResolver.openOutputStream(uri, "wt")?.use { out ->
                    out.write(content.toByteArray(Charsets.UTF_8))
                    out.flush()
                } != null
            } catch (e: Exception) {
                false
            }
        }

    fun shareText(context: Context, text: String, title: String = "UMBRA scan results") {
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, text)
            putExtra(Intent.EXTRA_TITLE, title)
        }
        context.startActivity(Intent.createChooser(intent, "Share via"))
    }
}
