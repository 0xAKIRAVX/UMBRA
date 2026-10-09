package com.umbra.scanner.core

import org.json.JSONArray
import org.json.JSONObject

/** v3.5.2: optDouble returns NaN for corrupt/absent values — never let NaN
 *  leak into persisted result fields (ranking math sorts them arbitrarily). */
private fun JSONObject.optDoubleOrNull(key: String): Double? =
    optDouble(key).takeUnless { it.isNaN() }

/**
 * Compact ScanResult ⇄ JSON codec for the persisted "smart picks" store.
 * Only the fields the results board and pick logic need survive the trip —
 * the full report format remains Exporters.json's business.
 */
object ResultCodec {

    fun toJson(r: ScanResult): JSONObject {
        val o = JSONObject()
        o.put("ip", r.ip)
        o.put("protocol", r.protocol.name)
        o.put("port", r.port)
        r.latencyMs?.let { o.put("lat", it) }
        r.jitterMs?.let { o.put("jit", it) }
        o.put("loss", r.packetLoss)
        r.speedMbps?.let { o.put("spd", it) }
        r.downloadedBytes?.let { o.put("dl", it) } ?: o.put("dl", 0L)
        o.put("att", r.tcpAttempts)
        o.put("ok", r.successfulAttempts)
        o.put("tls", r.tlsSuccess)
        if (r.tlsSkipped) o.put("tlsSkip", true)
        r.tlsHandshakeMs?.let { o.put("tlsMs", it) }
        r.httpStatus?.let { o.put("http", it) }
        o.put("wg", r.wgHandshakes)
        r.error?.let { o.put("err", it) }
        o.put("mode", r.mode.name)
        return o
    }

    fun fromJson(o: JSONObject): ScanResult? = runCatching {
        val ip = o.optString("ip")
        if (ip.isBlank()) return null
        ScanResult(
            ip = ip,
            protocol = runCatching { IpProtocol.valueOf(o.optString("protocol", "IPv4")) }
                .getOrDefault(IpProtocol.IPv4),
            port = o.optInt("port", 443).coerceIn(1, 65535),
            latencyMs = if (o.has("lat") && !o.isNull("lat")) o.optDoubleOrNull("lat") else null,
            jitterMs = if (o.has("jit") && !o.isNull("jit")) o.optDoubleOrNull("jit") else null,
            packetLoss = o.optDouble("loss", 0.0).takeUnless { it.isNaN() }?.coerceIn(0.0, 1.0) ?: 0.0,
            speedMbps = if (o.has("spd") && !o.isNull("spd")) o.optDoubleOrNull("spd") else null,
            downloadedBytes = o.optLong("dl", 0L),
            tcpAttempts = o.optInt("att", 0),
            successfulAttempts = o.optInt("ok", 0),
            tlsSuccess = o.optBoolean("tls", false),
            tlsSkipped = o.optBoolean("tlsSkip", false),
            tlsHandshakeMs = if (o.has("tlsMs") && !o.isNull("tlsMs")) o.optDoubleOrNull("tlsMs") else null,
            httpStatus = if (o.has("http") && !o.isNull("http")) o.optInt("http") else null,
            wgHandshakes = o.optInt("wg", 0),
            error = if (o.has("err") && !o.isNull("err")) o.optString("err") else null,
            mode = runCatching { ScanMode.valueOf(o.optString("mode", "CF_EDGE")) }
                .getOrDefault(ScanMode.CF_EDGE),
        )
    }.getOrNull()

    fun toJsonList(list: List<ScanResult>): String {
        val a = JSONArray()
        for (r in list) a.put(toJson(r))
        return a.toString()
    }

    fun fromJsonList(text: String?): List<ScanResult> {
        if (text.isNullOrBlank()) return emptyList()
        return runCatching {
            val a = JSONArray(text)
            val out = ArrayList<ScanResult>(a.length())
            for (i in 0 until a.length()) {
                val o = a.optJSONObject(i) ?: continue
                fromJson(o)?.let { out.add(it) }
            }
            out
        }.getOrDefault(emptyList())
    }
}
