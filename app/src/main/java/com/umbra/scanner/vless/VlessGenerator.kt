package com.umbra.scanner.vless

import com.umbra.scanner.core.IpText
import java.net.URLEncoder
import java.util.UUID

/**
 * VLESS link builder for exact-IP Cloudflare workers.
 * IPv6 addresses are always wrapped in square brackets as required by RFC 3986.
 * Format:
 * vless://UUID@[host]:port?encryption=none&security=tls&sni=S&type=ws&host=S&path=P#REMARK
 */
object VlessGenerator {

    data class Config(
        val uuid: String,
        val host: String,
        val port: Int = 443,
        val sni: String = "speed.cloudflare.com",
        val wsPath: String = "/",
        val remark: String = "UMBRA-node",
    )

    fun randomUuid(): String = UUID.randomUUID().toString()

    fun isValidUuid(s: String): Boolean = try {
        UUID.fromString(s.trim())
        true
    } catch (_: Exception) {
        false
    }

    fun buildLink(cfg: Config): String {
        val host = IpText.forUrl(cfg.host.trim())
        val sni = cfg.sni.trim().ifEmpty { "speed.cloudflare.com" }
        val path = cfg.wsPath.trim().ifEmpty { "/" }.let { if (it.startsWith("/")) it else "/$it" }
        val remark = cfg.remark.trim().ifEmpty { "UMBRA-node" }
        val port = cfg.port.coerceIn(1, 65535)
        return buildString {
            append("vless://").append(cfg.uuid.trim()).append('@')
            append(host).append(':').append(port)
            append("?encryption=none&security=tls&sni=").append(enc(sni))
            append("&type=ws&host=").append(enc(sni))
            append("&path=").append(enc(path).replace("%2F", "/"))
            append('#').append(enc(remark))
        }
    }

    private fun enc(s: String): String = URLEncoder.encode(s, "UTF-8")
}
