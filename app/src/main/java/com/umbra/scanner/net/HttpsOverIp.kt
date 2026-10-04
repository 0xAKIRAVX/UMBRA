package com.umbra.scanner.net

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Exact-IP HTTPS: TCP connect goes to the candidate IP itself, while the TLS SNI
 * and HTTP Host header point at speed.cloudflare.com / engage.cloudflareclient.com.
 * The certificate is fully validated (default trust store + hostname verification),
 * so a wrong-endpoint IP can never pass. DNS is never used for the candidate.
 */
object ExactIpHttps {

    data class TlsProbeResult(
        val ok: Boolean,
        val handshakeMs: Double? = null,
        val error: String? = null,
    )

    data class DownloadResult(
        val bytes: Long,
        val durationMs: Long,
        val httpStatus: Int? = null,
        val tlsOk: Boolean = false,
        val handshakeMs: Double? = null,
        val error: String? = null,
    )

    private const val UA = "UMBRA-Scanner/2.0 (Android)"

    fun tlsProbe(
        ip: ByteArray,
        port: Int,
        sni: String,
        connectTimeoutMs: Int,
        readTimeoutMs: Int,
    ): TlsProbeResult {
        openTls(ip, port, sni, connectTimeoutMs, readTimeoutMs).use { session ->
            return when (session) {
                is TlsSession.Ok -> TlsProbeResult(ok = true, handshakeMs = session.handshakeMs)
                is TlsSession.Fail -> TlsProbeResult(ok = false, error = session.error)
            }
        }
    }

    fun download(
        ip: ByteArray,
        port: Int,
        sni: String,
        bytes: Long,
        connectTimeoutMs: Int,
        readTimeoutMs: Int,
        maxDurationMs: Long,
    ): DownloadResult {
        when (val session = openTls(ip, port, sni, connectTimeoutMs, readTimeoutMs)) {
            is TlsSession.Fail -> return DownloadResult(0, 0, null, false, null, session.error)
            is TlsSession.Ok -> {
                val ssl = session.socket
                try {
                    val out = BufferedOutputStream(ssl.outputStream, 8192)
                    val req = buildString {
                        append("GET /__down?bytes=").append(bytes)
                        append(" HTTP/1.1\r\nHost: ").append(sni)
                        append("\r\nUser-Agent: ").append(UA)
                        append("\r\nAccept: */*\r\nConnection: close\r\n\r\n")
                    }
                    out.write(req.toByteArray(Charsets.ISO_8859_1))
                    out.flush()

                    val input = BufferedInputStream(ssl.inputStream, 64 * 1024)
                    val status = readStatusLine(input) ?: return DownloadResult(
                        0, 0, null, true, session.handshakeMs, "no HTTP response"
                    )
                    if (status != 200) return DownloadResult(
                        0, 0, status, true, session.handshakeMs, "HTTP status: $status"
                    )
                    skipHeaders(input)

                    val buf = ByteArray(64 * 1024)
                    var count = 0L
                    val t0 = System.nanoTime()
                    val deadline = t0 + maxDurationMs * 1_000_000L
                    while (count < bytes) {
                        if (System.nanoTime() >= deadline) break
                        val n = input.read(buf)
                        if (n < 0) break
                        count += n
                    }
                    val durMs = (System.nanoTime() - t0) / 1_000_000L
                    return if (count <= 0L) {
                        DownloadResult(0, 0, 200, true, session.handshakeMs, "empty body")
                    } else {
                        DownloadResult(count, durMs.coerceAtLeast(1L), 200, true, session.handshakeMs, null)
                    }
                } catch (e: Exception) {
                    return DownloadResult(0, 0, null, true, session.handshakeMs, describe(e))
                } finally {
                    runCatching { ssl.close() }
                }
            }
        }
    }

    private sealed interface TlsSession : AutoCloseable {
        data class Ok(val socket: SSLSocket, val handshakeMs: Double) : TlsSession {
            override fun close() {
                runCatching { socket.close() }
            }
        }

        data class Fail(val error: String) : TlsSession {
            override fun close() {}
        }
    }

    private fun openTls(
        ip: ByteArray,
        port: Int,
        sni: String,
        connectTimeoutMs: Int,
        readTimeoutMs: Int,
    ): TlsSession {
        val plain = Socket()
        try {
            val addr = InetAddress.getByAddress(ip)
            plain.tcpNoDelay = true
            plain.connect(InetSocketAddress(addr, port), connectTimeoutMs)
            plain.soTimeout = readTimeoutMs
            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            val ssl = factory.createSocket(plain, sni, port, true) as SSLSocket
            val params = (ssl.sslParameters ?: SSLParameters()).apply {
                serverNames = listOf(SNIHostName(sni))
            }
            ssl.sslParameters = params
            val t0 = System.nanoTime()
            ssl.startHandshake()
            val handshakeMs = (System.nanoTime() - t0) / 1e6
            val session = ssl.session
            val verified = try {
                HttpsURLConnection.getDefaultHostnameVerifier().verify(sni, session)
            } catch (e: Exception) {
                false
            }
            return if (verified) {
                TlsSession.Ok(ssl, handshakeMs)
            } else {
                runCatching { ssl.close() }
                TlsSession.Fail("TLS: certificate does not match $sni")
            }
        } catch (e: Exception) {
            runCatching { plain.close() }
            return TlsSession.Fail(describe(e))
        }
    }

    private fun readStatusLine(input: InputStream): Int? {
        val line = readLineCrude(input) ?: return null
        // "HTTP/1.1 200 OK"
        val parts = line.trim().split(" ")
        if (parts.size < 2) return null
        return parts[1].toIntOrNull() ?: parts.getOrNull(2)?.toIntOrNull()
    }

    private fun skipHeaders(input: InputStream) {
        var guard = 0
        while (guard++ < 100) {
            val line = readLineCrude(input) ?: return
            if (line.isEmpty()) return
        }
    }

    private fun readLineCrude(input: InputStream): String? {
        val sb = StringBuilder(64)
        while (true) {
            val c = input.read()
            if (c < 0) return if (sb.isEmpty()) null else sb.toString()
            if (c == '\n'.code) break
            if (c != '\r'.code) sb.append(c.toChar())
            if (sb.length > 8192) return sb.toString()
        }
        return sb.toString()
    }

    private fun describe(e: Exception): String = when {
        e is java.net.SocketTimeoutException -> "timeout"
        e is javax.net.ssl.SSLException && e.message?.contains("handshake") == true ->
            "TLS handshake failed"
        e.message.isNullOrBlank() -> e.javaClass.simpleName
        else -> e.javaClass.simpleName + ": " + (e.message ?: "")
    }
}
