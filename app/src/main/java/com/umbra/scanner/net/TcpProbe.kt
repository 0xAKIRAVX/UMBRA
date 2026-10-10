package com.umbra.scanner.net

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.runInterruptible
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import kotlin.math.sqrt

data class TcpStats(
    val latenciesMs: List<Double>,
    val failures: Int,
    val lastError: String?,
) {
    val success: Boolean get() = latenciesMs.isNotEmpty()
}

/**
 * Pure TCP handshake latency probing against a literal IP address.
 * - InetAddress built from raw bytes => the OS never resolves DNS for the candidate.
 * - runInterruptible => cooperative cancellation actually aborts blocked connects.
 */
object TcpProbe {

    suspend fun probe(
        ip: ByteArray,
        port: Int,
        attempts: Int,
        timeoutMs: Int,
        interAttemptDelayMs: Long = 25,
    ): TcpStats {
        val addr = InetAddress.getByAddress(ip)
        val lat = ArrayList<Double>(attempts.coerceAtMost(8))
        var failures = 0
        var lastError: String? = null
        repeat(attempts.coerceAtLeast(1)) {
            val socket = Socket()
            try {
                socket.tcpNoDelay = true
                val t0 = System.nanoTime()
                runInterruptible(Dispatchers.IO) {
                    socket.connect(InetSocketAddress(addr, port), timeoutMs)
                }
                val dtMs = (System.nanoTime() - t0) / 1e6
                lat.add(dtMs)
            } catch (e: kotlinx.coroutines.CancellationException) {
                runCatching { socket.close() }
                throw e
            } catch (e: Exception) {
                failures++
                lastError = describe(e)
            } finally {
                runCatching { socket.close() }
            }
            if (interAttemptDelayMs > 0 && it < attempts - 1) delay(interAttemptDelayMs)
        }
        return TcpStats(lat, failures, lastError)
    }

    fun jitterOf(latencies: List<Double>): Double? {
        if (latencies.size < 2) return null
        val mean = latencies.average()
        val variance = latencies.sumOf { (it - mean) * (it - mean) } / latencies.size
        return sqrt(variance)
    }

    private fun describe(e: Exception): String = when {
        e is java.net.SocketTimeoutException -> "TCP timeout"
        e.message.isNullOrBlank() -> e.javaClass.simpleName
        else -> e.javaClass.simpleName + ": " + (e.message ?: "")
    }
}
