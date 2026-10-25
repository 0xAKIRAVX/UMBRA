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
        ladder: Boolean = false,
    ): TcpStats {
        val addr = InetAddress.getByAddress(ip)
        val lat = ArrayList<Double>(attempts.coerceAtMost(8))
        var failures = 0
        var lastError: String? = null
        repeat(attempts.coerceAtLeast(1)) { i ->
            // v3.12: the WG probe budget ladder applied to big TCP storms —
            // the first attempt gets the full budget (a congested-but-alive
            // candidate deserves it), every retry runs at half (floor 700 ms,
            // never above the base). On an Akamai scan the overwhelming
            // majority of the pool is dark space: retries exist for
            // flaky-but-alive candidates, which answer within the first
            // budget anyway. Off by default — existing callers are unchanged.
            val budget = if (ladder && i > 0) {
                maxOf(timeoutMs / 2, minOf(timeoutMs, 700))
            } else timeoutMs
            val socket = Socket()
            try {
                socket.tcpNoDelay = true
                val t0 = System.nanoTime()
                runInterruptible(Dispatchers.IO) {
                    socket.connect(InetSocketAddress(addr, port), budget)
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
            if (interAttemptDelayMs > 0 && i < attempts - 1) delay(interAttemptDelayMs)
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
