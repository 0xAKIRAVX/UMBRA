package com.umbra.scanner.engine

import android.content.Context
import android.content.Intent
import android.os.SystemClock
import androidx.core.content.ContextCompat
import com.umbra.scanner.core.ScanMode
import com.umbra.scanner.core.ScanParams
import com.umbra.scanner.core.ScanPhase
import com.umbra.scanner.core.ScanResult
import com.umbra.scanner.core.ScanStats
import com.umbra.scanner.core.ScanSummary
import com.umbra.scanner.core.ScanUi
import com.umbra.scanner.core.SmartRanking
import com.umbra.scanner.settings.UmbraSettings
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicInteger

/**
 * App-scoped scan orchestrator. Owns the engine scope, live statistics, the result
 * store, and drives the foreground service lifecycle. Survives Activity rotation
 * and keeps the scan alive in the background while the service is in the foreground.
 *
 * v3.1: wired to [UmbraSettings] — final ranking uses the adaptive SmartRanking
 * weights (measured network profile when available) and the top verified results
 * per mode are persisted so the smart-pick board can recommend WARP + EDGE at once.
 */
class ScanController(private val settings: UmbraSettings? = null) {

    private val _ui = MutableStateFlow<ScanUi>(ScanUi.Idle)
    val ui: StateFlow<ScanUi> = _ui.asStateFlow()

    private val _stats = MutableStateFlow(ScanStats())
    val stats: StateFlow<ScanStats> = _stats.asStateFlow()

    private val _top = MutableStateFlow<List<ScanResult>>(emptyList())
    val top: StateFlow<List<ScanResult>> = _top.asStateFlow()

    private val _results = MutableStateFlow<List<ScanResult>>(emptyList())
    val results: StateFlow<List<ScanResult>> = _results.asStateFlow()

    private val _log = MutableStateFlow<List<String>>(emptyList())
    val log: StateFlow<List<String>> = _log.asStateFlow()

    init {
        // v3.1.1 fix: the top verified results of the last scan were persisted
        // precisely so they survive a restart — but the results tab showed
        // "NO SCAN DATA YET" on every fresh process until a new scan finished.
        // Hydrate the board from the persisted bucket of the last scan's mode.
        if (settings != null) {
            val saved = when (settings.lastScanMode()) {
                ScanMode.WARP -> settings.savedWarpResults.value
                else -> settings.savedEdgeResults.value
            }
            if (saved.isNotEmpty()) {
                _results.value = saved
                _top.value = saved.take(5)
            }
        }
    }

    /** IP pre-filled into the VLESS generator from a result row. */
    @Volatile
    var pendingVlessIp: String? = null

    private val lock = Any()
    private val logLock = Any()
    private val resultMap = LinkedHashMap<String, ScanResult>()

    private val tested = AtomicInteger(0)
    private val aliveCount = AtomicInteger(0)
    private val tlsOkCount = AtomicInteger(0)
    private val speedTestedCount = AtomicInteger(0)
    private val activeCount = AtomicInteger(0)

    @Volatile private var candidatesCount = 0
    @Volatile private var currentPhase = ScanPhase.IDLE
    @Volatile private var startedElapsed = 0L
    @Volatile private var params: ScanParams? = null
    @Volatile private var scanJob: Job? = null
    @Volatile private var tickerJob: Job? = null
    private var scope: CoroutineScope? = null

    val isRunning: Boolean get() = _ui.value is ScanUi.Running

    /**
     * v3.2: gate consulted before a scan may start — wired to the NETSENSE
     * center so a live network measurement and a scan never poison each
     * other's latency statistics (the check existed only in one direction
     * before: NETSENSE refused during scans, but scans did not refuse
     * during a measurement).
     */
    @Volatile
    var startGate: (() -> Boolean)? = null

    fun start(context: Context, newParams: ScanParams) {
        if (isRunning) return
        if (startGate?.invoke() == true) {
            appendLog("scan deferred — network measurement in progress · wait a few seconds")
            return
        }
        params = newParams
        resetState()
        startedElapsed = 0L
        _ui.value = ScanUi.Running(newParams, System.currentTimeMillis())
        val intent = Intent(context, ScanForegroundService::class.java)
            .setAction(ScanForegroundService.ACTION_START)
        ContextCompat.startForegroundService(context, intent)
    }

    /** Invoked by the service once it is in the foreground. */
    fun launchScan() {
        if (scanJob?.isActive == true) return
        val p = params ?: return
        startedElapsed = SystemClock.elapsedRealtime()
        val engineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        scope = engineScope
        appendLog(
            "scan session started · mode ${p.mode.name}" +
                if (p.mode == ScanMode.WARP) {
                    " · wireguard validation · ${p.warpAttempts} tries × ${p.tcpTimeoutMs} ms" +
                        if (p.udpNoise) " · udp noise ×${p.noiseCount}" else ""
                } else {
                    " · ${p.tcpAttempts} attempts × ${p.tcpTimeoutMs} ms"
                }
        )

        tickerJob = engineScope.launch {
            while (isActive) {
                delay(350)
                publishStats()
            }
        }
        scanJob = engineScope.launch {
            try {
                ScanEngine().run(p, sink)
                finalize(cancelled = false)
            } catch (e: kotlinx.coroutines.CancellationException) {
                finalize(cancelled = true)
            } catch (e: Exception) {
                appendLog("engine failure: ${e.message ?: e.javaClass.simpleName}")
                finalize(cancelled = false)
            }
        }
    }

    fun stopScan() {
        appendLog("stop requested — tearing down sockets")
        scanJob?.cancel()
    }

    /** Return to idle config screen (results stay available in [results]). */
    fun resetUi() {
        if (!isRunning) _ui.value = ScanUi.Idle
    }

    /**
     * Test/screenshot hook — injects UI-facing state without running the
     * engine or the foreground service. Never called from production code.
     */
    fun debugInjectState(
        uiState: ScanUi = _ui.value,
        statsValue: ScanStats = _stats.value,
        topValue: List<ScanResult> = _top.value,
        resultsValue: List<ScanResult> = _results.value,
        logValue: List<String> = _log.value,
    ) {
        _ui.value = uiState
        _stats.value = statsValue
        _top.value = topValue
        _results.value = resultsValue
        _log.value = logValue
    }

    /** Wipe the current result board — memory AND the persisted buckets. */
    fun clearResults() {
        if (isRunning) return
        synchronized(lock) { resultMap.clear() }
        _results.value = emptyList()
        _top.value = emptyList()
        // v3.1.1: also wipe the persisted smart-pick buckets, otherwise the
        // board resurrected on next launch from storage
        settings?.clearSavedResults()
        _ui.value = ScanUi.Idle
    }

    private fun resetState() {
        synchronized(lock) { resultMap.clear() }
        tested.set(0); aliveCount.set(0); tlsOkCount.set(0)
        speedTestedCount.set(0); activeCount.set(0)
        candidatesCount = 0
        currentPhase = ScanPhase.IDLE
        _results.value = emptyList()
        _top.value = emptyList()
        _log.value = emptyList()
        _stats.value = ScanStats()
    }

    private val sink = object : ScanSink {
        override fun onPhase(phase: ScanPhase) {
            currentPhase = phase
        }

        override fun onGenerated(count: Int) {
            candidatesCount = count
        }

        override fun onResult(result: ScanResult) {
            var newTested = false
            var aliveDelta = 0
            var tlsDelta = 0
            var speedDelta = 0
            synchronized(lock) {
                val old = resultMap[result.id]
                val merged = old?.merge(result) ?: result
                resultMap[result.id] = merged
                if (old == null) newTested = true
                val wasAlive = old?.alive == true
                if (merged.alive && !wasAlive) aliveDelta = 1
                if (merged.tlsSuccess && old?.tlsSuccess != true) tlsDelta = 1
                if (merged.speedMbps != null && old?.speedMbps == null) speedDelta = 1
            }
            if (newTested) tested.incrementAndGet()
            if (aliveDelta != 0) aliveCount.addAndGet(aliveDelta)
            if (tlsDelta != 0) tlsOkCount.addAndGet(tlsDelta)
            if (speedDelta != 0) speedTestedCount.addAndGet(speedDelta)
        }

        override fun onActive(delta: Int) {
            activeCount.addAndGet(delta)
        }

        override fun onLog(line: String) {
            appendLog(line)
        }

        override fun snapshot(): List<ScanResult> = synchronized(lock) { ArrayList(resultMap.values) }
    }

    private fun appendLog(line: String) {
        // v3 fix: sink callbacks land on worker threads while start()/stop()
        // come from main — the old read-modify-write raced and dropped lines.
        synchronized(logLock) {
            _log.value = listOf(line) + _log.value.take(29)
        }
    }

    private fun publishStats() {
        val testedN = tested.get()
        val elapsed = if (startedElapsed == 0L) 0L else SystemClock.elapsedRealtime() - startedElapsed
        val rate = if (elapsed > 500) testedN * 1000.0 / elapsed else 0.0
        val eta = when {
            candidatesCount <= 0 || rate < 0.5 -> null
            else -> (candidatesCount - testedN).toDouble() / rate
        }
        _stats.value = ScanStats(
            phase = currentPhase,
            candidates = candidatesCount,
            tested = testedN,
            alive = aliveCount.get(),
            tlsOk = tlsOkCount.get(),
            speedTested = speedTestedCount.get(),
            active = activeCount.get().coerceAtLeast(0),
            elapsedMs = elapsed,
            ratePerSec = rate,
            etaSec = eta,
        )
        // live top-5 board — only VERIFIED phases feed it (v3.1 fix: during the
        // EDGE tcp storm "alive" merely means tcp-connect, which DPI middleboxes
        // fake-accept; showing those as "top endpoints" was misleading)
        val scanMode = params?.mode
        if (currentPhase == ScanPhase.WG ||
            (scanMode != ScanMode.WARP &&
                (currentPhase == ScanPhase.PROBE || currentPhase == ScanPhase.RANKING))
        ) {
            val snap = synchronized(lock) { resultMap.values.filter { it.alive } }
            if (snap.isNotEmpty()) {
                _top.value = snap.sortedBy { it.latencyMs ?: Double.MAX_VALUE }.take(5)
            }
        }
    }

    private fun finalize(cancelled: Boolean) {
        tickerJob?.cancel()
        scope?.cancel()
        scanJob = null
        tickerJob = null
        // v3.1: adaptive final ranking — smart weights from the measured profile
        val profile = settings?.networkProfile?.value
        val finalAlive = SmartRanking.sort(
            synchronized(lock) { ArrayList(resultMap.values) }.filter { it.alive },
            profile,
        )
        _results.value = finalAlive
        _top.value = finalAlive.take(5)
        // persist the verified top results of this mode for the smart-pick board
        val mode = params?.mode
        if (settings != null && mode != null && finalAlive.isNotEmpty()) {
            settings.saveScanResults(mode, finalAlive)
        }
        if (profile != null) {
            appendLog("net profile · ${com.umbra.scanner.net.NetQuality.describe(profile)}")
        }
        publishStats()
        val elapsed = if (startedElapsed == 0L) 0L else SystemClock.elapsedRealtime() - startedElapsed
        _ui.value = ScanUi.Done(
            ScanSummary(
                cancelled = cancelled,
                candidates = candidatesCount,
                tested = tested.get(),
                alive = finalAlive.size,
                best = finalAlive.firstOrNull(),
                elapsedMs = elapsed,
                params = params ?: ScanParams(),
                // v3.3: zero-result scans now carry the engine's own last word
                // (registration blocked, probe budget capped, engine failure…)
                // into the Done panel — silence is the worst error message.
                error = if (finalAlive.isEmpty() && !cancelled) {
                    _log.value.firstOrNull() ?: "no verified endpoints"
                } else null,
            )
        )
    }
}
