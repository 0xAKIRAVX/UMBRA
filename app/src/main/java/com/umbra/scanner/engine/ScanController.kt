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
import com.umbra.scanner.engine.CrashGuard
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

    companion object {
        /** v3.9: sliding window for the live rate stat. */
        internal const val RATE_WINDOW_MS = 15_000L

        /** v3.9: hard cap — trimmed by time anyway, this bounds a pathological
         *  burst between two stats ticks (350ms ticker). */
        internal const val WINDOW_HARD_CAP = 8_192
    }

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

    /**
     * v3.3.1: transient, user-facing notice (currently: why a scan start was
     * refused). The Idle screen renders it under the start button so a
     * deferred scan is SEEN instead of silently swallowed into the log.
     */
    private val _notice = MutableStateFlow<String?>(null)
    val notice: StateFlow<String?> = _notice.asStateFlow()

    init {
        // v3.1.1 fix: the top verified results of the last scan were persisted
        // precisely so they survive a restart — but the results tab showed
        // "NO SCAN DATA YET" on every fresh process until a new scan finished.
        // Hydrate the board from the persisted bucket of the last scan's mode.
        // v3.8: ENDPOINT rows live in the warp bucket (they ARE warp
        // endpoints); EDGE/CUSTOM in the edge bucket.
        if (settings != null) {
            val saved = when (settings.lastScanMode()) {
                ScanMode.ENDPOINT -> settings.savedWarpResults.value
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

    /**
     * v3.9 (the frozen-stats-card fix): timestamps (elapsedRealtime) of every
     * newly-tested probe, kept inside a 15 s sliding window. The OLD rate
     * (tested × 1000 / totalElapsed) was cumulative-since-start: during the
     * WG storm's silent lead-in it read 0.0/s, and late in a long scan it
     * averaged the whole history into meaningless slowness — the card looked
     * dead in exactly both regimes the user screenshotted. The window rate
     * spikes the moment results land and decays honestly when they stop.
     */
    private val testedWindow = ArrayDeque<Long>()
    private val windowLock = Any()

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

    /**
     * Test seam — production always runs a fresh [ScanEngine]; tests replace
     * this to inject failures (e.g. an Error) into the exact scanJob path.
     * Never touched from production code.
     */
    internal var engineRunner: suspend (ScanParams, ScanSink) -> Unit =
        { p, s -> ScanEngine().run(p, s) }

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
            val reason = "scan deferred — network measurement in progress · wait a few seconds"
            appendLog(reason)
            _notice.value = reason
            return
        }
        params = newParams
        resetState()
        _notice.value = null
        startedElapsed = 0L
        _ui.value = ScanUi.Running(newParams, System.currentTimeMillis())
        val intent = Intent(context, ScanForegroundService::class.java)
            .setAction(ScanForegroundService.ACTION_START)
        // v3.3.1: this runs on the MAIN thread at the exact moment the user
        // presses INITIATE DEEP SCAN — the ONE spot an OEM throw (FGS start
        // restrictions, process state races) could still kill the app cold.
        // Any failure reverts to Idle with an honest message instead.
        try {
            ContextCompat.startForegroundService(context, intent)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            _ui.value = ScanUi.Idle
            val reason = "could not start scan service: ${e.javaClass.simpleName}"
            appendLog(reason)
            _notice.value = reason
            CrashGuard.recordNote("scan-start", reason)
        }
    }

    /** Invoked by the service once it is in the foreground. */
    fun launchScan() {
        if (scanJob?.isActive == true) return
        val p = params ?: return
        startedElapsed = SystemClock.elapsedRealtime()
        // v3.3.1: the engine scope carries a crash-net handler — anything the
        // scanJob's own catch misses (an Error, a bug in the ticker, a
        // collector hiccup) is journaled and logged, NEVER fatal to the app.
        val engineScope = CoroutineScope(
            SupervisorJob() + Dispatchers.Default +
                CrashGuard.handler("scan-engine") { line -> appendLog(line) }
        )
        scope = engineScope
        appendLog(
            "scan session started · mode ${p.mode.name}" +
                if (p.mode == ScanMode.ENDPOINT) {
                    " · ${p.endpointsCount} random ip:port endpoints + ${com.umbra.scanner.core.Presets.WARP_SEED_ENDPOINTS.size} seeds" +
                        " · wireguard handshake ×${p.warpAttempts} · " +
                        (if (p.port > 0) "port ${p.port}" else "random ports") +
                        " · ${p.family.label.lowercase()}" +
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
                engineRunner(p, sink)
                finalize(cancelled = false)
            } catch (e: kotlinx.coroutines.CancellationException) {
                finalize(cancelled = true)
            } catch (e: Throwable) {
                // v3.5.2 (THE zombie-scan bug): Errors are NOT Exceptions —
                // NoClassDefFoundError, StackOverflowError etc. escaped this
                // catch, were journaled by the scope's CEH… and finalize()
                // NEVER ran. The session stayed Running forever (progress
                // stuck at 0/n, elapsed ticking, ongoing notification, STOP
                // no-op because it cancelled an already-dead job — only a
                // force-kill ended it; the exact state in the user's crash
                // screenshot). Errors now fail the scan honestly: journaled
                // WITH stack trace, honest log line, Done panel with reason.
                CrashGuard.record("scan-engine", e)
                appendLog(
                    "engine failure — ${e.javaClass.simpleName}" +
                        (e.message?.let { ": $it" } ?: "") + " · recorded to crash log (settings)"
                )
                runCatching { finalize(cancelled = false) }
            }
        }
    }

    fun stopScan() {
        val job = scanJob
        // v3.5.2 (defense-in-depth for the zombie-scan bug): pressing STOP on
        // a session whose engine already died (a crash path finalize missed)
        // must ALWAYS end the session — cancelling an already-completed job
        // is a silent no-op, which is exactly what a stuck Running screen
        // used to show. Fail the session honestly instead.
        if (job == null || !job.isActive) {
            if (isRunning) {
                appendLog("stop requested — engine already dead · closing session")
                runCatching { finalize(cancelled = true) }
            }
            return
        }
        appendLog("stop requested — tearing down sockets")
        job.cancel()
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
        paramsValue: ScanParams? = null,
    ) {
        _ui.value = uiState
        _stats.value = statsValue
        _top.value = topValue
        _results.value = resultsValue
        _log.value = logValue
        if (paramsValue != null) params = paramsValue
    }

    /**
     * Test hook — feeds one probe result through the REAL statistics path
     * (the same sink the engine writes to), publishes the stats snapshot
     * exactly like the live ticker would, and returns how many entries the
     * engine's internal result map now holds (dead-dropped probes excluded).
     * Never called from production code.
     */
    fun debugFeed(result: ScanResult): Int {
        sink.onResult(result)
        publishStats()
        return synchronized(lock) { resultMap.size }
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
        synchronized(windowLock) { testedWindow.clear() }
        candidatesCount = 0
        currentPhase = ScanPhase.IDLE
        _results.value = emptyList()
        _top.value = emptyList()
        _log.value = emptyList()
        _notice.value = null
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
                if (old == null) {
                    newTested = true
                    // v3.4 fix (OOM): a FIRST result that already proves the
                    // endpoint dead (no successful attempt, no handshake) is
                    // counted for progress but never STORED — a capped mega-sweep
                    // must not build a 120k-entry map of dead rows nothing will
                    // ever read: the TLS phase only touches tcp-alive entries,
                    // the speed phase only alive ones, and the final board only
                    // shows alive ones. Dead probes are also never re-merged:
                    // each (ip, port) pair is probed exactly once per scan.
                    if (result.successfulAttempts > 0 || result.wgHandshakes > 0) {
                        resultMap[result.id] = result
                        if (result.alive) aliveDelta = 1
                        if (result.tlsSuccess) tlsDelta = 1
                        if (result.speedMbps != null) speedDelta = 1
                    }
                } else {
                    val merged = old.merge(result)
                    resultMap[result.id] = merged
                    val wasAlive = old.alive
                    if (merged.alive && !wasAlive) aliveDelta = 1
                    if (merged.tlsSuccess && !old.tlsSuccess) tlsDelta = 1
                    if (merged.speedMbps != null && old.speedMbps == null) speedDelta = 1
                }
            }
            if (newTested) {
                tested.incrementAndGet()
                synchronized(windowLock) {
                    testedWindow.addLast(SystemClock.elapsedRealtime())
                }
            }
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
        val rate = slidingRatePerSec(testedWindowSnapshot(), SystemClock.elapsedRealtime(), elapsed)
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
        // v3.8: ENDPOINT probes run in the WG phase — a row only becomes alive
        // after a real handshake answered, so the board streams live and every
        // shown endpoint is already usable.
        val scanMode = params?.mode
        if (currentPhase == ScanPhase.WG ||
            (scanMode != ScanMode.ENDPOINT &&
                (currentPhase == ScanPhase.PROBE || currentPhase == ScanPhase.RANKING))
        ) {
            val snap = synchronized(lock) { resultMap.values.filter { it.alive } }
            if (snap.isNotEmpty()) {
                _top.value = snap.sortedBy { it.latencyMs ?: Double.MAX_VALUE }.take(5)
            }
        }
    }

    /** Copy of the tested-event window under its lock (never leaks the
     * mutable deque to the rate computation). Also trims entries older than
     * the 15 s window and hard-caps the size so a 120k mega-sweep's bursts
     * cannot grow the deque unboundedly between stats ticks. */
    private fun testedWindowSnapshot(): List<Long> = synchronized(windowLock) {
        val now = SystemClock.elapsedRealtime()
        while (testedWindow.isNotEmpty() && now - testedWindow.first() > RATE_WINDOW_MS) {
            testedWindow.removeFirst()
        }
        while (testedWindow.size > WINDOW_HARD_CAP) testedWindow.removeFirst()
        ArrayList(testedWindow)
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

/**
 * v3.9 (the frozen-stats-card fix, pure core): throughput over a 15 s sliding
 * window of tested-event timestamps.
 *
 *  - elapsed < window → the window IS the whole scan so far (identical to the
 *    honest cumulative rate of the old code — early numbers stay truthful)
 *  - elapsed ≥ window → only events inside the window count: the rate spikes
 *    the moment results land (the old cumulative rate stayed ~0 through the
 *    WG storm's silent lead-in — the 0.0/s screen) and decays to 0 honestly
 *    when the pipeline stalls instead of averaging history into fake liveness.
 * Pure function — unit-tested directly.
 */
internal fun slidingRatePerSec(
    events: List<Long>,
    nowMs: Long,
    elapsedMs: Long,
): Double {
    if (events.isEmpty()) return 0.0
    val windowMs = when {
        elapsedMs >= ScanController.RATE_WINDOW_MS -> ScanController.RATE_WINDOW_MS
        elapsedMs >= 1_000 -> elapsedMs
        else -> 1_000L
    }
    val cutoff = nowMs - windowMs
    val counted = events.count { it >= cutoff }
    return counted * 1000.0 / windowMs
}
