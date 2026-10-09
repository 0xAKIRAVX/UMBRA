package com.umbra.scanner.engine

import com.umbra.scanner.net.NetQuality
import com.umbra.scanner.net.NetworkProfile
import com.umbra.scanner.settings.UmbraSettings
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * NETSENSE center — app-scoped owner of the network-status measurement.
 *
 * The measurement survives tab switches (unlike a rememberCoroutineScope) and
 * refuses to run while a scan is in flight: a concurrent bandwidth probe would
 * poison both the measurement and the scan's own latency statistics.
 */
class NetStatusCenter(
    private val settings: UmbraSettings,
    private val isScanRunning: () -> Boolean = { false },
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val _measuring = MutableStateFlow(false)
    val measuring: StateFlow<Boolean> = _measuring.asStateFlow()

    private val _step = MutableStateFlow<String?>(null)
    val step: StateFlow<String?> = _step.asStateFlow()

    val profile: StateFlow<NetworkProfile?> get() = settings.networkProfile

    /**
     * Starts a measurement if none is running and no scan is active.
     * Returns false when it refused (busy) so the UI can explain why.
     */
    fun startMeasure(): Boolean {
        // v3.2 fix: the flag is set SYNCHRONOUSLY (was set inside the launched
        // coroutine — a check-then-act window let two rapid taps launch two
        // concurrent NetQuality.measure() runs that poisoned each other).
        if (!_measuring.compareAndSet(expect = false, update = true)) return false
        if (isScanRunning()) {
            _measuring.value = false
            return false
        }
        scope.launch {
            try {
                val p = NetQuality.measure { s -> _step.value = s }
                settings.setNetworkProfile(p)
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (_: Exception) {
                // keep the previous profile; the card simply stays on the old data
            } finally {
                _measuring.value = false
                _step.value = null
            }
        }
        return true
    }
}
