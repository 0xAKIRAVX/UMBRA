package com.umbra.scanner.engine

import android.content.Context
import com.umbra.scanner.net.UpdateChecker
import com.umbra.scanner.settings.UmbraSettings
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Owns the update-channel state shown across the app: an animated dialog on
 * launch when a new GitHub release is detected, and a status row in settings
 * for manual checks. All network work happens on IO; failures degrade to a
 * quiet "unreachable" state and never interrupt scanning.
 */
class UpdateCenter(
    context: Context,
    private val settings: UmbraSettings,
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
) {

    sealed interface State {
        data object Idle : State
        data object Checking : State
        data class Available(
            val release: UpdateChecker.Release,
            val currentVersion: String,
        ) : State

        data class UpToDate(val currentVersion: String, val latestTag: String) : State
        data class Unreachable(val reason: String) : State
    }

    private val _state = MutableStateFlow<State>(State.Idle)
    val state: StateFlow<State> = _state.asStateFlow()

    val currentVersion: String by lazy {
        runCatching {
            val pm = context.packageManager
            pm.getPackageInfo(context.packageName, 0).versionName ?: "0.0.0"
        }.getOrDefault("0.0.0")
    }

    /** True when the available release has not been dismissed by the user. */
    fun shouldAnnounce(): Boolean {
        val s = _state.value
        return s is State.Available && s.release.tag != settings.dismissedUpdateTag.value
    }

    fun dismiss() {
        val s = _state.value
        if (s is State.Available) settings.setDismissedUpdateTag(s.release.tag)
    }

    /**
     * Silent background check used on app launch: respects the AUTO CHECK
     * toggle, throttles to one attempt per 24 h and skips while a check is
     * already in flight or an announcement is pending.
     */
    fun maybeAutoCheck() {
        if (!settings.autoUpdate.value) return
        if (shouldAnnounce()) return
        if (_state.value is State.Checking) return
        val now = System.currentTimeMillis()
        if (now - settings.lastUpdateCheck.value < AUTO_CHECK_INTERVAL_MS) return
        checkNow()
    }

    /** Immediate check — used by the settings row and ignores throttling. */
    fun checkNow() {
        if (_state.value is State.Checking) return
        settings.setLastUpdateCheck(System.currentTimeMillis())
        scope.launch {
            _state.value = State.Checking
            val release = UpdateChecker.fetchLatest()
            _state.value = when {
                release == null ->
                    State.Unreachable("github unreachable — check your connection")

                UpdateChecker.isNewer(currentVersion, release.tag) ->
                    State.Available(release, currentVersion)

                else -> State.UpToDate(currentVersion, release.tag)
            }
        }
    }

    companion object {
        private const val AUTO_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000L
    }
}
