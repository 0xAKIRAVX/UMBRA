package com.umbra.scanner.engine

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import androidx.compose.ui.graphics.toArgb
import com.umbra.scanner.MainActivity
import com.umbra.scanner.R
import com.umbra.scanner.UmbraApp
import com.umbra.scanner.core.IpText
import com.umbra.scanner.core.ScanUi
import com.umbra.scanner.i18n.AppLanguage
import com.umbra.scanner.i18n.EnglishStrings
import com.umbra.scanner.i18n.NotificationStrings
import com.umbra.scanner.ui.theme.ACCENTS
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.sample
import kotlinx.coroutines.launch

/**
 * Foreground (dataSync) service hosting the scan while UMBRA is off-screen.
 * The notification carries live progress and a STOP action; stopping from the
 * notification cancels the engine cooperatively and preserves partial results.
 */
class ScanForegroundService : Service() {

    companion object {
        const val ACTION_START = "com.umbra.scanner.action.START"
        const val ACTION_STOP = "com.umbra.scanner.action.STOP"
        private const val CHANNEL_ID = "umbra_scan"
        private const val NOTIF_ID = 4711
    }

    private lateinit var scope: CoroutineScope
    private val controller: ScanController by lazy { (application as UmbraApp).controller }

    /** v4.1.1: the notification body follows the app language — it used to be
     *  hardcoded English while the title / action / channel were localized,
     *  so Persian users saw a half-English notification in the shade. */
    private val strings: NotificationStrings
        get() = AppLanguage.stringsFor((application as UmbraApp).settings.language.value).notif

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        // v3.3.1: crash-net handler — a failure inside the notification/state
        // collector coroutine is journaled instead of killing the process
        // (uncaught coroutine exceptions are silent process-killers).
        scope = CoroutineScope(
            SupervisorJob() + Dispatchers.Default +
                CrashGuard.handler("scan-service")
        )
        createChannel()
        observeState()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> controller.stopScan()
            else -> {
                startForegroundCompat(buildProgressNotification(null))
                controller.launchScan()
            }
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun startForegroundCompat(notification: Notification) {
        val type = if (Build.VERSION.SDK_INT >= 29) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
        } else 0
        ServiceCompat.startForeground(this, NOTIF_ID, notification, type)
    }

    private fun observeState() {
        scope.launch {
            combine(controller.ui, controller.stats) { u, s -> u to s }
                .sample(1000)
                .collect { (u, s) ->
                    when (u) {
                        is ScanUi.Running -> notifySafe(buildProgressNotification(s))
                        is ScanUi.Done -> {
                            // v3.2 fix: when POST_NOTIFICATIONS is denied the final
                            // notification cannot be posted — DETACH would leave the
                            // ONGOING progress notification stuck in the shade until
                            // process death. Remove it instead in that case.
                            val posted = notifySafe(buildFinalNotification(u))
                            ServiceCompat.stopForeground(
                                this@ScanForegroundService,
                                if (posted) ServiceCompat.STOP_FOREGROUND_DETACH
                                else ServiceCompat.STOP_FOREGROUND_REMOVE
                            )
                            stopSelf()
                        }
                        ScanUi.Idle -> stopSelf()
                    }
                }
        }
    }

    private fun buildProgressNotification(stats: com.umbra.scanner.core.ScanStats?): Notification {
        val stopIntent = PendingIntent.getService(
            this, 1,
            Intent(this, ScanForegroundService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val contentIntent = PendingIntent.getActivity(
            this, 2,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val (text, candidates, tested) = when (stats) {
            null -> Triple(strings.warming, 0, 0)
            else -> Triple(
                // v4.1.1: localized (phase labels stay Latin technical tokens,
                // exactly like the in-app phase bar; Locale hardening kept)
                notificationProgressText(stats, strings),
                stats.candidates,
                stats.tested,
            )
        }
        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_umbra)
            .setContentTitle(getString(R.string.notif_title))
            .setContentText(text)
            .setProgress(candidates.coerceAtLeast(1), tested, candidates <= 0)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setUsesChronometer(true)
            .setWhen(controller.ui.value.let { if (it is ScanUi.Running) it.startedAt else System.currentTimeMillis() })
            .setContentIntent(contentIntent)
            .addAction(0, getString(R.string.notif_action_stop), stopIntent)
            .setCategory(NotificationCompat.CATEGORY_PROGRESS)
            .setColor(notificationAccent())
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
        return builder.build()
    }

    /** v3 fix: the notification tint now follows the palette chosen in settings. */
    private fun notificationAccent(): Int =
        ACCENTS[(application as UmbraApp).settings.accent.value.coerceIn(0, ACCENTS.size - 1)]
            .primary.toArgb()

    private fun buildFinalNotification(done: ScanUi.Done): Notification {
        val s = done.summary
        val best = s.best
        // v4.1.1: localized titles/body (was hardcoded English) — the channel
        // name, notification title and STOP action were already localized
        // through res/values-fa; the CONTENT lines now follow the app
        // language too.
        val title = if (s.cancelled) strings.stoppedTitle else strings.doneTitle
        val text = buildString {
            append(strings.doneBody(s.alive, s.tested, s.candidates, "${s.elapsedMs / 1000}s"))
            if (best != null) {
                // v4.1.1: the FULL endpoint ([ip]:port, IPv6 bracketed) — with
                // random ports (the ENDPOINT default) a bare IP identifies
                // nothing usable. Every other surface (live board, Done panel,
                // smart picks) was fixed in v3.8.1/v3.11; the notification was
                // the last one showing the bare IP.
                append('\n').append(strings.best(
                    "${IpText.forUrl(best.ip)}:${best.port}",
                    best.latencyMs?.let { "%.0f ms".format(java.util.Locale.US, it) } ?: "—",
                ))
            }
        }
        val contentIntent = PendingIntent.getActivity(
            this, 2,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_umbra)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setAutoCancel(true)
            .setContentIntent(contentIntent)
            .setColor(notificationAccent())
            .build()
    }

    private fun notifySafe(notification: Notification): Boolean {
        val granted = Build.VERSION.SDK_INT < 33 ||
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
        if (!granted) return false
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        return try {
            nm.notify(NOTIF_ID, notification)
            true
        } catch (_: SecurityException) {
            false
        }
    }

    private fun createChannel() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(R.string.channel_desc)
            setShowBadge(false)
        }
        nm.createNotificationChannel(channel)
    }
}

/**
 * v4.0.2 (locale hardening, extracted pure): the foreground notification's
 * progress line. The phase label used to pass through default-locale
 * lowercase() — on a Turkish device "IDENTITY" rendered "ıdentıty" (dotless
 * ı) inside the status-bar/lock-screen text, the exact bug class the v4.0.1
 * sessionStartLine fix pinned (Locale.ROOT keeps enum labels ASCII).
 * Pure function — unit-tested against hostile default locales (tr-TR, fa-IR).
 *
 * v4.1.1: [s] localizes the surrounding words (same leak class as the v3.11
 * toast fixes — the notification's title/action/channel were localized but
 * its content lines were hardcoded English). Defaults to English so the
 * v4.0.2 locale-hardening tests keep pinning the ASCII contract unchanged.
 */
internal fun notificationProgressText(
    stats: com.umbra.scanner.core.ScanStats?,
    s: NotificationStrings = EnglishStrings.notif,
): String = when (stats) {
    null -> s.warming
    else -> s.progress(
        stats.phase.label.lowercase(java.util.Locale.ROOT),
        stats.tested, stats.candidates, stats.alive,
        "%.1f".format(java.util.Locale.US, stats.ratePerSec),
    )
}
