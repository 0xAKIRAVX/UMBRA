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
import com.umbra.scanner.core.ScanUi
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

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
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
                            notifySafe(buildFinalNotification(u))
                            ServiceCompat.stopForeground(this@ScanForegroundService, ServiceCompat.STOP_FOREGROUND_DETACH)
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
            null -> Triple("warming up engine", 0, 0)
            else -> Triple(
                "phase ${stats.phase.label.lowercase()} · tested ${stats.tested}/${stats.candidates} · alive ${stats.alive} · ${"%.1f".format(java.util.Locale.US, stats.ratePerSec)}/s",
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
        val title = if (s.cancelled) "UMBRA · Scan Stopped" else "UMBRA · Scan Complete"
        val text = buildString {
            append("alive ").append(s.alive)
            append(" · tested ").append(s.tested).append('/').append(s.candidates)
            append(" · ").append("${s.elapsedMs / 1000}s")
            if (best != null) {
                append("\nbest ").append(best.ip)
                best.latencyMs?.let { append(" · ").append("%.0f".format(java.util.Locale.US, it)).append(" ms") }
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

    private fun notifySafe(notification: Notification) {
        val granted = Build.VERSION.SDK_INT < 33 ||
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
        if (!granted) return
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        try {
            nm.notify(NOTIF_ID, notification)
        } catch (_: SecurityException) {
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
