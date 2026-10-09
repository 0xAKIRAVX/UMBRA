package com.umbra.scanner.engine

import android.content.Context
import kotlinx.coroutines.CoroutineExceptionHandler
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * v3.3.1 — the last-resort safety net that turns "UMBRA has stopped" into a
 * diagnosable, survivable event.
 *
 * Two layers:
 *
 *  1. [install] hooks the process-wide default uncaught-exception handler.
 *     A crash is journaled to disk BEFORE the system dialog / process death
 *     (we chain to the previous handler, so Android's own crash handling is
 *     unchanged) — the next launch shows the exact stack trace in
 *     SETTINGS → CRASH LOG, ready to copy into a GitHub issue.
 *
 *  2. [handler] produces [CoroutineExceptionHandler]s installed on every
 *     engine-side scope (scan engine, foreground service, NETSENSE, update
 *     center). An exception escaping any of those coroutines is journaled
 *     and logged — the PROCESS SURVIVES. Uncaught coroutine exceptions
 *     otherwise kill the process silently, which is exactly how a single
 *     bad endpoint used to murder the whole app.
 */
object CrashGuard {

    private const val JOURNAL_FILE = "crash_journal.txt"
    private const val MAX_ENTRIES = 12
    private const val MAX_FILE_BYTES = 192_000

    @Volatile private var appContext: Context? = null
    @Volatile private var appVersion: String = "?"
    @Volatile private var deviceLabel: String = "?"
    @Volatile private var installed = false

    /** Entry separator — each journal record is one block of lines. */
    private const val SEP = "────────────────────────────────────────"

    fun install(context: Context) {
        if (installed) return
        installed = true
        appContext = context.applicationContext
        appVersion = runCatching {
            context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "?"
        }.getOrDefault("?")
        deviceLabel = "${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL} · API ${android.os.Build.VERSION.SDK_INT}"
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            // journal FIRST — never let journaling failures break chaining
            runCatching { append("thread[${thread.name}]", throwable) }
            previous?.uncaughtException(thread, throwable)
        }
    }

    /**
     * Coroutine exception handler for engine-side scopes: journals the
     * failure, hands a one-line reason to [log] (scan log / logcat), and
     * keeps the process alive.
     */
    fun handler(tag: String, log: (String) -> Unit = {}): CoroutineExceptionHandler =
        CoroutineExceptionHandler { _, throwable ->
            if (throwable is kotlinx.coroutines.CancellationException) return@CoroutineExceptionHandler
            runCatching { append("coroutine[$tag]", throwable) }
            runCatching {
                log("internal error in $tag — ${throwable.javaClass.simpleName}: " +
                    (throwable.message ?: "") + " · recorded to crash log (settings)")
            }
            android.util.Log.e("Umbra", "uncaught in $tag", throwable)
        }

    /** Non-crash diagnostic events (e.g. deferred scans) may share the journal. */
    fun recordNote(tag: String, message: String) {
        runCatching { appendNote(tag, message) }
    }

    /**
     * v3.5.2: journal a throwable that was CAUGHT and handled by engine code
     * itself (full stack trace, same format as the CEH net) — the scope-level
     * CoroutineExceptionHandler never sees a handled exception, so the scan
     * controller journals it here before failing the session honestly.
     */
    fun record(tag: String, throwable: Throwable) {
        runCatching { append("coroutine[$tag]", throwable) }
    }

    /** All journaled crash entries, newest first. */
    fun recentCrashes(): List<String> {
        val f = journalFile() ?: return emptyList()
        return runCatching {
            if (!f.exists()) return emptyList()
            f.readText().split("[$SEP]\n")
                .map { it.trim() }
                .filter { it.isNotEmpty() }
        }.getOrDefault(emptyList())
    }

    fun clear() {
        runCatching { journalFile()?.delete() }
    }

    // ------------------------------------------------------------- internals

    private fun journalFile(): File? = appContext?.let { File(it.filesDir, JOURNAL_FILE) }

    private fun timestamp(): String =
        SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())

    private fun append(origin: String, throwable: Throwable) {
        val trace = java.io.StringWriter().also {
            throwable.printStackTrace(java.io.PrintWriter(it))
        }.toString().take(4000)
        val entry = buildString {
            append(timestamp()).append(" · v").append(appVersion)
            append('\n').append(deviceLabel).append(" · ").append(origin)
            append('\n').append(trace.trim())
        }
        write(entry)
    }

    private fun appendNote(tag: String, message: String) {
        write("${timestamp()} · v$appVersion\n$deviceLabel · note[$tag]\n$message")
    }

    private fun write(entry: String) {
        val f = journalFile() ?: return
        val existing = runCatching {
            if (f.exists()) f.readText() else ""
        }.getOrDefault("")
        var blocks = existing.split("[$SEP]\n").map { it.trim() }.filter { it.isNotEmpty() }
        blocks = (listOf(entry) + blocks).take(MAX_ENTRIES)
        var text = blocks.joinToString("\n$SEP\n\n")
        while (text.length > MAX_FILE_BYTES && blocks.size > 1) {
            blocks = blocks.dropLast(1)
            text = blocks.joinToString("\n$SEP\n\n")
        }
        f.parentFile?.mkdirs()
        f.writeText(text)
    }
}
