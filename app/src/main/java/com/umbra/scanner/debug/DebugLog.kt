package com.umbra.scanner.debug

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * v3.12 — the app-wide DEBUG JOURNAL: the backbone of the Diagnostics tab.
 *
 * Every subsystem already had its own visibility story — the scan log
 * (30-line UI ring), the crash journal (disk), NETSENSE steps — but each
 * lived in its own silo and none could answer "what exactly happened on
 * THIS device, in order, right now?" when a scan came back 0 ALIVE. The
 * debug journal is ONE ordered stream every layer mirrors into:
 *
 *   scan log lines  → tag "scan"   (level inferred from the wording)
 *   crash journal   → tag "crash"  (ERROR)
 *   NETSENSE steps  → tag "net"    (INFO)
 *   update checks   → tag "update" (INFO / ERROR on failure)
 *   diagnostics     → tag "diag"   (every check, live while running)
 *
 * Design notes:
 *  - PURE KOTLIN (no android.* imports) so JVM unit tests cover it directly.
 *  - Thread-safe by a single monitor — writers come from dozens of engine
 *    lanes; readers are the compose UI and the share/export path.
 *  - Hard cap [CAP]: a 120k-probe mega-sweep must not build an unbounded
 *    mirror of itself; old entries fall off the back (newest-first UI).
 *  - [clock] is a seam — tests pin time; production uses wall clock.
 */
object DebugLog {

    /** Ring capacity — about 40 screens of console at 20 lines/screen. */
    const val CAP = 800

    private val lock = Any()
    private val entries = ArrayDeque<DbgEntry>()
    private val _flow = MutableStateFlow<List<DbgEntry>>(emptyList())

    /** Newest-first snapshot for the UI. */
    val flow: StateFlow<List<DbgEntry>> = _flow.asStateFlow()

    /** Wall-clock seam (epoch ms). Tests pin this. */
    @Volatile
    internal var clock: () -> Long = { System.currentTimeMillis() }

    fun log(level: DbgLevel, tag: String, message: String) {
        if (message.isBlank()) return
        val entry = DbgEntry(clock(), level, tag, message.trim())
        synchronized(lock) {
            entries.addFirst(entry)
            while (entries.size > CAP) entries.removeLast()
            _flow.value = ArrayList(entries)
        }
    }

    fun info(tag: String, message: String) = log(DbgLevel.INFO, tag, message)
    fun warn(tag: String, message: String) = log(DbgLevel.WARN, tag, message)
    fun error(tag: String, message: String) = log(DbgLevel.ERROR, tag, message)

    /** Mirrors a user-facing SCAN log line, inferring the level from its
     * wording — the engine's honest-verdict lines ("aborted", "0 answered",
     * "engine failure") are exactly the ones the console must paint red. */
    fun mirrorScanLine(line: String) = log(inferLevel(line), TAG_SCAN, line)

    /** Newest-first copy (never leaks the deque). */
    fun snapshot(): List<DbgEntry> = synchronized(lock) { ArrayList(entries) }

    fun clear() = synchronized(lock) {
        entries.clear()
        _flow.value = emptyList()
    }

    /**
     * Plain-text dump for sharing — OLDEST-FIRST (a support conversation
     * reads chronologically), one entry per line, compact timestamp + level
     * + tag + message. Header carries the entry count.
     */
    fun dump(): String {
        val snap = synchronized(lock) { ArrayList(entries) }
        val fmt = SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US)
        return buildString {
            append("UMBRA debug journal · ").append(snap.size).append(" entries\n")
            for (e in snap.asReversed()) {
                append(fmt.format(Date(e.epochMs)))
                append(' ').append(e.level.name.first())
                append('/').append(e.tag).append(' ')
                append(e.message.replace('\n', ' '))
                append('\n')
            }
        }
    }

    internal fun reset() {
        clock = { System.currentTimeMillis() }
        clear()
    }

    const val TAG_SCAN = "scan"
    const val TAG_CRASH = "crash"
    const val TAG_NET = "net"
    const val TAG_UPDATE = "update"
    const val TAG_DIAG = "diag"
}

enum class DbgLevel { TRACE, INFO, WARN, ERROR }

data class DbgEntry(
    val epochMs: Long,
    val level: DbgLevel,
    val tag: String,
    val message: String,
)

/**
 * Level inference for mirrored scan lines — pure function, unit-tested.
 * The engine's vocabulary is stable ("engine failure", "aborted", …), and
 * the two false-positive risks ("dead probes would only repeat" — a WARN
 * verdict, not an internal error; "no handshake" — a dead endpoint row,
 * never a log line) are handled by ordering: ERROR keywords are matched
 * strictly first.
 */
internal fun inferLevel(line: String): DbgLevel {
    val l = line.lowercase()
    return when {
        ERROR_KEYWORDS.any { it in l } -> DbgLevel.ERROR
        WARN_KEYWORDS.any { it in l } -> DbgLevel.WARN
        else -> DbgLevel.INFO
    }
}

private val ERROR_KEYWORDS = listOf(
    "engine failure",
    "internal error",
    "recorded to crash log",
    "could not start scan service",
    "engine died",
)

private val WARN_KEYWORDS = listOf(
    "aborted",
    "identity failed",
    "cannot validate endpoints",
    "0 answered",
    "0 validated",
    "dead probes",
    "unreachable",
    "blocked",
    "filtered",
    "silent",
    "no valid candidates",
    "no endpoints",
    "tls verify done · 0",
    "stop requested",
    "refused",
    "deferred",
    "witness verdict",
    "recovery sweep",
    "vpn",
)
