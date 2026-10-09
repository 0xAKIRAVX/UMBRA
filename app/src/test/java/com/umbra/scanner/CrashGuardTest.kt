package com.umbra.scanner

import android.app.Application
import com.umbra.scanner.engine.CrashGuard
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/**
 * v3.3.1 — CrashGuard is the last-resort net against "UMBRA has stopped".
 * These tests prove the three properties it must guarantee:
 *
 *  1. the journal records an uncaught-exception entry and chains to the
 *     previous handler (so Android's own crash handling stays intact)
 *  2. a coroutine exception with the installed handler is SURVIVED and journaled
 *  3. the journal truncates (no unbounded disk growth) and clears cleanly
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class CrashGuardTest {

    private fun app(): Application = RuntimeEnvironment.getApplication() as Application

    @Test
    fun `journal records thread crash and chains to previous handler`() {
        var chained = false
        // 1. marker handler becomes the chain target CrashGuard must call
        Thread.setDefaultUncaughtExceptionHandler { _, _ -> chained = true }
        // 2. fresh install captures the marker as `previous`
        CrashGuardTestAccess.reset()
        CrashGuard.install(app())
        CrashGuard.clear()
        // 3. simulate what happens when a thread explodes
        val hook = Thread.getDefaultUncaughtExceptionHandler()
        assertNotNull(hook)
        hook!!.uncaughtException(Thread.currentThread(), RuntimeException("probe kaboom"))

        assertTrue("must chain to the previous handler", chained)
        val entries = CrashGuard.recentCrashes()
        assertTrue("journal must contain the crash", entries.isNotEmpty())
        assertTrue(entries.first().contains("probe kaboom"))
        assertTrue(entries.first().contains("RuntimeException"))
    }

    @Test
    fun `coroutine exception is survived and journaled`() = runTest {
        CrashGuardTestAccess.reset()
        CrashGuard.install(app())
        CrashGuard.clear()
        var logged: String? = null
        val scope = CoroutineScope(SupervisorJob() + CrashGuard.handler("test") { logged = it })

        // this launch would kill the process without the handler
        scope.launch { throw IllegalStateException("coroutine kaboom") }

        // give the dispatcher a moment to run the failing coroutine
        kotlinx.coroutines.delay(300)

        val entries = CrashGuard.recentCrashes()
        assertTrue(entries.isNotEmpty())
        assertTrue(entries.first().contains("coroutine kaboom"))
        assertTrue(entries.first().contains("coroutine[test]"))
        assertNotNull(logged)
        assertTrue(logged!!.contains("test"))
    }

    @Test
    fun `journal truncates to the entry cap and clears`() {
        CrashGuardTestAccess.reset()
        CrashGuard.install(app())
        CrashGuard.clear()
        repeat(40) { i -> CrashGuard.recordNote("stress", "synthetic crash number $i") }
        val entries = CrashGuard.recentCrashes()
        assertTrue("cap enforced: ${entries.size}", entries.size <= 12)
        // newest first
        assertTrue(entries.first().contains("39"))
        CrashGuard.clear()
        assertEquals(0, CrashGuard.recentCrashes().size)
    }
}

/** Test-only access to singleton internals (kept out of the production API). */
object CrashGuardTestAccess {
    fun reset() {
        val f = CrashGuard::class.java.getDeclaredField("installed")
        f.isAccessible = true
        f.set(CrashGuard, false)
        val ctx = CrashGuard::class.java.getDeclaredField("appContext")
        ctx.isAccessible = true
        ctx.set(CrashGuard, null)
    }
}
