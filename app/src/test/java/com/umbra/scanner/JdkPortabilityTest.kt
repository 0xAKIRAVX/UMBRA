package com.umbra.scanner

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * v3.5.1 — regression guard for the class of bug that killed every WARP scan
 * on real devices in v3.5.0:
 *
 *   java.lang.NoSuchFieldError: No field TWO … in class Ljava/math/BigInteger;
 *
 * The Kotlin compiler resolves `java.*` references against the DESKTOP JDK
 * that runs Gradle (OpenJDK 21 knows BigInteger.TWO), while Android's
 * core-libart does not have that field at ANY api level. Unit tests execute on
 * the desktop JDK too, so nothing on the JVM side can ever catch this — the
 * app only dies at runtime, on the phone, inside the scan engine.
 *
 * This test therefore greps the production sources for a denylist of
 * JDK-only members that must never appear in `src/main`.
 */
class JdkPortabilityTest {

    // Each pattern: (regex, human-readable reason)
    private val forbidden: List<Pair<Regex, String>> = listOf(
        Regex("""BigInteger\s*\.\s*TWO\b""") to
            "BigInteger.TWO exists only on JDK 21+, not in Android core-libart (v3.5.0 crash) — use BigInteger.valueOf(2)",
        Regex("""java\.net\.http\b""") to
            "java.net.http.* (JDK 11+) is absent from Android entirely",
        Regex("""\.\s*stripIndent\s*\(""") to
            "String.stripIndent() is JDK 15+, not on Android",
        Regex("""\.\s*formatted\s*\(""") to
            "String.formatted() is JDK 15+, not on Android",
    )

    @Test
    fun `main sources contain no JDK-only java APIs missing on Android`() {
        val root = File("src/main/java")
        assertTrue("expected CWD to be the app module — got ${File(".").absolutePath}", root.isDirectory)

        val offenders = root.walkTopDown()
            .filter { it.isFile && (it.extension == "kt" || it.extension == "java") }
            .flatMap { file ->
                val text = file.readText()
                forbidden.mapNotNull { (rx, why) ->
                    rx.find(text)?.let { "${file.relativeToOrSelf(root).path}: «${it.value.trim()}» — $why" }
                }
            }
            .sorted()
            .toList()

        assertTrue(
            "JDK-only APIs found in production sources (they pass desktop unit tests but crash on devices):\n" +
                offenders.joinToString("\n"),
            offenders.isEmpty()
        )
    }

    @Test
    fun `WgCrypto class-init loads without a desktop-only BigInteger member`() {
        // Touching the object forces <clinit> (the exact crash site of v3.5.0:
        // NoClassDefFoundError inside the scan engine's first crypto call).
        // On the desktop JDK this always succeeds; the denylist test above is
        // what actually protects devices — this test documents the failure mode
        // and pins the fix (constants derive from valueOf(2), never a field ref).
        val pub = com.umbra.scanner.net.WgCrypto.x25519Base(ByteArray(32))
        org.junit.Assert.assertEquals(32, pub.size)
    }
}
