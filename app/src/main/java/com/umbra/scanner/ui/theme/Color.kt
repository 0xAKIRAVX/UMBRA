package com.umbra.scanner.ui.theme

import androidx.compose.runtime.Immutable
import androidx.compose.ui.graphics.Color

// ── UMBRA rare substrate ──────────────────────────────────────────────
val VoidBlack = Color(0xFF05070A)      // deepest substrate
val Obsidian = Color(0xFF0B0F14)       // raised surface
val Graphite = Color(0xFF121820)       // cards
val SlateLine = Color(0xFF1E2934)      // hairlines
val Mist = Color(0xFFE9F5F1)           // primary text
val Fog = Color(0xFF8CA3A0)            // secondary text
val Fade = Color(0xFF5A6B69)           // tertiary text

// ── Rare accents ──────────────────────────────────────────────────────
@Immutable
data class AccentScheme(
    val name: String,
    val primary: Color,
    val glow: Color,
    val secondary: Color,
    val tint: Color,
)

/** v3.0 default — mirrors the crimson cyber-globe launcher icon. */
val CrimsonOrbit = AccentScheme(
    name = "CRIMSON ORBIT",
    primary = Color(0xFFFF3B4A),
    glow = Color(0xFFFF9AA5),
    secondary = Color(0xFF7CE7FF),
    tint = Color(0xFFFFE9EC),
)

val PhantomMint = AccentScheme(
    name = "PHANTOM MINT",
    primary = Color(0xFF00F0B5),
    glow = Color(0xFF7CFFE0),
    secondary = Color(0xFF8F6BFF),
    tint = Color(0xFFD9FFF5),
)

val LunarIris = AccentScheme(
    name = "LUNAR IRIS",
    primary = Color(0xFF8F6BFF),
    glow = Color(0xFFC9B4FF),
    secondary = Color(0xFF00F0B5),
    tint = Color(0xFFEDE6FF),
)

val NovaRose = AccentScheme(
    name = "NOVA ROSE",
    primary = Color(0xFFFF4D8D),
    glow = Color(0xFFFFAFCB),
    secondary = Color(0xFF7CE7FF),
    tint = Color(0xFFFFE9F1),
)

val EmberFlare = AccentScheme(
    name = "EMBER FLARE",
    primary = Color(0xFFFFB454),
    glow = Color(0xFFFFDDA6),
    secondary = Color(0xFFFF6A5C),
    tint = Color(0xFFFFF3E2),
)

val ACCENTS = listOf(CrimsonOrbit, PhantomMint, LunarIris, NovaRose, EmberFlare)

// medal tints for the results board top-3
val GoldMedal = Color(0xFFF5C26B)
val SilverMedal = Color(0xFFC9D6E3)
val BronzeMedal = Color(0xFFD6905F)

// semantic
val Ultraviolet = Color(0xFF8F6BFF)
val DangerRose = Color(0xFFFF4D8D)
val WarnAmber = Color(0xFFFFB454)
val OkMint = Color(0xFF00F0B5)
