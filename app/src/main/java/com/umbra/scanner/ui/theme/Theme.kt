package com.umbra.scanner.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection
import com.umbra.scanner.i18n.AppLanguage
import com.umbra.scanner.i18n.LocalStrings
import com.umbra.scanner.settings.UmbraSettings

val LocalAccent = compositionLocalOf { CrimsonOrbit }
val LocalAmoled = staticCompositionLocalOf { false }
val LocalLightFx = staticCompositionLocalOf { false }

@Composable
fun UmbraTheme(settings: UmbraSettings, content: @Composable () -> Unit) {
    val accentIdx by settings.accent.collectAsState()
    val amoled by settings.amoled.collectAsState()
    val lightFx by settings.lightFx.collectAsState()
    val language by settings.language.collectAsState()
    val accent = ACCENTS[accentIdx.coerceIn(0, ACCENTS.size - 1)]
    val persian = language == AppLanguage.PERSIAN

    val bg = if (amoled) Color(0xFF000000) else VoidBlack
    val surface = if (amoled) Color(0xFF040507) else Obsidian
    val surfaceHigh = if (amoled) Color(0xFF080A0C) else Graphite

    val scheme = darkColorScheme(
        primary = accent.primary,
        onPrimary = Color(0xFF06110D),
        primaryContainer = surfaceHigh,
        onPrimaryContainer = accent.tint,
        secondary = Ultraviolet,
        onSecondary = Color(0xFF140B26),
        secondaryContainer = Graphite,
        onSecondaryContainer = Color(0xFFD9CCFF),
        tertiary = DangerRose,
        onTertiary = Color(0xFF2A0714),
        background = bg,
        onBackground = Mist,
        surface = surface,
        onSurface = Mist,
        surfaceVariant = surfaceHigh,
        onSurfaceVariant = Fog,
        outline = SlateLine,
        outlineVariant = SlateLine,
        error = DangerRose,
        onError = Color(0xFF2A0714),
        scrim = Color(0xB4000000),
    )

    CompositionLocalProvider(
        LocalAccent provides accent,
        LocalAmoled provides amoled,
        LocalLightFx provides lightFx,
        LocalStrings provides AppLanguage.stringsFor(language),
        LocalLayoutDirection provides if (persian) LayoutDirection.Rtl else LayoutDirection.Ltr,
    ) {
        MaterialTheme(
            colorScheme = scheme,
            typography = if (persian) UmbraTypographyFa else UmbraTypography,
            content = content,
        )
    }
}
