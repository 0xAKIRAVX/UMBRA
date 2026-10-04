package com.umbra.scanner.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import com.umbra.scanner.R

/** Rare geometric display face (small-caps) — wordmark and section headers. */
val BrunoAce = FontFamily(
    Font(R.font.bruno_ace_sc, FontWeight.Normal),
)

/** Technical UI face — body, labels, controls. */
val Chakra = FontFamily(
    Font(R.font.chakra_petch_light, FontWeight.Light),
    Font(R.font.chakra_petch_regular, FontWeight.Normal),
    Font(R.font.chakra_petch_medium, FontWeight.Medium),
    Font(R.font.chakra_petch_semibold, FontWeight.SemiBold),
)

/** Rare monospace display face — IPs, latencies, scores, VLESS payloads. */
val MajorMono = FontFamily(
    Font(R.font.major_mono_display, FontWeight.Normal),
)

val UmbraTypography = Typography(
    displayLarge = TextStyle(
        fontFamily = BrunoAce, fontWeight = FontWeight.Normal,
        fontSize = 26.sp, letterSpacing = 7.sp,
    ),
    displayMedium = TextStyle(
        fontFamily = BrunoAce, fontWeight = FontWeight.Normal,
        fontSize = 16.sp, letterSpacing = 4.sp,
    ),
    titleLarge = TextStyle(
        fontFamily = Chakra, fontWeight = FontWeight.SemiBold,
        fontSize = 16.sp, letterSpacing = 1.8.sp,
    ),
    titleMedium = TextStyle(
        fontFamily = Chakra, fontWeight = FontWeight.SemiBold,
        fontSize = 13.sp, letterSpacing = 1.4.sp,
    ),
    bodyLarge = TextStyle(
        fontFamily = Chakra, fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
    ),
    bodyMedium = TextStyle(
        fontFamily = Chakra, fontWeight = FontWeight.Normal,
        fontSize = 12.sp, letterSpacing = 0.3.sp,
    ),
    bodySmall = TextStyle(
        fontFamily = Chakra, fontWeight = FontWeight.Light,
        fontSize = 10.5.sp, letterSpacing = 0.4.sp,
    ),
    labelLarge = TextStyle(
        fontFamily = Chakra, fontWeight = FontWeight.SemiBold,
        fontSize = 12.sp, letterSpacing = 2.2.sp,
    ),
    labelMedium = TextStyle(
        fontFamily = Chakra, fontWeight = FontWeight.Medium,
        fontSize = 10.sp, letterSpacing = 1.6.sp,
    ),
    labelSmall = TextStyle(
        fontFamily = Chakra, fontWeight = FontWeight.Medium,
        fontSize = 9.sp, letterSpacing = 2.2.sp,
    ),
)

/** Data readouts. */
val MonoStyle = TextStyle(
    fontFamily = MajorMono,
    fontWeight = FontWeight.Normal,
    fontSize = 13.sp,
    letterSpacing = 0.6.sp,
)

val MonoStyleSmall = TextStyle(
    fontFamily = MajorMono,
    fontWeight = FontWeight.Normal,
    fontSize = 10.sp,
    letterSpacing = 0.4.sp,
)

val MonoStyleLarge = TextStyle(
    fontFamily = MajorMono,
    fontWeight = FontWeight.Normal,
    fontSize = 17.sp,
    letterSpacing = 0.8.sp,
)
