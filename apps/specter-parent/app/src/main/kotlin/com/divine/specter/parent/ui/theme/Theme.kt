package com.divine.specter.parent.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val CyberGreen = Color(0xFF00FF88)
private val CyberBlue = Color(0xFF00BFFF)
private val CyberPurple = Color(0xFF8B5CF6)
private val DarkBackground = Color(0xFF0A0A0F)
private val DarkSurface = Color(0xFF1A1A2E)
private val DarkCard = Color(0xFF16213E)

private val DarkColorScheme = darkColorScheme(
    primary = CyberGreen,
    secondary = CyberBlue,
    tertiary = CyberPurple,
    background = DarkBackground,
    surface = DarkSurface,
    surfaceVariant = DarkCard,
    onPrimary = Color.Black,
    onSecondary = Color.Black,
    onBackground = Color.White,
    onSurface = Color.White,
    onSurfaceVariant = Color.White.copy(alpha = 0.7f)
)

@Composable
fun SpecterParentTheme(
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = DarkColorScheme,
        typography = Typography(),
        content = content
    )
}
