package com.covertcloak.scripturealarm.data

import android.content.Context
import android.content.SharedPreferences

class AppPreferences(context: Context) {

    private val prefs: SharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    companion object {
        private const val PREFS_NAME = "scripture_alarm_settings"

        // Voice settings
        private const val KEY_SPEECH_RATE = "speech_rate"
        private const val KEY_SPEECH_PITCH = "speech_pitch"
        private const val KEY_VOICE_NAME = "voice_name"
        private const val KEY_USER_NAME = "user_name"

        // Theme settings
        private const val KEY_THEME_MODE = "theme_mode"
        private const val KEY_COLOR_SCHEME = "color_scheme"
        private const val KEY_FONT_SIZE = "font_size"

        // Defaults
        const val DEFAULT_SPEECH_RATE = 0.85f
        const val DEFAULT_SPEECH_PITCH = 1.0f
        const val THEME_SYSTEM = 0
        const val THEME_LIGHT = 1
        const val THEME_DARK = 2

        const val COLOR_SCHEME_PURPLE = 0
        const val COLOR_SCHEME_DARK_PURPLE = 1
        const val COLOR_SCHEME_BLUE = 2
        const val COLOR_SCHEME_DARK_BLUE = 3
        const val COLOR_SCHEME_GREEN = 4
        const val COLOR_SCHEME_DARK_GREEN = 5
        const val COLOR_SCHEME_ORANGE = 6
        const val COLOR_SCHEME_DARK_ORANGE = 7
        const val COLOR_SCHEME_PINK = 8
        const val COLOR_SCHEME_TEAL = 9

        const val FONT_SIZE_SMALL = 0
        const val FONT_SIZE_MEDIUM = 1
        const val FONT_SIZE_LARGE = 2
    }

    var speechRate: Float
        get() = prefs.getFloat(KEY_SPEECH_RATE, DEFAULT_SPEECH_RATE)
        set(value) = prefs.edit().putFloat(KEY_SPEECH_RATE, value).apply()

    var speechPitch: Float
        get() = prefs.getFloat(KEY_SPEECH_PITCH, DEFAULT_SPEECH_PITCH)
        set(value) = prefs.edit().putFloat(KEY_SPEECH_PITCH, value).apply()

    var voiceName: String?
        get() = prefs.getString(KEY_VOICE_NAME, null)
        set(value) = prefs.edit().putString(KEY_VOICE_NAME, value).apply()

    var userName: String?
        get() = prefs.getString(KEY_USER_NAME, null)
        set(value) = prefs.edit().putString(KEY_USER_NAME, value).apply()

    var themeMode: Int
        get() = prefs.getInt(KEY_THEME_MODE, THEME_SYSTEM)
        set(value) = prefs.edit().putInt(KEY_THEME_MODE, value).apply()

    var colorScheme: Int
        get() = prefs.getInt(KEY_COLOR_SCHEME, COLOR_SCHEME_PURPLE)
        set(value) = prefs.edit().putInt(KEY_COLOR_SCHEME, value).apply()

    var fontSize: Int
        get() = prefs.getInt(KEY_FONT_SIZE, FONT_SIZE_MEDIUM)
        set(value) = prefs.edit().putInt(KEY_FONT_SIZE, value).apply()
}
