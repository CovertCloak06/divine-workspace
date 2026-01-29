package com.divine.specter.child.telegram

import android.content.Context
import android.content.SharedPreferences

object TelegramConfig {
    private const val PREFS_NAME = "telegram_config"
    private const val KEY_BOT_TOKEN = "bot_token"
    private const val KEY_CHAT_ID = "chat_id"
    private const val KEY_ENABLED = "enabled"

    private fun getPrefs(context: Context): SharedPreferences {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    fun setBotToken(context: Context, token: String) {
        getPrefs(context).edit().putString(KEY_BOT_TOKEN, token).apply()
    }

    fun getBotToken(context: Context): String? {
        return getPrefs(context).getString(KEY_BOT_TOKEN, null)
    }

    fun setChatId(context: Context, chatId: String) {
        getPrefs(context).edit().putString(KEY_CHAT_ID, chatId).apply()
    }

    fun getChatId(context: Context): String? {
        return getPrefs(context).getString(KEY_CHAT_ID, null)
    }

    fun setEnabled(context: Context, enabled: Boolean) {
        getPrefs(context).edit().putBoolean(KEY_ENABLED, enabled).apply()
    }

    fun isEnabled(context: Context): Boolean {
        return getPrefs(context).getBoolean(KEY_ENABLED, false)
    }

    fun configure(context: Context, botToken: String, chatId: String, enabled: Boolean = true) {
        getPrefs(context).edit()
            .putString(KEY_BOT_TOKEN, botToken)
            .putString(KEY_CHAT_ID, chatId)
            .putBoolean(KEY_ENABLED, enabled)
            .apply()
    }

    fun isConfigured(context: Context): Boolean {
        val prefs = getPrefs(context)
        return !prefs.getString(KEY_BOT_TOKEN, null).isNullOrEmpty() &&
               !prefs.getString(KEY_CHAT_ID, null).isNullOrEmpty() &&
               prefs.getBoolean(KEY_ENABLED, false)
    }
}
