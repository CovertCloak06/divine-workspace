package com.divine.specter.child.worker

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.divine.specter.child.ChildApplication

/**
 * WorkManager worker for sync.
 * Handles registration and syncing with parent server.
 * Android 12+ compatible - replaces direct foreground service start.
 */
class SyncWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    companion object {
        private const val TAG = "SyncWorker"
    }

    override suspend fun doWork(): Result {
        return try {
            val app = ChildApplication.instance
            val prefs = app.prefs

            if (!app.isConfigured()) {
                Log.w(TAG, "Not configured, skipping sync")
                return Result.success()
            }

            val sync = app.sync

            // Ensure serverUrl is set
            if (sync.serverUrl.isEmpty()) {
                val serverIp = prefs.getString("server_ip", null)
                val serverPort = prefs.getInt("server_port", 8855)
                if (!serverIp.isNullOrBlank()) {
                    sync.serverUrl = "http://$serverIp:$serverPort"
                    sync.deviceId = prefs.getString("device_id", null)
                        ?: "child_${System.currentTimeMillis()}"
                }
            }

            // Register if not yet registered
            if (sync.deviceToken.isEmpty()) {
                val deviceName = prefs.getString("device_name", "Child") ?: "Child"
                Log.i(TAG, "Registering with parent: ${sync.serverUrl}")
                val success = sync.register(sync.serverUrl, deviceName)
                if (success) {
                    Log.i(TAG, "Registered successfully")
                    prefs.edit().putString("device_token", sync.deviceToken).apply()
                } else {
                    Log.e(TAG, "Registration failed, will retry")
                    return Result.retry()
                }
            }

            // Sync data
            Log.d(TAG, "Syncing data")
            sync.syncNow()

            // Poll for commands
            Log.d(TAG, "Polling commands")
            sync.pollCommands()

            Log.i(TAG, "Sync complete")
            Result.success()
        } catch (e: Exception) {
            Log.e(TAG, "Sync failed", e)
            Result.retry()
        }
    }
}
