package com.divine.specter.child

import android.app.Application
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.work.*
import com.divine.specter.child.sync.ChildSync
import com.divine.specter.child.worker.SyncWorker
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.util.concurrent.TimeUnit

class ChildApplication : Application() {

    companion object {
        private const val TAG = "ChildApp"
        private const val PREFS_NAME = "specter_child_prefs"

        lateinit var instance: ChildApplication
            private set
    }

    val sync by lazy { ChildSync(this) }
    val prefs by lazy { getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE) }

    override fun onCreate() {
        super.onCreate()
        instance = this

        // Load config from prefs (set by ConfigReceiver via ADB broadcast)
        loadConfigAndStart()
    }

    /**
     * Load configuration from SharedPreferences and start sync if configured.
     * Called on app start and after receiving config broadcast.
     */
    fun loadConfigAndStart() {
        val isConfigured = prefs.getBoolean("is_configured", false)
        val serverIp = prefs.getString("server_ip", null)
        val serverPort = prefs.getInt("server_port", 8855)
        val deviceId = prefs.getString("device_id", null)
        val deviceName = prefs.getString("device_name", "Child")

        Log.d(TAG, "Config check: configured=$isConfigured, server=$serverIp:$serverPort")

        if (!isConfigured || serverIp.isNullOrBlank()) {
            Log.w(TAG, "Not configured yet - waiting for config broadcast")
            return
        }

        // Set sync config
        sync.serverUrl = "http://$serverIp:$serverPort"
        sync.deviceId = deviceId ?: "child_${System.currentTimeMillis()}"

        Log.i(TAG, "Connecting to parent: ${sync.serverUrl}")

        // Register with parent server
        CoroutineScope(Dispatchers.IO).launch {
            val success = sync.register(sync.serverUrl, deviceName ?: "Child")
            if (success) {
                Log.i(TAG, "Registered with parent server")
                // Save token
                prefs.edit().putString("device_token", sync.deviceToken).apply()
            } else {
                Log.e(TAG, "Failed to register with parent")
            }
        }

        // Schedule immediate sync via WorkManager (Android 12+ safe)
        scheduleImmediateSync()

        // Schedule periodic sync via WorkManager
        scheduleSyncWork()
    }

    fun isConfigured(): Boolean {
        return prefs.getBoolean("is_configured", false)
    }

    /**
     * Schedule immediate sync via WorkManager (Android 12+ compatible).
     * Replaces direct startForegroundService which is blocked from background.
     */
    private fun scheduleImmediateSync() {
        val syncWork = OneTimeWorkRequestBuilder<SyncWorker>()
            .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
            .build()

        WorkManager.getInstance(this).enqueueUniqueWork(
            "immediate_sync",
            ExistingWorkPolicy.REPLACE,
            syncWork
        )
        Log.i(TAG, "Scheduled immediate sync via WorkManager")
    }

    private fun scheduleSyncWork() {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()

        val syncRequest = PeriodicWorkRequestBuilder<SyncWorker>(
            15, TimeUnit.MINUTES  // Minimum interval
        )
            .setConstraints(constraints)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 1, TimeUnit.MINUTES)
            .build()

        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            "specter_sync",
            ExistingPeriodicWorkPolicy.KEEP,
            syncRequest
        )
        Log.d(TAG, "Scheduled periodic sync work")
    }
}
