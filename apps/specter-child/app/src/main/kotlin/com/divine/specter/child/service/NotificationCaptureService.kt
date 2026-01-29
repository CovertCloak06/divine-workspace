package com.divine.specter.child.service

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import com.divine.specter.child.ChildApplication
import com.divine.specter.child.sync.ChildSync
import kotlinx.coroutines.flow.MutableStateFlow

/**
 * Captures notifications from all apps.
 * Requires user to enable in Settings > Notification Access.
 */
class NotificationCaptureService : NotificationListenerService() {

    companion object {
        val recentNotifications = MutableStateFlow<List<ChildSync.NotificationData>>(emptyList())
        private const val MAX_STORED = 100
    }

    override fun onListenerConnected() {
        super.onListenerConnected()

        // Wire up to sync
        ChildApplication.instance.sync.getNotifications = {
            recentNotifications.value
        }
    }

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        try {
            val notification = sbn.notification
            val extras = notification.extras

            val data = ChildSync.NotificationData(
                packageName = sbn.packageName,
                appName = getAppName(sbn.packageName),
                title = extras.getString(Notification.EXTRA_TITLE),
                text = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString(),
                timestamp = sbn.postTime
            )

            // Add to list
            val current = recentNotifications.value.toMutableList()
            current.add(0, data)
            recentNotifications.value = current.take(MAX_STORED)

        } catch (e: Exception) {
            // Ignore parsing errors
        }
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification) {
        // Optionally track removals
    }

    private fun getAppName(packageName: String): String {
        return try {
            val pm = packageManager
            pm.getApplicationLabel(
                pm.getApplicationInfo(packageName, 0)
            ).toString()
        } catch (e: Exception) {
            packageName
        }
    }

    override fun onListenerDisconnected() {
        super.onListenerDisconnected()
    }
}
