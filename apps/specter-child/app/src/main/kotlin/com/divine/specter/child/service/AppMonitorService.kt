package com.divine.specter.child.service

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.view.accessibility.AccessibilityEvent
import com.divine.specter.child.ChildApplication
import kotlinx.coroutines.flow.MutableStateFlow

/**
 * Accessibility service for monitoring foreground app.
 * Requires user to enable in Settings > Accessibility.
 */
class AppMonitorService : AccessibilityService() {

    companion object {
        val currentApp = MutableStateFlow<String?>(null)
        var instance: AppMonitorService? = null
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        instance = this

        serviceInfo = AccessibilityServiceInfo().apply {
            eventTypes = AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED
            feedbackType = AccessibilityServiceInfo.FEEDBACK_GENERIC
            flags = AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS
            notificationTimeout = 100
        }

        // Wire up to sync
        ChildApplication.instance.sync.getCurrentApp = {
            currentApp.value
        }
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        event ?: return

        when (event.eventType) {
            AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED -> {
                val packageName = event.packageName?.toString()
                if (packageName != null && packageName != currentApp.value) {
                    currentApp.value = packageName
                }
            }
        }
    }

    override fun onInterrupt() {}

    override fun onDestroy() {
        super.onDestroy()
        instance = null
    }
}
