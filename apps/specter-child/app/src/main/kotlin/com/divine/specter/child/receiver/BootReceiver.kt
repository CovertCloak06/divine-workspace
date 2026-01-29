package com.divine.specter.child.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.divine.specter.child.ChildApplication
import com.divine.specter.child.service.SyncService

/**
 * Auto-start sync service on device boot.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action in listOf(
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_LOCKED_BOOT_COMPLETED,
            "android.intent.action.QUICKBOOT_POWERON"
        )) {
            // Only start if configured
            val prefs = context.getSharedPreferences("specter_child", Context.MODE_PRIVATE)
            if (prefs.getBoolean("configured", false)) {
                val serviceIntent = Intent(context, SyncService::class.java)
                context.startForegroundService(serviceIntent)
            }
        }
    }
}
