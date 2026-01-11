package com.covertcloak.scripturealarm.alarm

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            // Restore all enabled alarms after device reboot
            AlarmScheduler.rescheduleAllAlarms(context)
        }
    }
}
