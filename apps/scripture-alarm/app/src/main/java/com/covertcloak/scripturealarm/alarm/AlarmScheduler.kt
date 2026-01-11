package com.covertcloak.scripturealarm.alarm

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import com.covertcloak.scripturealarm.data.Alarm

object AlarmScheduler {

    private const val PREFS_NAME = "scripture_alarm_prefs"
    private const val KEY_ALARMS = "alarms"

    fun scheduleAlarm(context: Context, alarm: Alarm) {
        val alarmManager = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager

        val intent = Intent(context, AlarmReceiver::class.java).apply {
            action = "com.covertcloak.scripturealarm.ALARM_TRIGGER"
            putExtra(AlarmReceiver.EXTRA_ALARM_ID, alarm.id)
            putExtra(AlarmReceiver.EXTRA_VERSE_CATEGORY, alarm.verseCategory.name)
            putExtra(AlarmReceiver.EXTRA_USE_SEQUENTIAL, alarm.useSequentialVerses)
            putExtra(AlarmReceiver.EXTRA_SCRIPTURE_SOURCE, alarm.scriptureSource.name)
            putExtra(AlarmReceiver.EXTRA_SELECTED_BOOK, alarm.selectedBook)
            putExtra(AlarmReceiver.EXTRA_SELECTED_CHAPTER, alarm.selectedChapter)
        }

        val pendingIntent = PendingIntent.getBroadcast(
            context,
            alarm.id,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val triggerTime = alarm.getNextAlarmTime().timeInMillis

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            if (alarmManager.canScheduleExactAlarms()) {
                alarmManager.setAlarmClock(
                    AlarmManager.AlarmClockInfo(triggerTime, pendingIntent),
                    pendingIntent
                )
            }
        } else {
            alarmManager.setAlarmClock(
                AlarmManager.AlarmClockInfo(triggerTime, pendingIntent),
                pendingIntent
            )
        }

        saveAlarm(context, alarm)
    }

    fun cancelAlarm(context: Context, alarm: Alarm) {
        val alarmManager = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager

        val intent = Intent(context, AlarmReceiver::class.java).apply {
            action = "com.covertcloak.scripturealarm.ALARM_TRIGGER"
        }

        val pendingIntent = PendingIntent.getBroadcast(
            context,
            alarm.id,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        alarmManager.cancel(pendingIntent)
        removeAlarm(context, alarm.id)
    }

    fun rescheduleAllAlarms(context: Context) {
        val alarms = getAlarms(context)
        alarms.filter { it.enabled }.forEach { alarm ->
            scheduleAlarm(context, alarm)
        }
    }

    fun saveAlarm(context: Context, alarm: Alarm) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val alarmsJson = prefs.getString(KEY_ALARMS, "") ?: ""
        val alarms = parseAlarms(alarmsJson).toMutableList()

        // Update existing or add new
        val existingIndex = alarms.indexOfFirst { it.id == alarm.id }
        if (existingIndex >= 0) {
            alarms[existingIndex] = alarm
        } else {
            alarms.add(alarm)
        }

        prefs.edit().putString(KEY_ALARMS, serializeAlarms(alarms)).apply()
    }

    fun removeAlarm(context: Context, alarmId: Int) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val alarmsJson = prefs.getString(KEY_ALARMS, "") ?: ""
        val alarms = parseAlarms(alarmsJson).filter { it.id != alarmId }
        prefs.edit().putString(KEY_ALARMS, serializeAlarms(alarms)).apply()
    }

    fun getAlarms(context: Context): List<Alarm> {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val alarmsJson = prefs.getString(KEY_ALARMS, "") ?: ""
        return parseAlarms(alarmsJson)
    }

    fun getNextAlarmId(context: Context): Int {
        val alarms = getAlarms(context)
        return if (alarms.isEmpty()) 1 else alarms.maxOf { it.id } + 1
    }

    private fun serializeAlarms(alarms: List<Alarm>): String {
        return alarms.joinToString("|") { alarm ->
            "${alarm.id},${alarm.hour},${alarm.minute},${alarm.enabled}," +
                    "${alarm.label},${alarm.daysOfWeek.joinToString(";")},${alarm.verseCategory.name},${alarm.useSequentialVerses}," +
                    "${alarm.scriptureSource.name},${alarm.selectedBook},${alarm.selectedChapter}"
        }
    }

    private fun parseAlarms(json: String): List<Alarm> {
        if (json.isBlank()) return emptyList()

        return json.split("|").mapNotNull { alarmStr ->
            try {
                val parts = alarmStr.split(",")
                if (parts.size >= 8) {
                    Alarm(
                        id = parts[0].toInt(),
                        hour = parts[1].toInt(),
                        minute = parts[2].toInt(),
                        enabled = parts[3].toBoolean(),
                        label = parts[4],
                        daysOfWeek = if (parts[5].isBlank()) emptySet() else parts[5].split(";").map { it.toInt() }.toSet(),
                        verseCategory = try { com.covertcloak.scripturealarm.data.VerseCategory.valueOf(parts[6]) } catch (e: Exception) { com.covertcloak.scripturealarm.data.VerseCategory.GENERAL },
                        useSequentialVerses = parts[7].toBoolean(),
                        // New fields with defaults for backward compatibility
                        scriptureSource = if (parts.size > 8) try { com.covertcloak.scripturealarm.data.ScriptureSource.valueOf(parts[8]) } catch (e: Exception) { com.covertcloak.scripturealarm.data.ScriptureSource.CATEGORY } else com.covertcloak.scripturealarm.data.ScriptureSource.CATEGORY,
                        selectedBook = if (parts.size > 9) parts[9] else "",
                        selectedChapter = if (parts.size > 10) parts[10].toIntOrNull() ?: 0 else 0
                    )
                } else null
            } catch (e: Exception) {
                null
            }
        }
    }
}
