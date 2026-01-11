package com.covertcloak.scripturealarm.data

import java.util.Calendar

enum class ScriptureSource {
    CATEGORY,       // Use curated verse categories (original behavior)
    FULL_BIBLE,     // Random from entire Bible
    OLD_TESTAMENT,  // Random from Old Testament
    NEW_TESTAMENT,  // Random from New Testament
    SPECIFIC_BOOK,  // Random from a specific book
    SPECIFIC_CHAPTER // Random from a specific chapter
}

data class Alarm(
    val id: Int = 0,
    val hour: Int,
    val minute: Int,
    val enabled: Boolean = true,
    val label: String = "",
    val daysOfWeek: Set<Int> = emptySet(), // Calendar.SUNDAY, MONDAY, etc.
    val verseCategory: VerseCategory = VerseCategory.GENERAL,
    val useSequentialVerses: Boolean = false, // false = random, true = sequential
    // New scripture source options
    val scriptureSource: ScriptureSource = ScriptureSource.CATEGORY,
    val selectedBook: String = "",  // For SPECIFIC_BOOK or SPECIFIC_CHAPTER
    val selectedChapter: Int = 0    // For SPECIFIC_CHAPTER (0 = all chapters)
) {
    fun getTimeString(): String {
        val period = if (hour >= 12) "PM" else "AM"
        val displayHour = when {
            hour == 0 -> 12
            hour > 12 -> hour - 12
            else -> hour
        }
        return String.format("%d:%02d %s", displayHour, minute, period)
    }

    fun getNextAlarmTime(): Calendar {
        val now = Calendar.getInstance()
        val alarmTime = Calendar.getInstance().apply {
            set(Calendar.HOUR_OF_DAY, hour)
            set(Calendar.MINUTE, minute)
            set(Calendar.SECOND, 0)
            set(Calendar.MILLISECOND, 0)
        }

        // If alarm time has passed today, schedule for tomorrow
        if (alarmTime.before(now) || alarmTime == now) {
            alarmTime.add(Calendar.DAY_OF_MONTH, 1)
        }

        // If specific days are set, find the next valid day
        if (daysOfWeek.isNotEmpty()) {
            while (alarmTime.get(Calendar.DAY_OF_WEEK) !in daysOfWeek) {
                alarmTime.add(Calendar.DAY_OF_MONTH, 1)
            }
        }

        return alarmTime
    }

    fun getDaysString(): String {
        if (daysOfWeek.isEmpty()) return "Once"
        if (daysOfWeek.size == 7) return "Every day"
        if (daysOfWeek == setOf(Calendar.SATURDAY, Calendar.SUNDAY)) return "Weekends"
        if (daysOfWeek == setOf(Calendar.MONDAY, Calendar.TUESDAY, Calendar.WEDNESDAY, Calendar.THURSDAY, Calendar.FRIDAY)) return "Weekdays"

        val dayNames = mapOf(
            Calendar.SUNDAY to "Sun",
            Calendar.MONDAY to "Mon",
            Calendar.TUESDAY to "Tue",
            Calendar.WEDNESDAY to "Wed",
            Calendar.THURSDAY to "Thu",
            Calendar.FRIDAY to "Fri",
            Calendar.SATURDAY to "Sat"
        )

        return daysOfWeek.sorted().mapNotNull { dayNames[it] }.joinToString(", ")
    }
}
