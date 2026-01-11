package com.covertcloak.scripturealarm.alarm

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build

class AlarmReceiver : BroadcastReceiver() {

    companion object {
        const val EXTRA_ALARM_ID = "alarm_id"
        const val EXTRA_VERSE_CATEGORY = "verse_category"
        const val EXTRA_USE_SEQUENTIAL = "use_sequential"
        const val EXTRA_SCRIPTURE_SOURCE = "scripture_source"
        const val EXTRA_SELECTED_BOOK = "selected_book"
        const val EXTRA_SELECTED_CHAPTER = "selected_chapter"
    }

    override fun onReceive(context: Context, intent: Intent) {
        val alarmId = intent.getIntExtra(EXTRA_ALARM_ID, -1)
        val verseCategory = intent.getStringExtra(EXTRA_VERSE_CATEGORY) ?: "GENERAL"
        val useSequential = intent.getBooleanExtra(EXTRA_USE_SEQUENTIAL, false)
        val scriptureSource = intent.getStringExtra(EXTRA_SCRIPTURE_SOURCE) ?: "CATEGORY"
        val selectedBook = intent.getStringExtra(EXTRA_SELECTED_BOOK) ?: ""
        val selectedChapter = intent.getIntExtra(EXTRA_SELECTED_CHAPTER, 0)

        val serviceIntent = Intent(context, AlarmService::class.java).apply {
            putExtra(EXTRA_ALARM_ID, alarmId)
            putExtra(EXTRA_VERSE_CATEGORY, verseCategory)
            putExtra(EXTRA_USE_SEQUENTIAL, useSequential)
            putExtra(EXTRA_SCRIPTURE_SOURCE, scriptureSource)
            putExtra(EXTRA_SELECTED_BOOK, selectedBook)
            putExtra(EXTRA_SELECTED_CHAPTER, selectedChapter)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(serviceIntent)
        } else {
            context.startService(serviceIntent)
        }
    }
}
