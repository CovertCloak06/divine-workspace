package com.covertcloak.scripturealarm.alarm

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.media.AudioManager
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import android.speech.tts.TextToSpeech
import android.speech.tts.UtteranceProgressListener
import androidx.core.app.NotificationCompat
import com.covertcloak.scripturealarm.R
import com.covertcloak.scripturealarm.data.AppPreferences
import com.covertcloak.scripturealarm.data.BibleDatabase
import com.covertcloak.scripturealarm.data.BibleVerse
import com.covertcloak.scripturealarm.data.BibleVerseRepository
import com.covertcloak.scripturealarm.data.ScriptureSource
import com.covertcloak.scripturealarm.data.VerseCategory
import com.covertcloak.scripturealarm.ui.AlarmActivity
import java.util.Locale

class AlarmService : Service(), TextToSpeech.OnInitListener {

    private var textToSpeech: TextToSpeech? = null
    private var vibrator: Vibrator? = null
    private var currentVerse: BibleVerse? = null
    private var isTtsReady = false

    // Gradual volume wake-up
    private var audioManager: AudioManager? = null
    private var originalVolume: Int = 0
    private var maxVolume: Int = 15
    private var currentVolume: Int = 0
    private val volumeHandler = Handler(Looper.getMainLooper())
    private val gradualVolumeRunnable = object : Runnable {
        override fun run() {
            if (currentVolume < maxVolume) {
                currentVolume++
                audioManager?.setStreamVolume(AudioManager.STREAM_MUSIC, currentVolume, 0)
                // Increase volume every 2 seconds over ~30 seconds total
                volumeHandler.postDelayed(this, 2000)
            }
        }
    }

    companion object {
        const val CHANNEL_ID = "scripture_alarm_channel"
        const val NOTIFICATION_ID = 1001
        const val ACTION_DISMISS = "com.covertcloak.scripturealarm.DISMISS"
        const val ACTION_SNOOZE = "com.covertcloak.scripturealarm.SNOOZE"

        var currentVerseText: String? = null
        var currentVerseReference: String? = null
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        textToSpeech = TextToSpeech(this, this)

        // Setup audio manager for gradual volume
        audioManager = getSystemService(Context.AUDIO_SERVICE) as AudioManager
        maxVolume = audioManager?.getStreamMaxVolume(AudioManager.STREAM_MUSIC) ?: 15
        originalVolume = audioManager?.getStreamVolume(AudioManager.STREAM_MUSIC) ?: maxVolume
    }

    private var pendingSpeak = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISMISS -> {
                stopAlarm()
                return START_NOT_STICKY
            }
            ACTION_SNOOZE -> {
                snoozeAlarm()
                return START_NOT_STICKY
            }
        }

        val verseCategory = intent?.getStringExtra(AlarmReceiver.EXTRA_VERSE_CATEGORY)?.let {
            try { VerseCategory.valueOf(it) } catch (e: Exception) { VerseCategory.GENERAL }
        } ?: VerseCategory.GENERAL

        val useSequential = intent?.getBooleanExtra(AlarmReceiver.EXTRA_USE_SEQUENTIAL, false) ?: false

        // Get scripture source settings
        val scriptureSource = intent?.getStringExtra(AlarmReceiver.EXTRA_SCRIPTURE_SOURCE)?.let {
            try { ScriptureSource.valueOf(it) } catch (e: Exception) { ScriptureSource.CATEGORY }
        } ?: ScriptureSource.CATEGORY
        val selectedBook = intent?.getStringExtra(AlarmReceiver.EXTRA_SELECTED_BOOK) ?: ""
        val selectedChapter = intent?.getIntExtra(AlarmReceiver.EXTRA_SELECTED_CHAPTER, 0) ?: 0

        // Get verse based on scripture source
        currentVerse = getVerseForSource(scriptureSource, verseCategory, useSequential, selectedBook, selectedChapter)

        currentVerseText = currentVerse?.text
        currentVerseReference = currentVerse?.reference

        startForeground(NOTIFICATION_ID, createNotification())

        // Brief vibration to wake user, then read scripture (NO alarm sound)
        startBriefVibration()

        // Start speaking the verse automatically
        if (isTtsReady) {
            speakVerse()
        } else {
            pendingSpeak = true
        }

        // Launch full-screen alarm activity
        val alarmIntent = Intent(this, AlarmActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            putExtra("verse_text", currentVerse?.text)
            putExtra("verse_reference", currentVerse?.reference)
        }
        startActivity(alarmIntent)

        return START_STICKY
    }

    override fun onInit(status: Int) {
        if (status == TextToSpeech.SUCCESS) {
            val result = textToSpeech?.setLanguage(Locale.US)
            if (result != TextToSpeech.LANG_MISSING_DATA && result != TextToSpeech.LANG_NOT_SUPPORTED) {
                isTtsReady = true

                // Apply voice settings from preferences
                val prefs = AppPreferences(this)
                textToSpeech?.setSpeechRate(prefs.speechRate)
                textToSpeech?.setPitch(prefs.speechPitch)

                // Set voice if saved
                prefs.voiceName?.let { savedVoiceName ->
                    textToSpeech?.voices?.find { it.name == savedVoiceName }?.let { voice ->
                        textToSpeech?.voice = voice
                    }
                }

                // If alarm triggered before TTS was ready, speak now
                if (pendingSpeak && currentVerse != null) {
                    speakVerse()
                    pendingSpeak = false
                }
            }
        }
    }

    private fun getVerseForSource(
        source: ScriptureSource,
        category: VerseCategory,
        useSequential: Boolean,
        selectedBook: String,
        selectedChapter: Int
    ): BibleVerse {
        return when (source) {
            ScriptureSource.CATEGORY -> {
                // Use original curated verse system
                if (useSequential) {
                    BibleVerseRepository.getNextVerse()
                } else {
                    BibleVerseRepository.getRandomVerse(category)
                }
            }
            ScriptureSource.FULL_BIBLE -> {
                // Random verse from entire Bible
                val bibleDb = BibleDatabase.getInstance(this)
                val verse = bibleDb.getRandomVerse()
                verse?.let {
                    BibleVerse(it.bookName, it.chapter, it.verse, it.text)
                } ?: BibleVerseRepository.getRandomVerse(category)
            }
            ScriptureSource.OLD_TESTAMENT -> {
                val bibleDb = BibleDatabase.getInstance(this)
                val verse = bibleDb.getRandomVerseFromTestament("Old Testament")
                verse?.let {
                    BibleVerse(it.bookName, it.chapter, it.verse, it.text)
                } ?: BibleVerseRepository.getRandomVerse(category)
            }
            ScriptureSource.NEW_TESTAMENT -> {
                val bibleDb = BibleDatabase.getInstance(this)
                val verse = bibleDb.getRandomVerseFromTestament("New Testament")
                verse?.let {
                    BibleVerse(it.bookName, it.chapter, it.verse, it.text)
                } ?: BibleVerseRepository.getRandomVerse(category)
            }
            ScriptureSource.SPECIFIC_BOOK -> {
                if (selectedBook.isNotEmpty()) {
                    val bibleDb = BibleDatabase.getInstance(this)
                    val verse = bibleDb.getRandomVerseFromBook(selectedBook)
                    verse?.let {
                        BibleVerse(it.bookName, it.chapter, it.verse, it.text)
                    } ?: BibleVerseRepository.getRandomVerse(category)
                } else {
                    BibleVerseRepository.getRandomVerse(category)
                }
            }
            ScriptureSource.SPECIFIC_CHAPTER -> {
                if (selectedBook.isNotEmpty() && selectedChapter > 0) {
                    val bibleDb = BibleDatabase.getInstance(this)
                    val verse = bibleDb.getRandomVerseFromChapter(selectedBook, selectedChapter)
                    verse?.let {
                        BibleVerse(it.bookName, it.chapter, it.verse, it.text)
                    } ?: BibleVerseRepository.getRandomVerse(category)
                } else {
                    BibleVerseRepository.getRandomVerse(category)
                }
            }
        }
    }

    fun speakVerse() {
        if (isTtsReady && currentVerse != null) {
            stopVibration()

            // Start gradual volume wake-up (start at 30% volume)
            startGradualVolume()

            val prefs = AppPreferences(this)
            val greeting = if (!prefs.userName.isNullOrBlank()) {
                "Good morning ${prefs.userName}."
            } else {
                "Good morning."
            }
            val textToSpeak = "$greeting Here is your scripture for today. ${currentVerse!!.reference}. ${currentVerse!!.text}"

            textToSpeech?.setOnUtteranceProgressListener(object : UtteranceProgressListener() {
                override fun onStart(utteranceId: String?) {}

                override fun onDone(utteranceId: String?) {
                    // Speech completed - keep alarm active until user dismisses
                }

                @Deprecated("Deprecated in Java")
                override fun onError(utteranceId: String?) {}
            })

            textToSpeech?.speak(textToSpeak, TextToSpeech.QUEUE_FLUSH, null, "verse_utterance")
        }
    }

    private fun startGradualVolume() {
        // Start at about 30% of max volume
        currentVolume = (maxVolume * 0.3).toInt().coerceAtLeast(1)
        audioManager?.setStreamVolume(AudioManager.STREAM_MUSIC, currentVolume, 0)

        // Begin gradual increase
        volumeHandler.postDelayed(gradualVolumeRunnable, 2000)
    }

    private fun stopGradualVolume() {
        volumeHandler.removeCallbacks(gradualVolumeRunnable)
        // Restore original volume
        audioManager?.setStreamVolume(AudioManager.STREAM_MUSIC, originalVolume, 0)
    }

    private fun startBriefVibration() {
        vibrator = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val vibratorManager = getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as VibratorManager
            vibratorManager.defaultVibrator
        } else {
            @Suppress("DEPRECATION")
            getSystemService(VIBRATOR_SERVICE) as Vibrator
        }

        // Brief vibration pattern to get attention, not continuous
        val pattern = longArrayOf(0, 300, 200, 300, 200, 300)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            vibrator?.vibrate(VibrationEffect.createWaveform(pattern, -1)) // -1 = don't repeat
        } else {
            @Suppress("DEPRECATION")
            vibrator?.vibrate(pattern, -1)
        }
    }

    private fun stopVibration() {
        vibrator?.cancel()
    }

    private fun snoozeAlarm() {
        // TODO: Implement snooze - reschedule alarm for 5-10 minutes later
        stopAlarm()
    }

    fun stopAlarm() {
        stopVibration()
        stopGradualVolume()
        textToSpeech?.stop()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Scripture Alarm",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Wake up with God's Word"
                setSound(null, null)
                enableVibration(false)
            }
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        val fullScreenIntent = Intent(this, AlarmActivity::class.java).apply {
            putExtra("verse_text", currentVerse?.text)
            putExtra("verse_reference", currentVerse?.reference)
        }
        val fullScreenPendingIntent = PendingIntent.getActivity(
            this, 0, fullScreenIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val dismissIntent = Intent(this, AlarmService::class.java).apply {
            action = ACTION_DISMISS
        }
        val dismissPendingIntent = PendingIntent.getService(
            this, 1, dismissIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_alarm)
            .setContentTitle("Scripture Alarm")
            .setContentText(currentVerse?.reference ?: "Time to wake up!")
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setFullScreenIntent(fullScreenPendingIntent, true)
            .addAction(R.drawable.ic_dismiss, "Dismiss", dismissPendingIntent)
            .setOngoing(true)
            .build()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        textToSpeech?.stop()
        textToSpeech?.shutdown()
        stopVibration()
        stopGradualVolume()
        super.onDestroy()
    }
}
