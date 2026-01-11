package com.covertcloak.scripturealarm.tts

import android.content.Context
import android.speech.tts.TextToSpeech
import android.speech.tts.UtteranceProgressListener
import com.covertcloak.scripturealarm.data.BibleVerse
import java.util.Locale

class ScriptureSpeaker(
    context: Context,
    private val onReady: () -> Unit = {},
    private val onComplete: () -> Unit = {},
    private val onError: (String) -> Unit = {}
) : TextToSpeech.OnInitListener {

    private var tts: TextToSpeech? = TextToSpeech(context, this)
    private var isReady = false

    override fun onInit(status: Int) {
        if (status == TextToSpeech.SUCCESS) {
            val result = tts?.setLanguage(Locale.US)
            if (result == TextToSpeech.LANG_MISSING_DATA || result == TextToSpeech.LANG_NOT_SUPPORTED) {
                onError("Language not supported")
            } else {
                isReady = true
                tts?.setSpeechRate(0.85f)
                tts?.setPitch(1.0f)
                onReady()
            }
        } else {
            onError("TTS initialization failed")
        }
    }

    fun speakVerse(verse: BibleVerse, includeGreeting: Boolean = true) {
        if (!isReady) {
            onError("TTS not ready")
            return
        }

        val greeting = if (includeGreeting) "Good morning. Here is your scripture for today. " else ""
        val text = "$greeting${verse.reference}. ${verse.text}"

        tts?.setOnUtteranceProgressListener(object : UtteranceProgressListener() {
            override fun onStart(utteranceId: String?) {}

            override fun onDone(utteranceId: String?) {
                onComplete()
            }

            @Deprecated("Deprecated in Java")
            override fun onError(utteranceId: String?) {
                this@ScriptureSpeaker.onError("Speech error")
            }
        })

        tts?.speak(text, TextToSpeech.QUEUE_FLUSH, null, "scripture_${System.currentTimeMillis()}")
    }

    fun stop() {
        tts?.stop()
    }

    fun shutdown() {
        tts?.stop()
        tts?.shutdown()
        tts = null
        isReady = false
    }
}
