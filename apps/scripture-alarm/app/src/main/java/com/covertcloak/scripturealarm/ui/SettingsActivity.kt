package com.covertcloak.scripturealarm.ui

import android.os.Bundle
import android.speech.tts.TextToSpeech
import android.speech.tts.Voice
import android.util.Log
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.ImageButton
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.SeekBar
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import com.covertcloak.scripturealarm.R
import com.covertcloak.scripturealarm.data.AppPreferences
import java.util.Locale

class SettingsActivity : AppCompatActivity(), TextToSpeech.OnInitListener {

    private lateinit var prefs: AppPreferences
    private var tts: TextToSpeech? = null
    private var availableVoices: List<Voice> = emptyList()
    private var isTtsReady = false

    private lateinit var editName: EditText
    private lateinit var spinnerVoice: Spinner
    private lateinit var seekBarSpeed: SeekBar
    private lateinit var seekBarPitch: SeekBar
    private lateinit var textSpeedValue: TextView
    private lateinit var textPitchValue: TextView
    private lateinit var btnTestVoice: Button
    private lateinit var radioGroupTheme: RadioGroup
    private lateinit var radioGroupFontSize: RadioGroup
    private lateinit var btnSaveSettings: Button

    private var selectedColorScheme: Int = AppPreferences.COLOR_SCHEME_PURPLE

    override fun onCreate(savedInstanceState: Bundle?) {
        prefs = AppPreferences(this)
        // Apply color scheme before setContentView
        applyColorScheme(prefs.colorScheme)

        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        tts = TextToSpeech(this, this)

        setupViews()
        loadSettings()
    }

    private fun applyColorScheme(scheme: Int) {
        val themeId = when (scheme) {
            AppPreferences.COLOR_SCHEME_DARK_PURPLE -> R.style.Theme_ScriptureAlarm_DarkPurple
            AppPreferences.COLOR_SCHEME_BLUE -> R.style.Theme_ScriptureAlarm_Blue
            AppPreferences.COLOR_SCHEME_DARK_BLUE -> R.style.Theme_ScriptureAlarm_DarkBlue
            AppPreferences.COLOR_SCHEME_GREEN -> R.style.Theme_ScriptureAlarm_Green
            AppPreferences.COLOR_SCHEME_DARK_GREEN -> R.style.Theme_ScriptureAlarm_DarkGreen
            AppPreferences.COLOR_SCHEME_ORANGE -> R.style.Theme_ScriptureAlarm_Orange
            AppPreferences.COLOR_SCHEME_DARK_ORANGE -> R.style.Theme_ScriptureAlarm_DarkOrange
            AppPreferences.COLOR_SCHEME_PINK -> R.style.Theme_ScriptureAlarm_Pink
            AppPreferences.COLOR_SCHEME_TEAL -> R.style.Theme_ScriptureAlarm_Teal
            else -> R.style.Theme_ScriptureAlarm // Purple default
        }
        setTheme(themeId)
    }

    private fun setupViews() {
        editName = findViewById(R.id.editName)
        spinnerVoice = findViewById(R.id.spinnerVoice)
        seekBarSpeed = findViewById(R.id.seekBarSpeed)
        seekBarPitch = findViewById(R.id.seekBarPitch)
        textSpeedValue = findViewById(R.id.textSpeedValue)
        textPitchValue = findViewById(R.id.textPitchValue)
        btnTestVoice = findViewById(R.id.btnTestVoice)
        radioGroupTheme = findViewById(R.id.radioGroupTheme)
        radioGroupFontSize = findViewById(R.id.radioGroupFontSize)
        btnSaveSettings = findViewById(R.id.btnSaveSettings)

        // Speed slider (0.5x to 1.5x)
        seekBarSpeed.setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
            override fun onProgressChanged(seekBar: SeekBar?, progress: Int, fromUser: Boolean) {
                val speed = 0.5f + (progress / 100f)
                textSpeedValue.text = String.format("%.1fx", speed)
            }
            override fun onStartTrackingTouch(seekBar: SeekBar?) {}
            override fun onStopTrackingTouch(seekBar: SeekBar?) {}
        })

        // Pitch slider (0.5 to 1.5)
        seekBarPitch.setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
            override fun onProgressChanged(seekBar: SeekBar?, progress: Int, fromUser: Boolean) {
                val pitch = 0.5f + (progress / 100f)
                textPitchValue.text = String.format("%.1f", pitch)
            }
            override fun onStartTrackingTouch(seekBar: SeekBar?) {}
            override fun onStopTrackingTouch(seekBar: SeekBar?) {}
        })

        btnTestVoice.setOnClickListener {
            testVoice()
        }

        // Color scheme buttons - Light themes
        findViewById<ImageButton>(R.id.btnColorPurple).setOnClickListener {
            selectedColorScheme = AppPreferences.COLOR_SCHEME_PURPLE
            highlightSelectedColor()
        }
        findViewById<ImageButton>(R.id.btnColorBlue).setOnClickListener {
            selectedColorScheme = AppPreferences.COLOR_SCHEME_BLUE
            highlightSelectedColor()
        }
        findViewById<ImageButton>(R.id.btnColorGreen).setOnClickListener {
            selectedColorScheme = AppPreferences.COLOR_SCHEME_GREEN
            highlightSelectedColor()
        }
        findViewById<ImageButton>(R.id.btnColorOrange).setOnClickListener {
            selectedColorScheme = AppPreferences.COLOR_SCHEME_ORANGE
            highlightSelectedColor()
        }
        findViewById<ImageButton>(R.id.btnColorPink).setOnClickListener {
            selectedColorScheme = AppPreferences.COLOR_SCHEME_PINK
            highlightSelectedColor()
        }

        // Color scheme buttons - Dark themes
        findViewById<ImageButton>(R.id.btnColorDarkPurple).setOnClickListener {
            selectedColorScheme = AppPreferences.COLOR_SCHEME_DARK_PURPLE
            highlightSelectedColor()
        }
        findViewById<ImageButton>(R.id.btnColorDarkBlue).setOnClickListener {
            selectedColorScheme = AppPreferences.COLOR_SCHEME_DARK_BLUE
            highlightSelectedColor()
        }
        findViewById<ImageButton>(R.id.btnColorDarkGreen).setOnClickListener {
            selectedColorScheme = AppPreferences.COLOR_SCHEME_DARK_GREEN
            highlightSelectedColor()
        }
        findViewById<ImageButton>(R.id.btnColorDarkOrange).setOnClickListener {
            selectedColorScheme = AppPreferences.COLOR_SCHEME_DARK_ORANGE
            highlightSelectedColor()
        }
        findViewById<ImageButton>(R.id.btnColorTeal).setOnClickListener {
            selectedColorScheme = AppPreferences.COLOR_SCHEME_TEAL
            highlightSelectedColor()
        }

        btnSaveSettings.setOnClickListener {
            saveSettings()
        }
    }

    private fun loadSettings() {
        // Load name
        editName.setText(prefs.userName ?: "")

        // Load speed (convert 0.5-1.5 to 0-100)
        val speedProgress = ((prefs.speechRate - 0.5f) * 100).toInt()
        seekBarSpeed.progress = speedProgress.coerceIn(0, 100)
        textSpeedValue.text = String.format("%.1fx", prefs.speechRate)

        // Load pitch
        val pitchProgress = ((prefs.speechPitch - 0.5f) * 100).toInt()
        seekBarPitch.progress = pitchProgress.coerceIn(0, 100)
        textPitchValue.text = String.format("%.1f", prefs.speechPitch)

        // Load theme
        when (prefs.themeMode) {
            AppPreferences.THEME_SYSTEM -> findViewById<RadioButton>(R.id.radioThemeSystem).isChecked = true
            AppPreferences.THEME_LIGHT -> findViewById<RadioButton>(R.id.radioThemeLight).isChecked = true
            AppPreferences.THEME_DARK -> findViewById<RadioButton>(R.id.radioThemeDark).isChecked = true
        }

        // Load color scheme
        selectedColorScheme = prefs.colorScheme
        highlightSelectedColor()

        // Load font size
        when (prefs.fontSize) {
            AppPreferences.FONT_SIZE_SMALL -> findViewById<RadioButton>(R.id.radioFontSmall).isChecked = true
            AppPreferences.FONT_SIZE_LARGE -> findViewById<RadioButton>(R.id.radioFontLarge).isChecked = true
            else -> findViewById<RadioButton>(R.id.radioFontMedium).isChecked = true
        }
    }

    private fun highlightSelectedColor() {
        val buttons = listOf(
            // Light themes
            R.id.btnColorPurple to AppPreferences.COLOR_SCHEME_PURPLE,
            R.id.btnColorBlue to AppPreferences.COLOR_SCHEME_BLUE,
            R.id.btnColorGreen to AppPreferences.COLOR_SCHEME_GREEN,
            R.id.btnColorOrange to AppPreferences.COLOR_SCHEME_ORANGE,
            R.id.btnColorPink to AppPreferences.COLOR_SCHEME_PINK,
            // Dark themes
            R.id.btnColorDarkPurple to AppPreferences.COLOR_SCHEME_DARK_PURPLE,
            R.id.btnColorDarkBlue to AppPreferences.COLOR_SCHEME_DARK_BLUE,
            R.id.btnColorDarkGreen to AppPreferences.COLOR_SCHEME_DARK_GREEN,
            R.id.btnColorDarkOrange to AppPreferences.COLOR_SCHEME_DARK_ORANGE,
            R.id.btnColorTeal to AppPreferences.COLOR_SCHEME_TEAL
        )

        buttons.forEach { (id, scheme) ->
            val btn = findViewById<ImageButton>(id)
            btn.alpha = if (scheme == selectedColorScheme) 1.0f else 0.4f
            btn.scaleX = if (scheme == selectedColorScheme) 1.2f else 1.0f
            btn.scaleY = if (scheme == selectedColorScheme) 1.2f else 1.0f
        }
    }

    override fun onInit(status: Int) {
        Log.d("SettingsTTS", "onInit called with status: $status")
        if (status == TextToSpeech.SUCCESS) {
            Log.d("SettingsTTS", "TTS init SUCCESS")
            val result = tts?.setLanguage(Locale.US)
            Log.d("SettingsTTS", "setLanguage result: $result")
            if (result == TextToSpeech.LANG_MISSING_DATA || result == TextToSpeech.LANG_NOT_SUPPORTED) {
                Toast.makeText(this, "English language not supported on this device", Toast.LENGTH_LONG).show()
                return
            }

            isTtsReady = true
            Log.d("SettingsTTS", "isTtsReady set to true")

            // Get available English voices (including high-quality network voices)
            availableVoices = tts?.voices?.filter {
                it.locale.language == "en"
            }?.sortedByDescending { it.quality }?.sortedBy { it.isNetworkConnectionRequired } ?: emptyList()

            // Create friendly voice names
            val voiceNames = if (availableVoices.isNotEmpty()) {
                availableVoices.mapIndexed { index, voice ->
                    val country = when (voice.locale.country) {
                        "US" -> "American"
                        "GB" -> "British"
                        "AU" -> "Australian"
                        "IN" -> "Indian"
                        else -> voice.locale.displayCountry
                    }
                    val quality = if (voice.quality >= Voice.QUALITY_HIGH) "HD" else ""
                    val network = if (voice.isNetworkConnectionRequired) "[Online]" else ""
                    "Voice ${index + 1} ($country) $quality $network".trim()
                }
            } else {
                listOf("Default Voice")
            }

            runOnUiThread {
                val adapter = ArrayAdapter(this, R.layout.spinner_item, voiceNames)
                adapter.setDropDownViewResource(R.layout.spinner_dropdown_item)
                spinnerVoice.adapter = adapter

                // Select saved voice
                val savedVoiceName = prefs.voiceName
                if (savedVoiceName != null) {
                    val index = availableVoices.indexOfFirst { it.name == savedVoiceName }
                    if (index >= 0) {
                        spinnerVoice.setSelection(index)
                    }
                }
            }
        } else {
            Toast.makeText(this, "Text-to-speech not available on this device", Toast.LENGTH_LONG).show()
        }
    }

    private fun testVoice() {
        Log.d("SettingsTTS", "testVoice() called, isTtsReady=$isTtsReady, tts=$tts")
        if (!isTtsReady) {
            Toast.makeText(this, "Voice is still loading, please wait...", Toast.LENGTH_SHORT).show()
            return
        }

        tts?.let { engine ->
            val speed = 0.5f + (seekBarSpeed.progress / 100f)
            val pitch = 0.5f + (seekBarPitch.progress / 100f)
            Log.d("SettingsTTS", "Speed: $speed, Pitch: $pitch")

            engine.setSpeechRate(speed)
            engine.setPitch(pitch)

            if (availableVoices.isNotEmpty() && spinnerVoice.selectedItemPosition < availableVoices.size) {
                val selectedVoice = availableVoices[spinnerVoice.selectedItemPosition]
                Log.d("SettingsTTS", "Setting voice: ${selectedVoice.name}")
                engine.voice = selectedVoice
            }

            Toast.makeText(this, "Playing test...", Toast.LENGTH_SHORT).show()

            val speakResult = engine.speak(
                "Good morning. The Lord is my shepherd, I shall not want. He makes me lie down in green pastures.",
                TextToSpeech.QUEUE_FLUSH,
                null,
                "test_${System.currentTimeMillis()}"
            )
            Log.d("SettingsTTS", "speak() returned: $speakResult (0=SUCCESS, -1=ERROR)")
        } ?: run {
            Log.d("SettingsTTS", "tts is null!")
            Toast.makeText(this, "Voice not ready yet", Toast.LENGTH_SHORT).show()
        }
    }

    private fun saveSettings() {
        // Save name
        val name = editName.text.toString().trim()
        prefs.userName = if (name.isNotEmpty()) name else null

        // Save voice settings
        prefs.speechRate = 0.5f + (seekBarSpeed.progress / 100f)
        prefs.speechPitch = 0.5f + (seekBarPitch.progress / 100f)

        if (availableVoices.isNotEmpty() && spinnerVoice.selectedItemPosition < availableVoices.size) {
            prefs.voiceName = availableVoices[spinnerVoice.selectedItemPosition].name
        }

        // Save theme
        prefs.themeMode = when (radioGroupTheme.checkedRadioButtonId) {
            R.id.radioThemeSystem -> AppPreferences.THEME_SYSTEM
            R.id.radioThemeLight -> AppPreferences.THEME_LIGHT
            R.id.radioThemeDark -> AppPreferences.THEME_DARK
            else -> AppPreferences.THEME_SYSTEM
        }

        // Apply theme immediately
        when (prefs.themeMode) {
            AppPreferences.THEME_LIGHT -> AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_NO)
            AppPreferences.THEME_DARK -> AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES)
            else -> AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM)
        }

        // Save color scheme
        prefs.colorScheme = selectedColorScheme

        // Save font size
        prefs.fontSize = when (radioGroupFontSize.checkedRadioButtonId) {
            R.id.radioFontSmall -> AppPreferences.FONT_SIZE_SMALL
            R.id.radioFontLarge -> AppPreferences.FONT_SIZE_LARGE
            else -> AppPreferences.FONT_SIZE_MEDIUM
        }

        Toast.makeText(this, "Settings saved! Restart app to see changes.", Toast.LENGTH_LONG).show()
        finish()
    }

    override fun onDestroy() {
        tts?.stop()
        tts?.shutdown()
        super.onDestroy()
    }
}
