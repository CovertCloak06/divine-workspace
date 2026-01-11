package com.covertcloak.scripturealarm.ui

import android.os.Bundle
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.Spinner
import android.widget.TextView
import android.widget.TimePicker
import android.widget.Toast
import android.widget.ToggleButton
import androidx.appcompat.app.AppCompatActivity
import com.covertcloak.scripturealarm.R
import com.covertcloak.scripturealarm.alarm.AlarmScheduler
import com.covertcloak.scripturealarm.data.Alarm
import com.covertcloak.scripturealarm.data.AppPreferences
import com.covertcloak.scripturealarm.data.BibleDatabase
import com.covertcloak.scripturealarm.data.ScriptureSource
import com.covertcloak.scripturealarm.data.VerseCategory
import com.google.android.material.switchmaterial.SwitchMaterial
import java.util.Calendar

class SetAlarmActivity : AppCompatActivity() {

    private lateinit var timePicker: TimePicker
    private lateinit var spinnerScriptureSource: Spinner
    private lateinit var spinnerCategory: Spinner
    private lateinit var spinnerBook: Spinner
    private lateinit var spinnerChapter: Spinner
    private lateinit var textCategory: TextView
    private lateinit var textBook: TextView
    private lateinit var textChapter: TextView
    private lateinit var switchSequential: SwitchMaterial
    private lateinit var btnSave: Button
    private lateinit var btnCancel: Button

    private lateinit var btnSunday: ToggleButton
    private lateinit var btnMonday: ToggleButton
    private lateinit var btnTuesday: ToggleButton
    private lateinit var btnWednesday: ToggleButton
    private lateinit var btnThursday: ToggleButton
    private lateinit var btnFriday: ToggleButton
    private lateinit var btnSaturday: ToggleButton

    private lateinit var bibleDatabase: BibleDatabase
    private var bookNames: List<String> = emptyList()
    private var existingAlarmId: Int = -1

    override fun onCreate(savedInstanceState: Bundle?) {
        // Apply color scheme before setContentView
        applyColorScheme(AppPreferences(this).colorScheme)
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_set_alarm)

        bibleDatabase = BibleDatabase.getInstance(this)
        bookNames = bibleDatabase.getAllBooks().map { it.name }

        setupViews()
        loadExistingAlarm()
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
        timePicker = findViewById(R.id.timePicker)
        spinnerScriptureSource = findViewById(R.id.spinnerScriptureSource)
        spinnerCategory = findViewById(R.id.spinnerCategory)
        spinnerBook = findViewById(R.id.spinnerBook)
        spinnerChapter = findViewById(R.id.spinnerChapter)
        textCategory = findViewById(R.id.textCategory)
        textBook = findViewById(R.id.textBook)
        textChapter = findViewById(R.id.textChapter)
        switchSequential = findViewById(R.id.switchSequential)
        btnSave = findViewById(R.id.btnSave)
        btnCancel = findViewById(R.id.btnCancel)

        btnSunday = findViewById(R.id.btnSunday)
        btnMonday = findViewById(R.id.btnMonday)
        btnTuesday = findViewById(R.id.btnTuesday)
        btnWednesday = findViewById(R.id.btnWednesday)
        btnThursday = findViewById(R.id.btnThursday)
        btnFriday = findViewById(R.id.btnFriday)
        btnSaturday = findViewById(R.id.btnSaturday)

        // Setup scripture source spinner
        val sourceOptions = listOf(
            "Curated Categories",
            "Full Bible (Random)",
            "Old Testament Only",
            "New Testament Only",
            "Specific Book",
            "Specific Chapter"
        )
        val sourceAdapter = ArrayAdapter(this, R.layout.spinner_item, sourceOptions)
        sourceAdapter.setDropDownViewResource(R.layout.spinner_dropdown_item)
        spinnerScriptureSource.adapter = sourceAdapter

        spinnerScriptureSource.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                updateVisibility(position)
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }

        // Setup category spinner
        val categories = VerseCategory.entries.map { category ->
            category.name.replace("_", " ").lowercase().replaceFirstChar { it.uppercase() }
        }
        val categoryAdapter = ArrayAdapter(this, R.layout.spinner_item, categories)
        categoryAdapter.setDropDownViewResource(R.layout.spinner_dropdown_item)
        spinnerCategory.adapter = categoryAdapter

        // Setup book spinner
        val bookAdapter = ArrayAdapter(this, R.layout.spinner_item, bookNames)
        bookAdapter.setDropDownViewResource(R.layout.spinner_dropdown_item)
        spinnerBook.adapter = bookAdapter

        spinnerBook.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                updateChapterSpinner(bookNames[position])
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }

        btnSave.setOnClickListener {
            saveAlarm()
        }

        btnCancel.setOnClickListener {
            finish()
        }
    }

    private fun updateVisibility(sourceIndex: Int) {
        val source = indexToScriptureSource(sourceIndex)

        // Show/hide category selector
        val showCategory = source == ScriptureSource.CATEGORY
        textCategory.visibility = if (showCategory) View.VISIBLE else View.GONE
        spinnerCategory.visibility = if (showCategory) View.VISIBLE else View.GONE

        // Show/hide book selector
        val showBook = source == ScriptureSource.SPECIFIC_BOOK || source == ScriptureSource.SPECIFIC_CHAPTER
        textBook.visibility = if (showBook) View.VISIBLE else View.GONE
        spinnerBook.visibility = if (showBook) View.VISIBLE else View.GONE

        // Show/hide chapter selector
        val showChapter = source == ScriptureSource.SPECIFIC_CHAPTER
        textChapter.visibility = if (showChapter) View.VISIBLE else View.GONE
        spinnerChapter.visibility = if (showChapter) View.VISIBLE else View.GONE

        // Update chapter spinner if book is visible
        if (showBook && bookNames.isNotEmpty()) {
            updateChapterSpinner(bookNames[spinnerBook.selectedItemPosition])
        }
    }

    private fun updateChapterSpinner(bookName: String) {
        val chapterCount = bibleDatabase.getChapterCount(bookName)
        val chapters = (1..chapterCount).map { "Chapter $it" }
        val chapterAdapter = ArrayAdapter(this, R.layout.spinner_item, chapters)
        chapterAdapter.setDropDownViewResource(R.layout.spinner_dropdown_item)
        spinnerChapter.adapter = chapterAdapter
    }

    private fun indexToScriptureSource(index: Int): ScriptureSource {
        return when (index) {
            0 -> ScriptureSource.CATEGORY
            1 -> ScriptureSource.FULL_BIBLE
            2 -> ScriptureSource.OLD_TESTAMENT
            3 -> ScriptureSource.NEW_TESTAMENT
            4 -> ScriptureSource.SPECIFIC_BOOK
            5 -> ScriptureSource.SPECIFIC_CHAPTER
            else -> ScriptureSource.CATEGORY
        }
    }

    private fun scriptureSourceToIndex(source: ScriptureSource): Int {
        return when (source) {
            ScriptureSource.CATEGORY -> 0
            ScriptureSource.FULL_BIBLE -> 1
            ScriptureSource.OLD_TESTAMENT -> 2
            ScriptureSource.NEW_TESTAMENT -> 3
            ScriptureSource.SPECIFIC_BOOK -> 4
            ScriptureSource.SPECIFIC_CHAPTER -> 5
        }
    }

    private fun loadExistingAlarm() {
        existingAlarmId = intent.getIntExtra("alarm_id", -1)

        if (existingAlarmId > 0) {
            val alarms = AlarmScheduler.getAlarms(this)
            val alarm = alarms.find { it.id == existingAlarmId }

            alarm?.let {
                timePicker.hour = it.hour
                timePicker.minute = it.minute

                // Set scripture source
                spinnerScriptureSource.setSelection(scriptureSourceToIndex(it.scriptureSource))

                // Set category
                val categoryIndex = VerseCategory.entries.indexOf(it.verseCategory)
                if (categoryIndex >= 0) {
                    spinnerCategory.setSelection(categoryIndex)
                }

                // Set book
                if (it.selectedBook.isNotEmpty()) {
                    val bookIndex = bookNames.indexOf(it.selectedBook)
                    if (bookIndex >= 0) {
                        spinnerBook.setSelection(bookIndex)
                        // Need to update chapter spinner after book is set
                        spinnerBook.post {
                            updateChapterSpinner(it.selectedBook)
                            if (it.selectedChapter > 0) {
                                spinnerChapter.setSelection(it.selectedChapter - 1)
                            }
                        }
                    }
                }

                switchSequential.isChecked = it.useSequentialVerses

                btnSunday.isChecked = Calendar.SUNDAY in it.daysOfWeek
                btnMonday.isChecked = Calendar.MONDAY in it.daysOfWeek
                btnTuesday.isChecked = Calendar.TUESDAY in it.daysOfWeek
                btnWednesday.isChecked = Calendar.WEDNESDAY in it.daysOfWeek
                btnThursday.isChecked = Calendar.THURSDAY in it.daysOfWeek
                btnFriday.isChecked = Calendar.FRIDAY in it.daysOfWeek
                btnSaturday.isChecked = Calendar.SATURDAY in it.daysOfWeek
            }
        }
    }

    private fun saveAlarm() {
        val hour = timePicker.hour
        val minute = timePicker.minute

        val selectedDays = mutableSetOf<Int>()
        if (btnSunday.isChecked) selectedDays.add(Calendar.SUNDAY)
        if (btnMonday.isChecked) selectedDays.add(Calendar.MONDAY)
        if (btnTuesday.isChecked) selectedDays.add(Calendar.TUESDAY)
        if (btnWednesday.isChecked) selectedDays.add(Calendar.WEDNESDAY)
        if (btnThursday.isChecked) selectedDays.add(Calendar.THURSDAY)
        if (btnFriday.isChecked) selectedDays.add(Calendar.FRIDAY)
        if (btnSaturday.isChecked) selectedDays.add(Calendar.SATURDAY)

        val scriptureSource = indexToScriptureSource(spinnerScriptureSource.selectedItemPosition)
        val categoryIndex = spinnerCategory.selectedItemPosition
        val category = VerseCategory.entries[categoryIndex]

        val selectedBook = if (spinnerBook.selectedItemPosition >= 0 && bookNames.isNotEmpty()) {
            bookNames[spinnerBook.selectedItemPosition]
        } else ""

        val selectedChapter = if (spinnerChapter.selectedItemPosition >= 0) {
            spinnerChapter.selectedItemPosition + 1
        } else 0

        val alarmId = if (existingAlarmId > 0) existingAlarmId else AlarmScheduler.getNextAlarmId(this)

        val alarm = Alarm(
            id = alarmId,
            hour = hour,
            minute = minute,
            enabled = true,
            daysOfWeek = selectedDays,
            verseCategory = category,
            useSequentialVerses = switchSequential.isChecked,
            scriptureSource = scriptureSource,
            selectedBook = selectedBook,
            selectedChapter = selectedChapter
        )

        AlarmScheduler.scheduleAlarm(this, alarm)
        Toast.makeText(this, "Alarm set for ${alarm.getTimeString()}", Toast.LENGTH_SHORT).show()
        finish()
    }
}
