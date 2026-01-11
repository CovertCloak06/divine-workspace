package com.covertcloak.scripturealarm.ui

import android.Manifest
import android.app.AlarmManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageButton
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.covertcloak.scripturealarm.R
import com.covertcloak.scripturealarm.alarm.AlarmScheduler
import com.covertcloak.scripturealarm.data.Alarm
import com.covertcloak.scripturealarm.data.AppPreferences
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.google.android.material.switchmaterial.SwitchMaterial

class MainActivity : AppCompatActivity() {

    private lateinit var recyclerView: RecyclerView
    private lateinit var emptyView: TextView
    private lateinit var fabAdd: FloatingActionButton
    private lateinit var adapter: AlarmAdapter
    private lateinit var prefs: AppPreferences

    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        if (!isGranted) {
            Toast.makeText(this, "Notification permission needed for alarms", Toast.LENGTH_LONG).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        prefs = AppPreferences(this)
        // Apply color scheme before setContentView
        applyColorScheme(prefs.colorScheme)
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        setupViews()
        applyFontSize()
        checkPermissions()
        loadAlarms()
    }

    private fun applyFontSize() {
        val titleSize = when (prefs.fontSize) {
            AppPreferences.FONT_SIZE_SMALL -> 24f
            AppPreferences.FONT_SIZE_LARGE -> 32f
            else -> 28f
        }
        val subtitleSize = when (prefs.fontSize) {
            AppPreferences.FONT_SIZE_SMALL -> 12f
            AppPreferences.FONT_SIZE_LARGE -> 16f
            else -> 14f
        }
        findViewById<TextView>(R.id.textTitle).textSize = titleSize
        findViewById<TextView>(R.id.textSubtitle).textSize = subtitleSize
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

    override fun onResume() {
        super.onResume()
        loadAlarms()
    }

    private fun setupViews() {
        recyclerView = findViewById(R.id.recyclerAlarms)
        emptyView = findViewById(R.id.textEmpty)
        fabAdd = findViewById(R.id.fabAddAlarm)

        adapter = AlarmAdapter(
            onToggle = { alarm, enabled ->
                val updatedAlarm = alarm.copy(enabled = enabled)
                if (enabled) {
                    AlarmScheduler.scheduleAlarm(this, updatedAlarm)
                    Toast.makeText(this, "Alarm set for ${alarm.getTimeString()}", Toast.LENGTH_SHORT).show()
                } else {
                    AlarmScheduler.cancelAlarm(this, alarm)
                }
                AlarmScheduler.saveAlarm(this, updatedAlarm)
            },
            onClick = { alarm ->
                val intent = Intent(this, SetAlarmActivity::class.java)
                intent.putExtra("alarm_id", alarm.id)
                startActivity(intent)
            },
            onDelete = { alarm ->
                AlarmScheduler.cancelAlarm(this, alarm)
                loadAlarms()
            }
        )

        recyclerView.layoutManager = LinearLayoutManager(this)
        recyclerView.adapter = adapter

        fabAdd.setOnClickListener {
            startActivity(Intent(this, SetAlarmActivity::class.java))
        }

        findViewById<ImageButton>(R.id.btnSettings).setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }
    }

    private fun checkPermissions() {
        // Check notification permission (Android 13+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                requestPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }

        // Check exact alarm permission (Android 12+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val alarmManager = getSystemService(Context.ALARM_SERVICE) as AlarmManager
            if (!alarmManager.canScheduleExactAlarms()) {
                Intent(Settings.ACTION_REQUEST_SCHEDULE_EXACT_ALARM).also {
                    startActivity(it)
                }
            }
        }
    }

    private fun loadAlarms() {
        val alarms = AlarmScheduler.getAlarms(this)
        adapter.submitList(alarms)

        if (alarms.isEmpty()) {
            recyclerView.visibility = View.GONE
            emptyView.visibility = View.VISIBLE
        } else {
            recyclerView.visibility = View.VISIBLE
            emptyView.visibility = View.GONE
        }
    }
}

class AlarmAdapter(
    private val onToggle: (Alarm, Boolean) -> Unit,
    private val onClick: (Alarm) -> Unit,
    private val onDelete: (Alarm) -> Unit
) : RecyclerView.Adapter<AlarmAdapter.AlarmViewHolder>() {

    private var alarms: List<Alarm> = emptyList()

    fun submitList(newAlarms: List<Alarm>) {
        alarms = newAlarms
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): AlarmViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_alarm, parent, false)
        return AlarmViewHolder(view)
    }

    override fun onBindViewHolder(holder: AlarmViewHolder, position: Int) {
        holder.bind(alarms[position])
    }

    override fun getItemCount() = alarms.size

    inner class AlarmViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val textTime: TextView = itemView.findViewById(R.id.textTime)
        private val textDays: TextView = itemView.findViewById(R.id.textDays)
        private val textCategory: TextView = itemView.findViewById(R.id.textCategory)
        private val switchEnabled: SwitchMaterial = itemView.findViewById(R.id.switchEnabled)

        fun bind(alarm: Alarm) {
            textTime.text = alarm.getTimeString()
            textDays.text = alarm.getDaysString()
            textCategory.text = alarm.verseCategory.name.replace("_", " ").lowercase()
                .replaceFirstChar { it.uppercase() }
            switchEnabled.isChecked = alarm.enabled

            switchEnabled.setOnCheckedChangeListener { _, isChecked ->
                onToggle(alarm, isChecked)
            }

            itemView.setOnClickListener {
                onClick(alarm)
            }

            itemView.setOnLongClickListener {
                onDelete(alarm)
                true
            }
        }
    }
}
