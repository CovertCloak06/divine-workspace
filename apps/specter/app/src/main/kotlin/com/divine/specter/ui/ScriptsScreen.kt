package com.divine.specter.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.focusable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.divine.specter.PreferencesManager
import com.divine.specter.SpecterService
import com.divine.specter.scripts.BuiltinScripts
import com.divine.specter.scripts.ScriptRunner
import com.divine.specter.scripts.ScriptScheduler
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScriptsScreen(service: SpecterService?) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val preferencesManager = remember { PreferencesManager(context) }

    var selectedCategory by remember { mutableStateOf<BuiltinScripts.Category?>(null) }
    var showAllDevices by remember { mutableStateOf(false) }

    // Detect device type
    val deviceType = remember { BuiltinScripts.detectDeviceType(context) }

    // Script scheduler for periodic maintenance
    val scriptScheduler = remember {
        service?.getScriptRunner()?.let { runner ->
            ScriptScheduler(context, runner, preferencesManager)
        }
    }

    // Get enabled boot scripts from preferences
    val enabledBootScripts by preferencesManager.enabledBuiltinScripts.collectAsState(initial = emptySet())

    val executionLog by service?.getScriptRunner()?.executionLog?.collectAsState()
        ?: remember { mutableStateOf(emptyList()) }

    // Filter scripts by device type and category
    val allScripts = if (showAllDevices) {
        BuiltinScripts.all
    } else {
        BuiltinScripts.getForDevice(deviceType)
    }

    val scripts = if (selectedCategory != null) {
        allScripts.filter { it.category == selectedCategory }
    } else {
        allScripts
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(SpecterColors.Background)
    ) {
        // Device type indicator
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            colors = CardDefaults.cardColors(containerColor = SpecterColors.Surface)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(12.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = when (deviceType) {
                            BuiltinScripts.DeviceType.PHONE -> Icons.Default.Smartphone
                            BuiltinScripts.DeviceType.TABLET -> Icons.Default.Tablet
                            BuiltinScripts.DeviceType.FIRE_TV -> Icons.Default.Tv
                            BuiltinScripts.DeviceType.ANDROID_TV -> Icons.Default.Tv
                            BuiltinScripts.DeviceType.ALL -> Icons.Default.Devices
                        },
                        contentDescription = null,
                        tint = SpecterColors.Primary
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Device: ${deviceType.name.replace("_", " ")}",
                        style = MaterialTheme.typography.bodyMedium,
                        color = SpecterColors.OnSurface
                    )
                }

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = "Show All Devices",
                        style = MaterialTheme.typography.bodySmall,
                        color = SpecterColors.OnSurface.copy(alpha = 0.7f)
                    )
                    Switch(
                        checked = showAllDevices,
                        onCheckedChange = { showAllDevices = it },
                        modifier = Modifier.height(24.dp),
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = SpecterColors.Primary,
                            checkedTrackColor = SpecterColors.Primary.copy(alpha = 0.5f)
                        )
                    )
                }
            }
        }

        // Fire TV Periodic Maintenance Card (only shown for Fire TV devices)
        if (deviceType == BuiltinScripts.DeviceType.FIRE_TV && scriptScheduler != null) {
            FireTvMaintenanceCard(
                preferencesManager = preferencesManager,
                scriptScheduler = scriptScheduler,
                onRunNow = {
                    scope.launch {
                        val script = BuiltinScripts.getById("firetv_maintenance")
                        if (script != null) {
                            service?.getScriptRunner()?.runScript(script)
                        }
                    }
                }
            )
        }

        // Category filter chips
        LazyRow(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            item {
                var isFocused by remember { mutableStateOf(false) }
                FilterChip(
                    selected = selectedCategory == null,
                    onClick = { selectedCategory = null },
                    label = { Text("All") },
                    modifier = Modifier.onFocusChanged { isFocused = it.isFocused },
                    colors = FilterChipDefaults.filterChipColors(
                        containerColor = if (isFocused) SpecterColors.Primary.copy(alpha = 0.3f) else SpecterColors.Surface
                    )
                )
            }

            items(BuiltinScripts.Category.entries.toList()) { category ->
                val count = allScripts.count { it.category == category }
                if (count > 0) {
                    var isFocused by remember { mutableStateOf(false) }
                    FilterChip(
                        selected = selectedCategory == category,
                        onClick = { selectedCategory = category },
                        label = { Text("${category.name.lowercase().replaceFirstChar { it.uppercase() }} ($count)") },
                        modifier = Modifier.onFocusChanged { isFocused = it.isFocused },
                        colors = FilterChipDefaults.filterChipColors(
                            containerColor = if (isFocused) SpecterColors.Primary.copy(alpha = 0.3f) else SpecterColors.Surface
                        )
                    )
                }
            }
        }

        // Scripts list
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            items(scripts) { script ->
                val lastExecution = executionLog.lastOrNull { it.scriptId == script.id }
                val isBootEnabled = enabledBootScripts.contains(script.id)

                ScriptCard(
                    script = script,
                    lastExecution = lastExecution,
                    isBootEnabled = isBootEnabled,
                    onRun = {
                        scope.launch {
                            service?.getScriptRunner()?.runScript(script)
                        }
                    },
                    onToggleBoot = { enabled ->
                        scope.launch {
                            val newSet = if (enabled) {
                                enabledBootScripts + script.id
                            } else {
                                enabledBootScripts - script.id
                            }
                            preferencesManager.setEnabledBuiltinScripts(newSet)
                        }
                    }
                )
            }

            // Empty state
            if (scripts.isEmpty()) {
                item {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(32.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Icon(
                                imageVector = Icons.Default.SearchOff,
                                contentDescription = null,
                                modifier = Modifier.size(48.dp),
                                tint = SpecterColors.OnSurface.copy(alpha = 0.5f)
                            )
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = "No scripts for this device/category",
                                color = SpecterColors.OnSurface.copy(alpha = 0.5f)
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun ScriptCard(
    script: BuiltinScripts.Script,
    lastExecution: ScriptRunner.ScriptExecution?,
    isBootEnabled: Boolean,
    onRun: () -> Unit,
    onToggleBoot: (Boolean) -> Unit
) {
    var isRunning by remember { mutableStateOf(false) }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = SpecterColors.Surface)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            // Header row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(
                            text = script.name,
                            style = MaterialTheme.typography.titleMedium,
                            color = SpecterColors.OnSurface
                        )

                        if (script.dangerous) {
                            Icon(
                                imageVector = Icons.Default.Warning,
                                contentDescription = "Dangerous",
                                tint = SpecterColors.Warning,
                                modifier = Modifier.size(16.dp)
                            )
                        }

                        if (script.requiresRoot) {
                            Icon(
                                imageVector = Icons.Default.AdminPanelSettings,
                                contentDescription = "Requires root",
                                tint = SpecterColors.Error,
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    }

                    Text(
                        text = script.description,
                        style = MaterialTheme.typography.bodySmall,
                        color = SpecterColors.OnSurface.copy(alpha = 0.7f)
                    )
                }

                // Run button
                IconButton(
                    onClick = {
                        isRunning = true
                        onRun()
                    },
                    enabled = !isRunning
                ) {
                    if (isRunning) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(24.dp),
                            strokeWidth = 2.dp
                        )
                    } else {
                        Icon(
                            imageVector = Icons.Default.PlayArrow,
                            contentDescription = "Run",
                            tint = SpecterColors.Primary
                        )
                    }
                }
            }

            // Boot toggle row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Autorenew,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp),
                        tint = if (isBootEnabled) SpecterColors.Primary else SpecterColors.OnSurface.copy(alpha = 0.5f)
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        text = "Run on boot",
                        style = MaterialTheme.typography.bodySmall,
                        color = SpecterColors.OnSurface.copy(alpha = 0.7f)
                    )
                }

                Switch(
                    checked = isBootEnabled,
                    onCheckedChange = onToggleBoot,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = SpecterColors.Primary,
                        checkedTrackColor = SpecterColors.Primary.copy(alpha = 0.5f)
                    )
                )
            }

            // Reset running state when execution completes (outside null guard so it fires on null too)
            LaunchedEffect(lastExecution?.status) {
                if (lastExecution?.status != ScriptRunner.ScriptExecution.Status.RUNNING) {
                    isRunning = false
                }
            }

            // Last execution info
            if (lastExecution != null) {
                var showOutput by remember { mutableStateOf(false) }

                Divider(color = SpecterColors.SurfaceVariant)

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { showOutput = !showOutput },
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    val statusColor = when (lastExecution.status) {
                        ScriptRunner.ScriptExecution.Status.SUCCESS -> SpecterColors.Success
                        ScriptRunner.ScriptExecution.Status.RUNNING -> SpecterColors.Connecting
                        ScriptRunner.ScriptExecution.Status.PARTIAL_FAILURE -> SpecterColors.Warning
                        ScriptRunner.ScriptExecution.Status.FAILED -> SpecterColors.Error
                    }

                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = "Last: ${lastExecution.status.name}",
                            style = MaterialTheme.typography.bodySmall,
                            color = statusColor
                        )

                        if (lastExecution.results.isNotEmpty()) {
                            Icon(
                                imageVector = if (showOutput) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                                contentDescription = if (showOutput) "Hide output" else "Show output",
                                modifier = Modifier.size(16.dp),
                                tint = SpecterColors.OnSurface.copy(alpha = 0.5f)
                            )
                        }
                    }

                    lastExecution.duration?.let { duration ->
                        Text(
                            text = "${duration}ms",
                            style = MaterialTheme.typography.bodySmall,
                            color = SpecterColors.OnSurface.copy(alpha = 0.5f)
                        )
                    }
                }

                // Output display
                if (showOutput && lastExecution.results.isNotEmpty()) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(max = 150.dp)
                            .clip(MaterialTheme.shapes.small)
                            .background(SpecterColors.Background)
                            .padding(8.dp)
                            .verticalScroll(rememberScrollState())
                    ) {
                        Text(
                            text = lastExecution.results.joinToString("\n") { it.output },
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            color = SpecterColors.Secondary
                        )
                    }
                }

            }

            // Commands count
            Text(
                text = "${script.commands.size} command(s)",
                style = MaterialTheme.typography.labelSmall,
                color = SpecterColors.OnSurface.copy(alpha = 0.5f)
            )
        }
    }
}

/**
 * Fire TV Periodic Maintenance Card - Clear labeling for TV
 */
@Composable
fun FireTvMaintenanceCard(
    preferencesManager: PreferencesManager,
    scriptScheduler: ScriptScheduler,
    onRunNow: () -> Unit
) {
    val scope = rememberCoroutineScope()
    val enabled by preferencesManager.periodicMaintenanceEnabled.collectAsState(initial = false)
    val interval by preferencesManager.periodicMaintenanceInterval.collectAsState(initial = 30)

    var showIntervalDropdown by remember { mutableStateOf(false) }
    var isRunningNow by remember { mutableStateOf(false) }

    val intervalOptions = listOf(15, 30, 60, 120)

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 4.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (enabled) SpecterColors.Primary.copy(alpha = 0.15f) else SpecterColors.Surface
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Icon + Label
            Icon(
                imageVector = Icons.Default.CleaningServices,
                contentDescription = null,
                modifier = Modifier.size(24.dp),
                tint = if (enabled) SpecterColors.Primary else SpecterColors.OnSurface
            )
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "Fire TV Auto-Clean",
                    style = MaterialTheme.typography.bodyMedium,
                    color = SpecterColors.OnSurface
                )
                Text(
                    text = if (enabled) "Every ${interval}m: cache + bloatware" else "Clears cache, stops bloatware",
                    style = MaterialTheme.typography.bodySmall,
                    color = SpecterColors.OnSurface.copy(alpha = 0.6f)
                )
            }

            // Interval dropdown
            Box {
                TextButton(
                    onClick = { showIntervalDropdown = true },
                    enabled = enabled,
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Text("${interval}m", style = MaterialTheme.typography.bodySmall)
                    Icon(Icons.Default.ArrowDropDown, null, Modifier.size(16.dp))
                }
                DropdownMenu(
                    expanded = showIntervalDropdown,
                    onDismissRequest = { showIntervalDropdown = false }
                ) {
                    intervalOptions.forEach { option ->
                        DropdownMenuItem(
                            text = { Text("$option min") },
                            onClick = {
                                scope.launch {
                                    preferencesManager.setPeriodicMaintenanceInterval(option)
                                    if (enabled) scriptScheduler.schedulePeriodicMaintenance(option)
                                }
                                showIntervalDropdown = false
                            }
                        )
                    }
                }
            }

            // Toggle
            Switch(
                checked = enabled,
                onCheckedChange = { newEnabled ->
                    scope.launch {
                        preferencesManager.setPeriodicMaintenanceEnabled(newEnabled)
                        if (newEnabled) {
                            scriptScheduler.schedulePeriodicMaintenance(interval)
                        } else {
                            scriptScheduler.cancelPeriodicMaintenance()
                        }
                    }
                },
                colors = SwitchDefaults.colors(
                    checkedThumbColor = SpecterColors.Primary,
                    checkedTrackColor = SpecterColors.Primary.copy(alpha = 0.5f)
                )
            )

            // Run Now button
            IconButton(
                onClick = { isRunningNow = true; onRunNow() },
                enabled = !isRunningNow,
                modifier = Modifier.size(36.dp)
            ) {
                if (isRunningNow) {
                    CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                } else {
                    Icon(Icons.Default.PlayArrow, "Run Now", tint = SpecterColors.Primary)
                }
            }
        }
    }

    LaunchedEffect(isRunningNow) {
        if (isRunningNow) {
            kotlinx.coroutines.delay(5000)
            isRunningNow = false
        }
    }
}
