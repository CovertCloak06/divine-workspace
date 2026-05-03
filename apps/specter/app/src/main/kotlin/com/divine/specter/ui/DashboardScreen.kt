package com.divine.specter.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import com.divine.specter.R
import com.divine.specter.SpecterService
import com.divine.specter.adb.AdbManager
import com.divine.specter.ui.theme.Cyber
import kotlinx.coroutines.launch

@Composable
fun DashboardScreen(
    service: SpecterService?,
    connectionState: AdbManager.ConnectionState,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onNavigateToGuides: () -> Unit = {},
    onSecretMenuActivated: () -> Unit = {}
) {
    val scope = rememberCoroutineScope()
    var commandOutput by remember { mutableStateOf("") }
    var customCommand by remember { mutableStateOf("") }

    // Secret menu tap tracking
    var logoTapCount by remember { mutableIntStateOf(0) }
    var lastTapTime by remember { mutableLongStateOf(0L) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Header with tappable ghost icon (secret menu trigger)
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Ghost icon - tappable for secret menu (no visual feedback)
            Image(
                painter = painterResource(id = R.drawable.ic_launcher_foreground),
                contentDescription = "Spe<ter",
                modifier = Modifier
                    .size(48.dp)
                    .clickable(
                        indication = null,  // No ripple effect
                        interactionSource = remember { MutableInteractionSource() }
                    ) {
                        val now = System.currentTimeMillis()
                        // Reset count if more than 2 seconds since last tap
                        if (now - lastTapTime > 2000) {
                            logoTapCount = 0
                        }
                        lastTapTime = now
                        logoTapCount++

                        if (logoTapCount >= 7) {
                            logoTapCount = 0
                            onSecretMenuActivated()
                        }
                    },
                colorFilter = ColorFilter.tint(MaterialTheme.colorScheme.primary)
            )

            Text(
                text = "Spe<ter",
                fontSize = 24.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.primary
            )
        }
        // Connection Status Card
        ConnectionStatusCard(
            connectionState = connectionState,
            onConnect = onConnect,
            onDisconnect = onDisconnect,
            executionMode = service?.getExecutionMode() ?: "Local Shell"
        )

        // Quick Actions Card
        QuickActionsCard(
            service = service,
            onResult = { commandOutput = it }
        )

        // Guides Card
        GuidesCard(onNavigateToGuides = onNavigateToGuides)

        // Command Input Card
        CommandInputCard(
            command = customCommand,
            onCommandChange = { customCommand = it },
            onExecute = {
                scope.launch {
                    val result = service?.executeCommand(customCommand)
                    commandOutput = result?.output ?: "No output"
                }
            },
            enabled = connectionState is AdbManager.ConnectionState.Connected
        )

        // Output Card
        if (commandOutput.isNotEmpty()) {
            OutputCard(output = commandOutput)
        }
    }
}

@Composable
fun ConnectionStatusCard(
    connectionState: AdbManager.ConnectionState,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    executionMode: String = "Local Shell"
) {
    // Show green border when ADB connected OR in local mode (scripts can always run)
    val borderColor = when (connectionState) {
        is AdbManager.ConnectionState.Connected -> SpecterColors.Connected
        is AdbManager.ConnectionState.Connecting -> SpecterColors.Connecting
        else -> SpecterColors.Secondary // Local mode available
    }

    CyberCard(borderColor = borderColor) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = "// EXECUTION_STATUS",
                    style = cyberTitleStyle(MaterialTheme.colorScheme.primary)
                )

                // Show execution mode (always functional)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Circle,
                        contentDescription = null,
                        tint = SpecterColors.Connected,
                        modifier = Modifier.size(12.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "READY",
                        color = SpecterColors.Connected,
                        style = cyberBodyStyle()
                    )
                }

                // Show mode
                Text(
                    text = "MODE: $executionMode",
                    style = cyberBodyStyle().copy(
                        color = if (connectionState is AdbManager.ConnectionState.Connected)
                            SpecterColors.Connected else SpecterColors.Secondary
                    )
                )
            }

            // Device info if connected via ADB
            if (connectionState is AdbManager.ConnectionState.Connected) {
                Text(
                    text = "DEVICE: ${connectionState.device}",
                    style = cyberBodyStyle()
                )
            }

            // Show ADB status for network connection attempts
            if (connectionState is AdbManager.ConnectionState.Connecting) {
                Text(
                    text = "ADB: Connecting...",
                    style = cyberBodyStyle().copy(color = SpecterColors.Connecting)
                )
            }

            // Error message if ADB error (but local mode still works)
            if (connectionState is AdbManager.ConnectionState.Error) {
                Text(
                    text = "ADB: ${connectionState.message.take(50)}",
                    style = cyberBodyStyle().copy(color = SpecterColors.Warning)
                )
                Text(
                    text = "Scripts running via local shell",
                    style = cyberBodyStyle().copy(color = SpecterColors.Secondary)
                )
            }

            // Connect button (optional - local mode always works)
            if (connectionState !is AdbManager.ConnectionState.Connected) {
                CyberButton(
                    text = "TRY ADB CONNECT",
                    color = MaterialTheme.colorScheme.primary,
                    onClick = onConnect
                )
            } else {
                CyberButton(
                    text = "DISCONNECT ADB",
                    color = SpecterColors.Error,
                    onClick = onDisconnect
                )
            }
        }
    }
}

@Composable
fun QuickActionsCard(
    service: SpecterService?,
    onResult: (String) -> Unit
) {
    val scope = rememberCoroutineScope()

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = SpecterColors.Surface)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                text = "Quick Actions",
                style = MaterialTheme.typography.titleMedium,
                color = SpecterColors.OnSurface
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                QuickActionButton(
                    icon = Icons.Default.Memory,
                    label = "Free RAM",
                    modifier = Modifier.weight(1f),
                    onClick = {
                        scope.launch {
                            service?.getScriptRunner()?.runScript("kill_background_apps")
                            onResult("Background apps killed")
                        }
                    }
                )
                QuickActionButton(
                    icon = Icons.Default.DeleteSweep,
                    label = "Clear Cache",
                    modifier = Modifier.weight(1f),
                    onClick = {
                        scope.launch {
                            service?.getScriptRunner()?.runScript("clear_system_cache")
                            onResult("System cache cleared")
                        }
                    }
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                QuickActionButton(
                    icon = Icons.Default.Info,
                    label = "System Info",
                    modifier = Modifier.weight(1f),
                    onClick = {
                        scope.launch {
                            val result = service?.getScriptRunner()?.runScript("system_info")
                            onResult(result?.results?.joinToString("\n") { it.output } ?: "No info")
                        }
                    }
                )
                QuickActionButton(
                    icon = Icons.Default.Storage,
                    label = "TRIM",
                    modifier = Modifier.weight(1f),
                    onClick = {
                        scope.launch {
                            service?.getScriptRunner()?.runScript("fstrim")
                            onResult("Storage optimized")
                        }
                    }
                )
            }
        }
    }
}

@Composable
fun QuickActionButton(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    OutlinedButton(
        onClick = onClick,
        modifier = modifier,
        colors = ButtonDefaults.outlinedButtonColors(
            contentColor = SpecterColors.Primary
        )
    ) {
        Icon(imageVector = icon, contentDescription = null, modifier = Modifier.size(18.dp))
        Spacer(modifier = Modifier.width(4.dp))
        Text(label, style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
fun CommandInputCard(
    command: String,
    onCommandChange: (String) -> Unit,
    onExecute: () -> Unit,
    enabled: Boolean
) {
    val focusManager = LocalFocusManager.current

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = SpecterColors.Surface)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                text = "Custom Command",
                style = MaterialTheme.typography.titleMedium,
                color = SpecterColors.OnSurface
            )

            OutlinedTextField(
                value = command,
                onValueChange = onCommandChange,
                modifier = Modifier.fillMaxWidth(),
                placeholder = { Text("Enter shell command...") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                keyboardActions = KeyboardActions(
                    onDone = {
                        focusManager.clearFocus()
                        if (command.isNotBlank()) onExecute()
                    }
                ),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = SpecterColors.Primary,
                    unfocusedBorderColor = SpecterColors.SurfaceVariant
                )
            )

            Button(
                onClick = onExecute,
                modifier = Modifier.fillMaxWidth(),
                enabled = command.isNotBlank()
            ) {
                Icon(Icons.Default.Send, contentDescription = null)
                Spacer(modifier = Modifier.width(8.dp))
                Text("Execute")
            }
        }
    }
}

@Composable
fun OutputCard(output: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = SpecterColors.SurfaceVariant)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = "Output",
                style = MaterialTheme.typography.titleMedium,
                color = SpecterColors.OnSurface
            )

            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .background(SpecterColors.Background)
                    .padding(12.dp)
            ) {
                Text(
                    text = output,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = SpecterColors.Secondary
                )
            }
        }
    }
}

@Composable
fun GuidesCard(onNavigateToGuides: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = SpecterColors.Surface)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = "Service Menu Guides",
                        style = MaterialTheme.typography.titleMedium,
                        color = SpecterColors.OnSurface
                    )
                    Text(
                        text = "Learn what you can do in Samsung secret menus",
                        style = MaterialTheme.typography.bodySmall,
                        color = SpecterColors.OnSurface.copy(alpha = 0.7f)
                    )
                }
                Icon(
                    imageVector = Icons.Default.MenuBook,
                    contentDescription = null,
                    tint = SpecterColors.Primary,
                    modifier = Modifier.size(32.dp)
                )
            }

            OutlinedButton(
                onClick = onNavigateToGuides,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = SpecterColors.Primary
                )
            ) {
                Icon(Icons.Default.ArrowForward, contentDescription = null)
                Spacer(modifier = Modifier.width(8.dp))
                Text("View Guides")
            }
        }
    }
}
