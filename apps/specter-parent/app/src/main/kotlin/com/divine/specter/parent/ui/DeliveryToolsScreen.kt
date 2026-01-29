package com.divine.specter.parent.ui

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.Context
import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.io.File

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeliveryToolsScreen(
    apkFile: File,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    var deliveryMethod by remember { mutableStateOf<DeliveryMethod?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Delivery Tools") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, "Back")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color(0xFF1A1A1A),
                    titleContentColor = Color.White,
                    navigationIconContentColor = Color.White
                )
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .background(Color(0xFF0F0F0F))
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item {
                DeliveryMethodCard(
                    icon = Icons.Default.Message,
                    title = "SMS Delivery",
                    description = "Send APK via SMS chunks (no internet required)",
                    color = Color(0xFF00FF88),
                    onClick = { deliveryMethod = DeliveryMethod.SMS }
                )
            }

            item {
                DeliveryMethodCard(
                    icon = Icons.Default.Bluetooth,
                    title = "Bluetooth Transfer",
                    description = "Direct transfer via Bluetooth (requires pairing)",
                    color = Color(0xFF00CCFF),
                    onClick = { deliveryMethod = DeliveryMethod.BLUETOOTH }
                )
            }

            item {
                DeliveryMethodCard(
                    icon = Icons.Default.Cloud,
                    title = "HTTP Binary Update",
                    description = "Over-the-air encrypted APK distribution",
                    color = Color(0xFFFF8800),
                    onClick = { deliveryMethod = DeliveryMethod.HTTP }
                )
            }

            item {
                Spacer(Modifier.height(16.dp))
                InfoCard(apkFile)
            }
        }
    }

    // Delivery dialogs
    when (deliveryMethod) {
        DeliveryMethod.SMS -> SmsDeliveryDialog(apkFile) { deliveryMethod = null }
        DeliveryMethod.BLUETOOTH -> BluetoothDeliveryDialog(context, apkFile) { deliveryMethod = null }
        DeliveryMethod.HTTP -> HttpDeliveryDialog { deliveryMethod = null }
        null -> {}
    }
}

enum class DeliveryMethod {
    SMS, BLUETOOTH, HTTP
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeliveryMethodCard(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    description: String,
    color: Color,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        onClick = onClick,
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF1A1A1A)
        ),
        shape = RoundedCornerShape(12.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                icon,
                contentDescription = null,
                modifier = Modifier.size(48.dp),
                tint = color
            )
            Spacer(Modifier.width(16.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    title,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color.White
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    description,
                    fontSize = 13.sp,
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
}

@Composable
fun InfoCard(apkFile: File) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF1A1A1A).copy(alpha = 0.5f)
        ),
        shape = RoundedCornerShape(8.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Info, null, tint = Color(0xFF00CCFF))
                Spacer(Modifier.width(8.dp))
                Text("APK Information", fontWeight = FontWeight.Bold, color = Color.White)
            }
            Spacer(Modifier.height(12.dp))
            DeliveryInfoRow("File", apkFile.name)
            DeliveryInfoRow("Size", "${apkFile.length() / 1024 / 1024} MB")
            DeliveryInfoRow("Status", if (apkFile.exists()) "Ready" else "Not found")
        }
    }
}

@Composable
private fun DeliveryInfoRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, fontSize = 13.sp, color = Color.Gray)
        Text(value, fontSize = 13.sp, color = Color.White, fontWeight = FontWeight.Medium)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SmsDeliveryDialog(apkFile: File, onDismiss: () -> Unit) {
    var phoneNumber by remember { mutableStateOf("") }
    var isSending by remember { mutableStateOf(false) }
    var progress by remember { mutableStateOf(0f) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("SMS Delivery") },
        text = {
            Column {
                Text("Enter target phone number:")
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = phoneNumber,
                    onValueChange = { phoneNumber = it },
                    label = { Text("Phone Number") },
                    placeholder = { Text("+1234567890") },
                    singleLine = true
                )
                if (isSending) {
                    Spacer(Modifier.height(16.dp))
                    LinearProgressIndicator(
                        progress = progress,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Text(
                        "Sending ${(progress * 100).toInt()}%...",
                        fontSize = 12.sp,
                        color = Color.Gray
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    isSending = true
                    // TODO: Wire to SmsApkSender
                    // SmsApkSender.send(apkFile, phoneNumber) { p -> progress = p }
                },
                enabled = phoneNumber.isNotBlank() && !isSending
            ) {
                Text("Send")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BluetoothDeliveryDialog(context: Context, apkFile: File, onDismiss: () -> Unit) {
    var isServerRunning by remember { mutableStateOf(false) }
    var connectedDevice by remember { mutableStateOf<String?>(null) }

    val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    val bluetoothAdapter = bluetoothManager.adapter

    val enableBluetoothLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { /* Bluetooth enabled */ }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Bluetooth Transfer") },
        text = {
            Column {
                if (bluetoothAdapter == null) {
                    Text("Bluetooth not supported on this device")
                } else if (!bluetoothAdapter.isEnabled) {
                    Text("Please enable Bluetooth first")
                    Spacer(Modifier.height(12.dp))
                    Button(
                        onClick = {
                            val enableBtIntent = Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE)
                            enableBluetoothLauncher.launch(enableBtIntent)
                        }
                    ) {
                        Text("Enable Bluetooth")
                    }
                } else {
                    Text(
                        if (isServerRunning) "Waiting for connection..."
                        else "Start Bluetooth server to accept connections"
                    )
                    if (connectedDevice != null) {
                        Spacer(Modifier.height(8.dp))
                        Text(
                            "Connected: $connectedDevice",
                            color = Color(0xFF00FF88),
                            fontSize = 12.sp
                        )
                    }
                }
            }
        },
        confirmButton = {
            if (bluetoothAdapter?.isEnabled == true) {
                Button(
                    onClick = {
                        isServerRunning = !isServerRunning
                        if (isServerRunning) {
                            // TODO: Wire to BluetoothServer
                            // BluetoothServer.start(apkFile) { device -> connectedDevice = device }
                        }
                    }
                ) {
                    Text(if (isServerRunning) "Stop Server" else "Start Server")
                }
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Close")
            }
        }
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HttpDeliveryDialog(onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("HTTP Binary Update") },
        text = {
            Column {
                Text("HTTP delivery is automatic via /api/update endpoint.")
                Spacer(Modifier.height(12.dp))
                Text(
                    "Child devices will check for updates and download encrypted APK when available.",
                    fontSize = 13.sp,
                    color = Color.Gray
                )
                Spacer(Modifier.height(16.dp))
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = Color(0xFF1A1A1A)
                    )
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text("Setup:", fontWeight = FontWeight.Bold)
                        Spacer(Modifier.height(8.dp))
                        Text("1. Place child-v2.apk in parent's filesDir", fontSize = 12.sp)
                        Text("2. Update latestVersion in ParentServer.kt", fontSize = 12.sp)
                        Text("3. Restart parent server", fontSize = 12.sp)
                        Text("4. Child auto-downloads on next sync", fontSize = 12.sp)
                    }
                }
            }
        },
        confirmButton = {
            Button(onClick = onDismiss) {
                Text("Got it")
            }
        }
    )
}
