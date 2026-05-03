package com.divine.specter.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.divine.specter.ui.theme.Cyber
import com.divine.specter.ui.CyberButton
import com.divine.specter.ui.CyberCard
import com.divine.specter.ui.CyberTextField
import java.io.File

/**
 * Delivery Methods Card - SMS, Bluetooth, and Dropper APK deployment
 *
 * Shows available delivery methods for deploying child APK when ADB is not available
 */
@Composable
fun DeliveryMethodsCard(
    apkFile: File?,
    apkSize: String,
    onSendSms: (phoneNumber: String) -> Unit,
    onSendBluetooth: (deviceAddress: String) -> Unit,
    onGenerateDropper: () -> Unit,
    prefilledBluetoothMac: String? = null,
    transferStatus: String? = null
) {
    var selectedMethod by remember { mutableStateOf(if (prefilledBluetoothMac != null) "bluetooth" else "sms") }
    var phoneNumber by remember { mutableStateOf("") }
    var bluetoothAddress by remember(prefilledBluetoothMac) { mutableStateOf(prefilledBluetoothMac ?: "") }

    CyberCard(borderColor = Cyber.Cyan) {
        Column(
            modifier = Modifier
                .padding(16.dp)
                .fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Header
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    Icons.Default.Send,
                    contentDescription = null,
                    tint = Cyber.Cyan,
                    modifier = Modifier.size(24.dp)
                )
                Text(
                    "SMS / BLUETOOTH / DROPPER",
                    style = TextStyle(
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace,
                        color = Cyber.Cyan
                    )
                )
            }

            // Brief description
            Text(
                "Alternative delivery when ADB not available",
                style = TextStyle(
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = Cyber.TextSecondary
                )
            )

            Divider(color = Cyber.Cyan.copy(alpha = 0.3f))

            // Method selector tabs
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                MethodTab(
                    icon = Icons.Default.Sms,
                    label = "SMS",
                    selected = selectedMethod == "sms",
                    onClick = { selectedMethod = "sms" },
                    modifier = Modifier.weight(1f)
                )
                MethodTab(
                    icon = Icons.Default.Bluetooth,
                    label = "BT",
                    selected = selectedMethod == "bluetooth",
                    onClick = { selectedMethod = "bluetooth" },
                    modifier = Modifier.weight(1f)
                )
                MethodTab(
                    icon = Icons.Default.GetApp,
                    label = "DROP",
                    selected = selectedMethod == "dropper",
                    onClick = { selectedMethod = "dropper" },
                    modifier = Modifier.weight(1f)
                )
            }

            Divider(color = Cyber.Cyan.copy(alpha = 0.3f))

            // Method-specific UI
            when (selectedMethod) {
                "sms" -> SmsDeliveryUI(
                    apkSize = apkSize,
                    phoneNumber = phoneNumber,
                    onPhoneNumberChange = { phoneNumber = it },
                    transferStatus = transferStatus,
                    onSend = {
                        if (phoneNumber.isNotBlank()) {
                            onSendSms(phoneNumber)
                        }
                    }
                )

                "bluetooth" -> BluetoothDeliveryUI(
                    apkSize = apkSize,
                    deviceAddress = bluetoothAddress,
                    onDeviceAddressChange = { bluetoothAddress = it },
                    transferStatus = transferStatus,
                    onSend = {
                        if (bluetoothAddress.isNotBlank()) {
                            onSendBluetooth(bluetoothAddress)
                        }
                    }
                )

                "dropper" -> DropperDeliveryUI(
                    apkSize = apkSize,
                    onGenerate = onGenerateDropper
                )
            }
        }
    }
}

/**
 * Simple tab button for delivery method selection.
 */
@Composable
private fun MethodTab(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Surface(
        onClick = onClick,
        modifier = modifier.height(40.dp),
        shape = MaterialTheme.shapes.small,
        color = if (selected) Cyber.Cyan else Cyber.Black,
        border = BorderStroke(
            1.dp,
            if (selected) Cyber.Cyan else Cyber.Cyan.copy(alpha = 0.3f)
        )
    ) {
        Row(
            modifier = Modifier.fillMaxSize(),
            horizontalArrangement = Arrangement.Center,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                icon,
                contentDescription = null,
                tint = if (selected) Cyber.Black else Cyber.Cyan,
                modifier = Modifier.size(16.dp)
            )
            Spacer(Modifier.width(4.dp))
            Text(
                label,
                style = TextStyle(
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace,
                    color = if (selected) Cyber.Black else Cyber.Cyan
                ),
                maxLines = 1
            )
        }
    }
}

@Composable
private fun SmsDeliveryUI(
    apkSize: String,
    phoneNumber: String,
    onPhoneNumberChange: (String) -> Unit,
    transferStatus: String?,
    onSend: () -> Unit
) {
    Column(
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Info
        InfoRow("METHOD", "Chunked SMS (120 bytes/msg)")
        InfoRow("APK_SIZE", apkSize)
        InfoRow("ESTIMATED_SMS", calculateSmsCount(apkSize))

        // Phone number input
        CyberTextField(
            value = phoneNumber,
            onValueChange = onPhoneNumberChange,
            label = "TARGET_PHONE",
            placeholder = "+1234567890"
        )

        // Warning
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                Icons.Default.Warning,
                contentDescription = null,
                tint = Cyber.Orange,
                modifier = Modifier.size(16.dp)
            )
            Text(
                "SMS delivery may be slow. Use for remote deployment only.",
                style = TextStyle(
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = Cyber.Orange
                )
            )
        }

        // Send button
        CyberButton(
            text = "SEND_VIA_SMS",
            onClick = onSend,
            enabled = phoneNumber.isNotBlank(),
            color = Cyber.Magenta
        )

        // Progress
        if (transferStatus != null) {
            Column(
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                LinearProgressIndicator(
                    modifier = Modifier.fillMaxWidth(),
                    color = Cyber.Magenta,
                    trackColor = Cyber.Magenta.copy(alpha = 0.2f)
                )
                Text(
                    transferStatus,
                    style = TextStyle(
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        color = Cyber.Magenta
                    )
                )
            }
        }
    }
}

@Composable
private fun BluetoothDeliveryUI(
    apkSize: String,
    deviceAddress: String,
    onDeviceAddressChange: (String) -> Unit,
    transferStatus: String?,
    onSend: () -> Unit
) {

    Column(
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Info
        InfoRow("METHOD", "Bluetooth RFCOMM")
        InfoRow("APK_SIZE", apkSize)
        InfoRow("TRANSFER_SPEED", "~512 KB/s")
        InfoRow("ESTIMATED_TIME", estimateBluetoothTime(apkSize))

        // Device address input
        CyberTextField(
            value = deviceAddress,
            onValueChange = onDeviceAddressChange,
            label = "TARGET_MAC",
            placeholder = "00:11:22:33:44:55"
        )

        // Info
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                Icons.Default.Info,
                contentDescription = null,
                tint = Cyber.Cyan,
                modifier = Modifier.size(16.dp)
            )
            Text(
                "Devices must be paired first. Range: ~10 meters.",
                style = TextStyle(
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = Cyber.Cyan
                )
            )
        }

        // Send button
        CyberButton(
            text = "SEND_VIA_BLUETOOTH",
            onClick = onSend,
            enabled = deviceAddress.isNotBlank() && transferStatus == null,
            color = Cyber.Cyan
        )

        // Progress
        if (transferStatus != null) {
            Column(
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                LinearProgressIndicator(
                    modifier = Modifier.fillMaxWidth(),
                    color = Cyber.Cyan,
                    trackColor = Cyber.Cyan.copy(alpha = 0.2f)
                )
                Text(
                    transferStatus,
                    style = TextStyle(
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        color = Cyber.Cyan
                    )
                )
            }
        }
    }
}

@Composable
private fun DropperDeliveryUI(
    apkSize: String,
    onGenerate: () -> Unit
) {
    Column(
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Info
        InfoRow("METHOD", "Embedded Dropper APK")
        InfoRow("CHILD_SIZE", apkSize)
        InfoRow("DROPPER_SIZE", estimateDropperSize(apkSize))

        // Description
        Text(
            "Generates minimal dropper app that extracts and installs child APK from assets. Appears as 'System Update' app.",
            style = TextStyle(
                fontSize = 11.sp,
                fontFamily = FontFamily.Monospace,
                color = Cyber.TextSecondary
            )
        )

        // Features list
        Column(
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            FeatureBullet("✓ Single APK install")
            FeatureBullet("✓ Auto-extracts payload")
            FeatureBullet("✓ Legitimate appearance")
            FeatureBullet("✓ Side-loadable via email/web")
        }

        // Generate button
        CyberButton(
            text = "GENERATE_DROPPER",
            onClick = onGenerate,
            color = Cyber.Lime
        )
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            label + ":",
            style = TextStyle(
                fontSize = 10.sp,
                fontFamily = FontFamily.Monospace,
                color = Cyber.TextMuted
            )
        )
        Text(
            value,
            style = TextStyle(
                fontSize = 10.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                color = Cyber.TextPrimary
            )
        )
    }
}

@Composable
private fun FeatureBullet(text: String) {
    Text(
        text,
        style = TextStyle(
            fontSize = 10.sp,
            fontFamily = FontFamily.Monospace,
            color = Cyber.Lime
        )
    )
}

private fun calculateSmsCount(apkSize: String): String {
    // Parse size (e.g., "1.2 MB" -> 1228800 bytes)
    val sizeMb = apkSize.replace(" MB", "").toFloatOrNull() ?: 0f
    val sizeBytes = (sizeMb * 1024 * 1024).toInt()
    val chunks = (sizeBytes / 120.0).toInt() + 1
    return "~$chunks messages"
}

private fun estimateDropperSize(childSize: String): String {
    // Dropper = child APK + small wrapper (~200KB overhead)
    val sizeMb = childSize.replace(" MB", "").toFloatOrNull() ?: 0f
    val totalMb = sizeMb + 0.2f
    return String.format("~%.1f MB", totalMb)
}

private fun estimateBluetoothTime(apkSize: String): String {
    // Bluetooth 2.0: ~512 KB/s theoretical, ~256 KB/s practical
    val sizeMb = apkSize.replace(" MB", "").toFloatOrNull() ?: 0f
    val sizeKb = sizeMb * 1024
    val seconds = (sizeKb / 256).toInt() // 256 KB/s

    return when {
        seconds < 60 -> "~${seconds}s"
        seconds < 3600 -> "~${seconds / 60}m"
        else -> "~${seconds / 3600}h ${(seconds % 3600) / 60}m"
    }
}
