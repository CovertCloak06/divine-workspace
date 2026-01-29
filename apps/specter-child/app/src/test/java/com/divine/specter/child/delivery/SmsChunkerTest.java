package com.divine.specter.child.delivery;

import org.junit.Test;
import org.junit.runner.RunWith;
import static org.junit.Assert.*;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.io.File;
import java.io.FileOutputStream;
import java.util.List;
import java.util.Random;

/**
 * Unit tests for SMS APK Chunking
 */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 28)
public class SmsChunkerTest {

    @Test
    public void testChunkAndReassemble() throws Exception {
        System.out.println("\n=== Test: Chunk and Reassemble ===");

        // Create test APK (100KB with valid ZIP header)
        File testApk = File.createTempFile("test", ".apk");
        byte[] originalData = new byte[1024 * 100]; // 100KB
        new Random(12345).nextBytes(originalData);

        // Write ZIP header
        originalData[0] = 0x50; originalData[1] = 0x4B;
        originalData[2] = 0x03; originalData[3] = 0x04;

        FileOutputStream fos = new FileOutputStream(testApk);
        fos.write(originalData);
        fos.close();

        System.out.println("Created test APK: " + testApk.getPath());
        System.out.println("Size: " + originalData.length + " bytes");

        // Chunk the APK
        List<SmsChunker.ChunkInfo> chunks = SmsChunker.chunkApk(testApk);

        assertNotNull(chunks);
        assertTrue(chunks.size() > 0);

        System.out.println("Created " + chunks.size() + " chunks");

        // Create collection and reassemble
        SmsChunker.ChunkCollection collection = SmsChunker.createCollection(chunks.size());

        for (SmsChunker.ChunkInfo chunk : chunks) {
            byte[] chunkData = SmsChunker.decodeChunk(chunk);
            assertNotNull(chunkData);
            collection.addChunk(chunk.chunkNumber, chunkData);
        }

        assertTrue(collection.isComplete());

        // Reassemble
        byte[] reassembled = collection.reassemble();

        // Verify
        assertEquals(originalData.length, reassembled.length);
        assertArrayEquals(originalData, reassembled);
        assertTrue(SmsChunker.isValidApk(reassembled));

        System.out.println("✓ Chunking and reassembly PASSED!");
        testApk.delete();
    }

    @Test
    public void testChunkParsing() {
        System.out.println("\n=== Test: Chunk Parsing ===");

        String testMessage = "SPK:1/10:dGVzdGRhdGE=";
        SmsChunker.ChunkInfo chunk = SmsChunker.parseChunk(testMessage);

        assertNotNull(chunk);
        assertEquals(1, chunk.chunkNumber);
        assertEquals(10, chunk.totalChunks);
        assertEquals("dGVzdGRhdGE=", chunk.base64Data);

        byte[] decoded = SmsChunker.decodeChunk(chunk);
        assertEquals("testdata", new String(decoded));

        System.out.println("✓ Chunk parsing PASSED!");
    }

    @Test
    public void testInvalidChunks() {
        System.out.println("\n=== Test: Invalid Chunk Detection ===");

        assertNull(SmsChunker.parseChunk("INVALID"));
        assertNull(SmsChunker.parseChunk("SPK:invalid"));
        assertNull(SmsChunker.parseChunk("SPK:1/10"));
        assertNull(SmsChunker.parseChunk(null));

        System.out.println("✓ Invalid chunk detection PASSED!");
    }

    @Test
    public void testDuplicateChunks() {
        System.out.println("\n=== Test: Duplicate Chunk Handling ===");

        SmsChunker.ChunkCollection collection = SmsChunker.createCollection(5);
        byte[] testData = "test".getBytes();

        boolean added1 = collection.addChunk(1, testData);
        boolean added2 = collection.addChunk(1, testData); // Duplicate

        assertTrue(added1);
        assertFalse(added2);

        System.out.println("✓ Duplicate chunk handling PASSED!");
    }

    @Test
    public void testMissingChunks() {
        System.out.println("\n=== Test: Missing Chunk Detection ===");

        SmsChunker.ChunkCollection collection = SmsChunker.createCollection(5);
        byte[] testData = "test".getBytes();

        collection.addChunk(1, testData);
        collection.addChunk(2, testData);
        collection.addChunk(4, testData);

        assertFalse(collection.isComplete());

        List<Integer> missing = collection.getMissingChunks();
        assertEquals(2, missing.size());
        assertTrue(missing.contains(3));
        assertTrue(missing.contains(5));

        System.out.println("Missing chunks: " + missing);
        System.out.println("✓ Missing chunk detection PASSED!");
    }

    @Test
    public void testApkValidation() {
        System.out.println("\n=== Test: APK Validation ===");

        byte[] validApk = new byte[100];
        validApk[0] = 0x50; validApk[1] = 0x4B;
        validApk[2] = 0x03; validApk[3] = 0x04;
        assertTrue(SmsChunker.isValidApk(validApk));

        byte[] invalidApk = new byte[] {0x00, 0x01, 0x02, 0x03};
        assertFalse(SmsChunker.isValidApk(invalidApk));

        assertFalse(SmsChunker.isValidApk(null));

        System.out.println("✓ APK validation PASSED!");
    }
}
