# PREDATOR/ALIEN Spyware - Complete Research Summary

**Vendor:** Intellexa (formerly Cytrox)
**Analyzed By:** Cisco Talos (May 2023)
**Platform:** Android (iOS variants exist)
**Classification:** Commercial Spyware / Mercenary Software
**Research Date:** 2026-01-28

---

## Master Index

### Documentation Created

1. **[PREDATOR_ANALYSIS.md](PREDATOR_ANALYSIS.md)** (21KB)
   - Complete technical analysis
   - Architecture comparison to Specter
   - 9 advanced techniques breakdown
   - Capability matrix
   - IOCs and detection methods

2. **[PREDATOR_DATA_TARGETS.md](PREDATOR_DATA_TARGETS.md)** (19KB)
   - Exact file paths targeted
   - Database structures
   - Directory enumeration patterns
   - Exfiltration strategy

3. **[YAHFA_APP_HIDING_ANALYSIS.md](YAHFA_APP_HIDING_ANALYSIS.md)** (22KB)
   - YAHFA framework deep dive
   - Application hiding mechanism
   - ArtMethod hooking process
   - Memory layout analysis

4. **[DELIVERY_SYSTEM_ANALYSIS.md](DELIVERY_SYSTEM_ANALYSIS.md)** (18KB)
   - Specter's existing delivery methods
   - What was deleted vs what's working
   - SMS, Accessibility, QR provisioning

---

## Executive Summary

### What is PREDATOR/ALIEN?

**PREDATOR** is state-of-the-art commercial spyware sold by Intellexa. It represents the most advanced mobile surveillance platform analyzed to date.

**Two-Component Architecture:**
```
┌─────────────────────────────────────────┐
│ ALIEN (Loader + Worker)                 │
├─────────────────────────────────────────┤
│ • Injected into zygote64 process        │
│ • Sets up hooks and IPC                 │
│ • Downloads PREDATOR from C2            │
│ • Handles low-level operations          │
│ • Bypasses SELinux via process forking  │
└─────────────────────────────────────────┘
                   ↓
┌─────────────────────────────────────────┐
│ PREDATOR (Main Spyware)                 │
├─────────────────────────────────────────┤
│ • PyFrozen (Python + native code)       │
│ • Modular architecture (tcore.py core)  │
│ • Communicates via shared memory        │
│ • Exfiltrates data to C2                │
│ • Updates via encrypted SQLite modules  │
└─────────────────────────────────────────┘
```

---

## Key Technical Innovations

### 1. Kernel Exploit Chain

**QUAILEGGS Exploit:**
- CVE-2021-1048 (Linux kernel code injection)
- Allows injection into privileged processes
- Grants kernel-level memory access

**KMEM Module:**
- Arbitrary kernel memory read/write
- Disable SELinux enforcement
- Modify system state at kernel level

### 2. Process Injection into zygote64

**Why zygote64?**
- Parent of ALL Android applications
- Can transition to any UID and SELinux context
- Survives app launches, crashes, reboots
- Extremely stealthy (no standalone process)

**Injection Method:**
```
Exploit Chain → RCE in privileged process →
ptrace/mmap injection → ALIEN in zygote64 →
Hook ioctl() → Download PREDATOR →
Launch PyFrozen payload
```

### 3. SELinux Context Abuse

**Problem:** Android SELinux prevents direct violations (e.g., zygote can't access network sockets)

**Solution:** Multi-process architecture with shared memory

```
audioserver (ALIEN thread)
    ↓ (records audio via memcpy hooks)
Shared Memory (bypass SELinux restriction)
    ↓
zygote64 (ALIEN main)
    ↓ (reads shared memory)
Shared Memory
    ↓
system_server (PREDATOR thread)
    ↓ (exfiltrates via network)
C2 Server
```

**Result:** Each component operates in its allowed SELinux context, but collectively bypass restrictions.

### 4. ioctl() Hooking (xHook Framework)

**Target:** `libbinder.so` (Android IPC library)

**Hooked Commands:**
- `BINDER_WRITE_READ`
  - `BC_TRANSACTION`
  - `BR_TRANSACTION`
  - `BC_REPLY`
  - `BR_REPLY`

**Purpose:**
- Covert IPC between ALIEN and PREDATOR
- No network traffic (undetectable)
- Hides within legitimate system IPC

### 5. Audio Recording via memcpy Hooking

**Hooked Libraries:**
- `libaudioutils.so` → `memcpy_by_audio_format()`
- `libaudiohal*.so` → `memcpy()`
- `libaudioflinger.so` → `memcpy()`

**Why This Works:**
- All audio data flows through these libraries
- Every audio sample passes through memcpy() calls
- Hook intercepts → copies to spyware buffer → exfiltrates

**Sources Captured:**
- Microphone (ambient recording)
- VOIP calls (WhatsApp, Telegram, Signal audio)
- Phone calls (earpiece audio)

### 6. Application Hiding (YAHFA + DEX Injection)

**YAHFA Framework:** Yet Another Hook Framework for ART

**Embedded DEX:**
- ALIEN contains embedded DEX file (no disk artifact)
- Loaded via `InMemoryDexClassLoader()`
- Plugin: `com.jnative.pluginshideapp`

**Hooked APIs:**
```java
PackageManager.getInstalledApplications()
PackageManager.getInstalledPackages()
PackageManager.queryIntentReceiversInternal()
```

**Filtering Logic:**
```java
// Read /data/system/.0 (hidden packages list)
if (packageName in hiddenPackages) {
    // Don't include in result
}
```

**Effects:**
- Invisible in Settings → Apps
- Not shown by `pm list packages`
- Doesn't auto-start on BOOT_COMPLETED
- Can extend to hide SMS_RECEIVED, CALL_STATE, etc.

### 7. Arbitrary Code Execution

**Injection Target:** `system_server`

**Shellcode Storage:** `/system/fonts/NotoColorEmoji.ttf` (hidden in font file!)

**Injection Flow:**
```c
fork() → ptrace(ATTACH) → mmap(remote memory) →
write(shellcode) → set RIP to shellcode →
ptrace(CONT) → detach
```

**Parameter:** Contents of `/data/system/.0`

**Purpose:**
- Execute arbitrary code in privileged processes
- No app installation required
- Memory-resident (no disk forensics)

### 8. PyFrozen Modular Architecture

**Structure:**
```
PREDATOR ELF Binary
├── Native Code (C/C++)
│   ├── main_exec() - Entry point
│   ├── startPy() - Python runtime
│   └── Audio/IPC native methods
└── Frozen Python Modules
    ├── __main__.py - Bootstrap
    ├── loader.py - Module loader
    ├── tcore.py - Core spyware (MISSING)
    ├── sqlimper.py - Encrypted DB handler
    └── _km.py - Kernel memory access
```

**Update Mechanism:**
- ALIEN downloads `fs.db` (encrypted SQLite)
- PREDATOR's `sqlimper.py` processes it
- New Python modules loaded without re-exploitation
- Encrypted bytecode → decrypt → import

**Advantages:**
- Flexible (add capabilities without recompiling)
- Stealthy (Python harder to reverse)
- Rapid development (write modules in Python)
- Obfuscated (encrypted payloads)

### 9. Certificate Injection (TLS Decryption)

**Target:** User-level CA trust store

**Method:**
```bash
# Write CA certificate
echo "$cert_pem" > /data/misc/user/0/cacerts-added/<hash>.0
chmod 0644 /data/misc/user/0/cacerts-added/<hash>.0
```

**Why User-Level?**
- System-level risky (filesystem remount, device instability)
- User-level sufficient for browser TLS decryption
- No certificate warnings in Chrome/Firefox

**Enables:**
- MITM on HTTPS traffic
- Decrypt Signal, WhatsApp, Telegram web
- Capture credentials, session tokens

---

## Data Collection Targets

### Manufacturer-Specific Targeting

**System Property Check:**
```bash
getprop ro.product.manufacturer
```

**Targeted Brands:**
- Samsung
- Huawei
- Oppo
- Xiaomi

**Why?** Different manufacturers store data in different paths. PREDATOR adapts collection strategy.

### Complete Target List

#### Contacts
```
/data/data/com.android.providers.contacts/databases/contacts2.db
/data/data/com.android.providers.contacts/databases/contacts2.db-wal
/data/data/com.android.providers.contacts/databases/contacts2.db-shm
```

#### SMS/MMS
```
/data/data/com.android.providers.telephony/databases/mmssms.db
/data/data/com.android.providers.telephony/databases/mmssms.db-wal
/data/data/com.android.providers.telephony/databases/mmssms.db-shm
```

#### Call Logs
```
/data/data/com.android.providers.contacts/databases/calls.db
/data/data/com.android.providers.contacts/databases/calls.db-journal
```

#### WiFi Passwords
```
/data/misc/wifi/.WifiConfigStore.xml
```

#### Messaging Apps
```
/data/data/com.whatsapp/databases/msgstore.db
/data/data/org.telegram.messenger/files/cache4.db
/data/data/org.thoughtcrime.securesms/databases/signal.db
/data/data/com.viber.voip/
/data/data/com.tencent.mm/ (WeChat)
/data/data/jp.naver.line.android/ (LINE)
/data/data/com.skype.raider/ (Skype)
```

#### Social Media
```
/data/data/com.instagram.android/
/data/data/com.facebook.orca/
/data/data/com.twitter.android/
```

#### Browser
```
/data/data/com.android.chrome/app_chrome/Default/History
/data/data/com.android.chrome/app_chrome/Default/Cookies
/data/data/com.android.chrome/app_chrome/Default/Login Data
```

#### PREDATOR Working Directory
```
/data/local/tmp/wd/
├── pred.so (PREDATOR component)
├── fs.db (encrypted modules)
├── WifiConfigStore.xml (copied)
├── contacts2.db (copied)
└── [exfiltrated data]
```

### Database File Types

**Write-Ahead Log (.db-wal):**
- Contains recent uncommitted transactions
- May have data not yet in main .db
- Provides complete picture when combined

**Shared Memory (.db-shm):**
- Shared memory index for .wal file
- Required to properly read .wal
- Contains transaction metadata

**Journal (.db-journal):**
- SQLite rollback journal
- Older journaling mode (pre-WAL)
- May contain interrupted transaction data

---

## Comparison: PREDATOR vs Specter

### Architecture

| Feature | PREDATOR | Specter | Gap |
|---------|----------|---------|-----|
| **Components** | 2 (ALIEN + PREDATOR) | 1 (Specter Child) | More modular |
| **Injection** | zygote64 (system process) | Standalone app | More stealthy |
| **Privilege** | Kernel (QUAILEGGS/KMEM) | Device Owner/Accessibility | Higher privilege |
| **Language** | PyFrozen (Python + C) | Kotlin/Java | More flexible |
| **Updates** | Download Python modules | Reinstall APK | Easier updates |

### Capabilities

| Capability | PREDATOR | Specter | Winner |
|------------|----------|---------|--------|
| **SMS Interception** | ✅ BroadcastReceiver hooks | ✅ SmsInterceptor.java | Tie |
| **Call Interception** | ✅ Audio hooks + telephony | ✅ Android telephony API | PREDATOR (covert) |
| **Audio Recording** | ✅ memcpy hooks in audio libs | ✅ MediaRecorder API | PREDATOR (undetectable) |
| **File Exfiltration** | ✅ Direct database access | ✅ ContentProvider APIs | PREDATOR (faster) |
| **App Hiding** | ✅ YAHFA + DEX injection | ❌ Not implemented | PREDATOR |
| **TLS Decryption** | ✅ CA injection | ❌ Not implemented | PREDATOR |
| **Code Injection** | ✅ ptrace/mmap | ❌ Not implemented | PREDATOR |
| **Persistence** | ✅ Injection into zygote | ✅ Boot receiver | PREDATOR (survives more) |
| **QR Provisioning** | ❌ Not documented | ✅ AdminReceiver.java | Specter |
| **Device Owner Setup** | ❌ Manual | ✅ QR auto-config | Specter (easier deployment) |

### Detection Surface

| Metric | PREDATOR | Specter |
|--------|----------|---------|
| **Network Traffic** | Minimal (shared memory IPC) | High (HTTP + Telegram) |
| **Visible Process** | Hidden (injected into zygote) | Visible (standalone app) |
| **File Artifacts** | Few (memory-resident) | More (app directory) |
| **Permission Requests** | None (kernel access) | Many (if not Device Owner) |
| **Detection Difficulty** | Very Hard | Medium |

---

## Techniques Applicable to Specter

### ✅ Can Be Implemented (With Device Owner)

1. **Direct Database Access**
   - Copy database files instead of using ContentProvider APIs
   - Faster and bypasses framework logging
   - Device Owner has file system access

2. **User-Level CA Injection**
   - Add certificates to `/data/misc/user/0/cacerts-added/`
   - Enables TLS decryption of browser traffic
   - Requires Device Owner or root

3. **Modular Architecture**
   - Use `DexClassLoader` to load encrypted DEX modules
   - Store modules in encrypted SQLite database
   - Update capabilities without reinstalling APK

4. **Shared Memory IPC**
   - If implementing multi-component architecture
   - Use `MemoryFile` or native `shm_open()`
   - Reduce network traffic (harder to detect)

### ❌ Cannot Be Implemented (Requires Kernel Access)

1. **Process Injection** - Needs kernel exploit
2. **ioctl() Hooking** - Needs code injection into system_server
3. **YAHFA Application Hiding** - Needs injection into system_server
4. **memcpy Audio Hooking** - Needs injection into audioserver
5. **Kernel Memory Access (KMEM)** - Needs kernel vulnerability

### 🔶 Partially Applicable

1. **PyFrozen-like Updates**
   - Specter can use `DexClassLoader` (not Python)
   - Still provides modularity
   - Encrypted DEX in SQLite

2. **Working Directory Strategy**
   - Specter can use `/data/local/tmp/specter/`
   - Less suspicious than app-specific directory
   - Requires shell or SYSTEM UID access

---

## Research Repositories

### 1. YAHFA Framework
**URL:** https://github.com/PAGalaxyLab/YAHFA
**Purpose:** Android ART method hooking
**Use in PREDATOR:** Application hiding via PackageManager API hooks
**Status:** ✅ Analyzed in YAHFA_APP_HIDING_ANALYSIS.md

### 2. PAGalaxyLab Ghidra Scripts
**URL:** https://github.com/PAGalaxyLab/ghidra_scripts
**Purpose:** Reverse engineering tools
**Contents:**
- OLLVM deobfuscation scripts
- DEX parameter tracing
- Objective-C message send analysis
**Relevance:** General malware analysis (not PREDATOR-specific)

### 3. PAGalaxyLab VulInfo
**URL:** https://github.com/PAGalaxyLab/VulInfo
**Purpose:** Vulnerability research database
**Contents:**
- Router vulnerabilities (D-Link, ASUS, TP-Link, MiWifi)
- JAMF vulnerabilities
**Relevance:** General security research (not PREDATOR-specific)

### 4. Pegasus Samples (Previously Analyzed)
**URL:** https://github.com/byt3n33dl3/EXAPegasus
**Contents:**
- 5 Pegasus APK samples
- Dropper mechanisms (asset extraction)
- SMS exfiltration code
**Status:** ✅ Analyzed in dropper_reconstruction.md

### 5. AndroRAT (Previously Analyzed)
**URL:** https://github.com/androrat-community/AndroRAT
**Contents:**
- Android RAT reference implementation
- TCP connection, SMS reading, screenshot capture
**Status:** ✅ Analyzed in DELIVERY_SYSTEM_ANALYSIS.md

---

## Detection and Mitigation

### For Users

**Detection Indicators:**
1. **Battery drain** - Constant surveillance consumes power
2. **Data usage spikes** - Exfiltration uses network
3. **Device heat** - CPU-intensive hooking/injection
4. **Suspicious files:**
   ```bash
   /data/local/tmp/wd/pred.so
   /data/system/.0
   /data/misc/user/0/cacerts-added/
   ```

**Mitigation:**
1. **Keep device updated** - Patches kernel exploits
2. **Avoid unknown sources** - Don't install from untrusted APKs
3. **Check running processes:** `ps -A | grep zygote`
4. **Factory reset if suspected** - Only way to remove kernel-level spyware

### For Developers

**Protection Strategies:**
1. **Android Keystore** - Encrypt sensitive data
2. **Certificate Pinning** - Prevent TLS decryption
3. **Root Detection** - Use SafetyNet/Play Integrity
4. **Database Encryption** - Encrypt SQLite with Keystore-backed keys
5. **File Access Monitoring** - Detect unusual directory access

### For Security Researchers

**Analysis Methods:**
1. **Memory Forensics:**
   ```bash
   cat /proc/$(pidof zygote64)/maps | grep -E "pred|alien"
   ```
2. **ArtMethod Entry Point Inspection:**
   ```javascript
   // Frida script to check for hooks
   Memory.readU64(artMethodPtr.add(32))
   ```
3. **Network Traffic Analysis:**
   - Capture C2 communication
   - Identify exfiltration patterns
4. **Binary Analysis:**
   - Reverse ALIEN/PREDATOR components
   - Extract IOCs

---

## Indicators of Compromise (IOCs)

### File Paths
```
/data/local/tmp/wd/pred.so
/data/local/tmp/wd/fs.db
/data/local/tmp/wd/WifiConfigStore.xml
/data/system/.0
/system/fonts/NotoColorEmoji.ttf (if shellcode storage)
/data/misc/user/0/cacerts-added/ (injected CAs)
```

### Library Names
```
libalien.so
libpred.so
pred.so
```

### Process Context
```
zygote64 (injection target)
system_server (injection target)
installd (file permission changer)
audioserver (audio recording)
```

### SELinux Contexts
```
u:object_r:shell_data_file:s0 (exfiltrated files)
```

### Network Patterns
- Encrypted SQLite uploads (fs.db)
- Periodic HTTP POSTs to unknown IPs
- TLS connections without valid SNI

---

## Legal and Ethical Framework

### Authorized Use Cases

✅ **ONLY USE FOR:**
- **Penetration Testing** - With explicit written permission
- **CTF Competitions** - Security challenges and education
- **Academic Research** - In controlled lab environments
- **Law Enforcement** - With proper legal authority
- **Defensive Security** - Threat intelligence and tool development
- **Incident Response** - Analyzing compromised devices

### Prohibited Uses

❌ **DO NOT:**
- Deploy for unauthorized surveillance
- Target individuals without consent
- Use for malicious purposes
- Implement without legal authorization
- Share with malicious actors

### Biden-Harris Executive Order (March 27, 2023)

U.S. government **prohibited from using** commercial spyware that:
- Poses national security risks
- Has been misused by foreign actors
- Enables human rights abuses

**Implication:** PREDATOR-class spyware represents technology the U.S. government has deemed too dangerous for its own use.

---

## References

### Primary Sources

1. **Cisco Talos PREDATOR Analysis**
   - https://blog.talosintelligence.com/predator-spyware/
   - Published: May 25, 2023

2. **Google TAG (2021) - Five Zero-Days**
   - CVE-2021-37973, CVE-2021-37976, CVE-2021-38000, CVE-2021-38003 (Chrome)
   - CVE-2021-1048 (Linux/Android kernel)

3. **YAHFA Framework**
   - https://github.com/PAGalaxyLab/YAHFA
   - Introduction: http://rk700.github.io/2017/03/30/YAHFA-introduction/

### Technical References

4. **Android ART Internals**
   - https://source.android.com/docs/core/runtime
   - ArtMethod: http://aosp.opersys.com/xref/android-11.0.0_r17/xref/art/runtime/art_method.h

5. **xHook Library**
   - https://github.com/iqiyi/xHook
   - PLT/GOT hooking for Android

6. **Android SELinux Policy**
   - https://android.googlesource.com/platform/system/sepolicy/
   - zygote policy: private/app_zygote.te

### Related Research

7. **Pegasus (NSO Group)**
   - Zero-click exploit: FORCEDENTRY
   - iOS/Android dual-platform

8. **GhostSpy**
   - Accessibility Service abuse
   - Similar auto-install technique

9. **Biden-Harris Executive Order**
   - March 27, 2023
   - Prohibits U.S. gov use of mercenary spyware

---

## Conclusion

PREDATOR represents the pinnacle of commercial mobile spyware technology:

**Key Innovations:**
1. Two-component architecture (ALIEN + PREDATOR)
2. Kernel-level privilege escalation (QUAILEGGS/KMEM)
3. Process injection into zygote64
4. SELinux bypass via multi-context architecture
5. PyFrozen modularity with encrypted updates
6. Low-level hooking (ioctl, memcpy, YAHFA)
7. Comprehensive data collection (messaging, social, browsers, WiFi)
8. Application hiding and stealth capabilities

**Comparison to Specter:**
- PREDATOR uses kernel exploits; Specter uses Device Owner/Accessibility
- PREDATOR injects into system processes; Specter is standalone app
- PREDATOR has lower detection surface; Specter is more visible
- **Specter has easier deployment** (QR provisioning vs kernel exploitation)

**Applicability:**
- Advanced techniques requiring kernel access are NOT applicable to Specter
- Modular architecture, direct database access, CA injection ARE applicable
- PREDATOR provides threat intelligence for defensive security

**Educational Value:**
This research documents state-of-the-art mobile surveillance for:
- Threat intelligence and awareness
- Detection tool development
- Security researcher education
- Defensive security improvements

---

**Research Compiled:** 2026-01-28
**Total Documentation:** 80KB across 4 comprehensive documents
**Classification:** Threat Intelligence / Educational Research
**Purpose:** Authorized security research and defensive security development
