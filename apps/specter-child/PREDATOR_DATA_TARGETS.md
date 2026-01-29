# PREDATOR/ALIEN Data Collection Targets - Reference

**Source:** Cisco Talos Intelligence PREDATOR Analysis
**Date:** 2026-01-28
**Purpose:** Document exact file paths and directories targeted by PREDATOR spyware

---

## Manufacturer Detection

**System Property Used:**
```bash
getprop ro.product.manufacturer
```

**Targeted Manufacturers:**
- Samsung
- Huawei
- Oppo
- Xiaomi

**Purpose:** Different manufacturers store data in different locations. PREDATOR adapts its collection strategy based on manufacturer.

---

## Directory Enumeration Targets

### 1. Messaging (Default SMS/MMS)

```
/data/data/com.samsung.android.messaging
```

**Contains:**
- Samsung Messages app database
- SMS/MMS messages
- Message attachments
- Conversation metadata

---

### 2. Contacts

```
/data/data/com.samsung.android.providers.contacts
/data/data/com.android.providers.contacts
```

**Contains:**
- contacts2.db (main contacts database)
- Contact names, phone numbers, emails
- Contact photos
- Contact sync data

**Database Files:**
```
contacts2.db
contacts2.db-wal (Write-Ahead Log)
contacts2.db-shm (Shared Memory)
```

---

### 3. Media

```
/data/data/com.samsung.android.providers.media
/data/data/com.android.providers.media
/data/data/com.google.android.providers.media
/data/media/0
/data/media
/data/data/com.google.android.providers.media.module
/data/data/com.android.providers.media.module
```

**Contains:**
- Photos, videos, audio files
- Media metadata (timestamps, locations, camera info)
- Thumbnails
- Media store database

**File Types:**
- .jpg, .png, .mp4, .3gp, .mp3, .m4a
- .gif, .webp, .mkv, .avi

---

### 4. Email

```
/data/data/com.samsung.android.email.provider
/data/data/com.google.android.gm (Gmail)
```

**Contains:**
- Email messages (inbox, sent, drafts)
- Email attachments
- Email accounts (addresses, sync settings)
- Contact lists from email

**Gmail Database:**
```
/data/data/com.google.android.gm/databases/EmailProvider.db
/data/data/com.google.android.gm/databases/EmailProviderBody.db
```

---

### 5. Telephony (Calls & SMS)

```
/data/data/com.android.providers.telephony
```

**Contains:**
- mmssms.db (combined SMS/MMS database)
- Call logs
- Carrier messaging data
- APN settings

**Database Files:**
```
mmssms.db
mmssms.db-wal
mmssms.db-shm
telephony.db
```

**Call Logs Database:**
```
/data/data/com.android.providers.contacts/databases/calls.db
/data/data/com.android.providers.contacts/databases/calls.db-wal
/data/data/com.android.providers.contacts/databases/calls.db-shm
/data/data/com.android.providers.contacts/databases/calls.db-journal
```

---

### 6. Social Media Apps

#### Instagram
```
/data/data/com.instagram.android
```
**Contains:**
- Direct messages
- Story views
- Cached photos/videos
- Account session tokens

#### Facebook Messenger
```
/data/data/com.facebook.orca
```
**Contains:**
- Chat messages
- Voice messages
- Cached media
- Contact list

#### Twitter
```
/data/data/com.twitter.android
```
**Contains:**
- Direct messages
- Tweets (cached)
- Media cache
- Session tokens

---

### 7. Messaging Apps

#### WhatsApp
```
/data/data/com.whatsapp
```
**Key Files:**
```
/data/data/com.whatsapp/databases/msgstore.db (messages)
/data/data/com.whatsapp/databases/wa.db (contacts, settings)
/data/data/com.whatsapp/files/key (encryption key)
/data/data/com.whatsapp/shared_prefs/ (settings)
```
**Contains:**
- Chat messages (encrypted)
- Media (photos, videos, voice notes)
- Contact list
- Status updates
- Group chats

#### Telegram
```
/data/data/org.telegram.messenger
```
**Key Files:**
```
/data/data/org.telegram.messenger/files/cache4.db (messages)
/data/data/org.telegram.messenger/cache/ (media cache)
```
**Contains:**
- Chat messages
- Secret chats (if device unlocked)
- Media cache
- Contact list
- Channel subscriptions

#### Signal
```
/data/data/org.thoughtcrime.securesms
```
**Key Files:**
```
/data/data/org.thoughtcrime.securesms/databases/signal.db (messages)
/data/data/org.thoughtcrime.securesms/files/ (attachments)
```
**Contains:**
- Encrypted messages
- Attachments
- Contact list
- Session keys

**Note:** Signal uses strong encryption, but if device is unlocked and spyware has root/Device Owner, databases can be accessed.

#### Viber
```
/data/data/com.viber.voip
```
**Contains:**
- Messages
- Call history
- Media cache
- Contact sync

#### WeChat
```
/data/data/com.tencent.mm
```
**Contains:**
- Messages
- Moments (posts)
- Media cache
- Payment info (encrypted)

#### LINE
```
/data/data/jp.naver.line.android
```
**Contains:**
- Messages
- Stickers
- Timeline posts
- Media cache

#### Skype
```
/data/data/com.skype.raider
```
**Contains:**
- Messages
- Call history
- Contact list
- Media cache

#### Google Messages
```
/data/data/com.google.android.apps.messaging
```
**Contains:**
- SMS/MMS messages
- RCS messages
- Media attachments
- Conversation data

---

### 8. Browser Data

#### Chrome
```
/data/data/com.android.chrome
```
**Key Files:**
```
/data/data/com.android.chrome/app_chrome/Default/History
/data/data/com.android.chrome/app_chrome/Default/Cookies
/data/data/com.android.chrome/app_chrome/Default/Login Data
/data/data/com.android.chrome/app_chrome/Default/Web Data (autofill)
/data/data/com.android.chrome/app_chrome/Default/Bookmarks
```
**Contains:**
- Browsing history
- Cookies
- Saved passwords (encrypted with device credential)
- Autofill data
- Bookmarks
- Download history

---

### 9. WiFi Passwords

```
/data/misc/wifi/.WifiConfigStore.xml
```

**Contains:**
```xml
<WifiConfiguration>
    <string name="SSID">"HomeNetwork"</string>
    <string name="PreSharedKey">"wifi_password_here"</string>
    <string name="KeyMgmt">WPA_PSK</string>
</WifiConfiguration>
```

**Access Required:**
- Root or Device Owner
- File is readable by SYSTEM user only

**PREDATOR Working Copy:**
```
/data/local/tmp/wd/WifiConfigStore.xml
```

---

### 10. ALIEN Working Directory

```
/data/local/tmp/wd/
```

**Purpose:** Staging area for exfiltrated data before transmission to C2

**Contents:**
```
/data/local/tmp/wd/
├── pred.so                    # PREDATOR component
├── fs.db                      # Encrypted SQLite (modules/config)
├── WifiConfigStore.xml        # WiFi passwords
├── contacts2.db               # Copied contacts
├── calls.db                   # Copied call logs
├── mmssms.db                  # Copied SMS/MMS
└── [app_specific_data]/       # Copied app databases
```

**Why /data/local/tmp/?**
- Accessible by SYSTEM user
- Not app-specific (less suspicious)
- Used by many legitimate system processes
- Can be accessed from multiple SELinux contexts

---

## Database File Types

### Write-Ahead Log (.db-wal)
```
Example: contacts2.db-wal
```
**Purpose:**
- SQLite Write-Ahead Logging mode
- Contains recent uncommitted transactions
- Often has data not yet in main .db file

**Why PREDATOR Targets This:**
- May contain very recent data (last few seconds)
- Main .db file might be locked, but .wal can be read
- Provides complete picture when combined with .db

### Shared Memory (.db-shm)
```
Example: contacts2.db-shm
```
**Purpose:**
- Shared memory index for .db-wal file
- Helps SQLite coordinate between processes
- Usually small (32KB header)

**Why PREDATOR Targets This:**
- Required to properly read .db-wal file
- Contains metadata about uncommitted transactions

### Journal (.db-journal)
```
Example: calls.db-journal
```
**Purpose:**
- SQLite rollback journal
- Used for transaction recovery
- Older journaling mode (pre-WAL)

**Why PREDATOR Targets This:**
- May contain data from interrupted transactions
- Some apps still use journal mode instead of WAL

---

## Exfiltration Strategy

### Step 1: Enumerate Directories
```bash
# PREDATOR pseudo-code
manufacturer = getprop("ro.product.manufacturer")

if manufacturer in ["Samsung", "Huawei", "Oppo", "Xiaomi"]:
    for directory in target_directories:
        recursively_copy_files(directory)
```

### Step 2: Copy Database Files
```bash
# Copy all database files and their companions
cp /data/data/com.android.providers.contacts/databases/contacts2.db /data/local/tmp/wd/
cp /data/data/com.android.providers.contacts/databases/contacts2.db-wal /data/local/tmp/wd/
cp /data/data/com.android.providers.contacts/databases/contacts2.db-shm /data/local/tmp/wd/
```

### Step 3: Copy WiFi Config
```bash
cp /data/misc/wifi/.WifiConfigStore.xml /data/local/tmp/wd/WifiConfigStore.xml
```

### Step 4: Exfiltrate
- Package files into encrypted archive
- Upload to C2 server via HTTP/HTTPS
- Delete local copies after successful upload

---

## File Access Requirements

| File/Directory | Minimum Privilege | SELinux Context Required |
|----------------|-------------------|--------------------------|
| `/data/data/com.whatsapp/` | App's UID or root | `u:r:untrusted_app:s0` or higher |
| `/data/data/com.android.providers.telephony/` | SYSTEM or root | `u:r:system_app:s0` or higher |
| `/data/misc/wifi/` | SYSTEM or root | `u:r:system_server:s0` |
| `/data/local/tmp/` | shell, SYSTEM, or root | `u:r:shell:s0` or higher |
| `/data/media/0/` | media_rw or root | `u:r:sdcardd:s0` or higher |

**PREDATOR's Access:**
- Kernel exploit (QUAILEGGS) grants root-level access
- Can transition to any SELinux context via zygote injection
- Bypasses all file permission checks

**Specter's Access (with Device Owner):**
- Can grant itself file access permissions
- Can read most app directories via Device Owner privilege
- Cannot access `/data/misc/wifi/` without root (requires SYSTEM UID)
- Can use `ContentProvider` APIs as alternative to direct file access

---

## Database Structure Examples

### contacts2.db Schema
```sql
-- Main contacts table
CREATE TABLE contacts (
    _id INTEGER PRIMARY KEY,
    display_name TEXT,
    has_phone_number INTEGER,
    times_contacted INTEGER,
    last_time_contacted INTEGER
);

-- Phone numbers
CREATE TABLE phone_lookup (
    _id INTEGER PRIMARY KEY,
    normalized_number TEXT,
    contact_id INTEGER
);

-- Raw contacts (per account)
CREATE TABLE raw_contacts (
    _id INTEGER PRIMARY KEY,
    contact_id INTEGER,
    account_name TEXT,
    account_type TEXT
);
```

### mmssms.db Schema
```sql
-- SMS messages
CREATE TABLE sms (
    _id INTEGER PRIMARY KEY,
    thread_id INTEGER,
    address TEXT,     -- Phone number
    body TEXT,        -- Message content
    date INTEGER,     -- Timestamp
    type INTEGER,     -- 1=inbox, 2=sent
    read INTEGER
);

-- MMS messages
CREATE TABLE pdu (
    _id INTEGER PRIMARY KEY,
    thread_id INTEGER,
    date INTEGER,
    msg_box INTEGER,
    read INTEGER
);

-- MMS parts (attachments)
CREATE TABLE part (
    _id INTEGER PRIMARY KEY,
    mid INTEGER,      -- Message ID
    ct TEXT,          -- Content type (image/jpeg, etc.)
    _data TEXT        -- File path
);
```

### calls.db Schema
```sql
CREATE TABLE calls (
    _id INTEGER PRIMARY KEY,
    number TEXT,
    date INTEGER,
    duration INTEGER,  -- In seconds
    type INTEGER,      -- 1=incoming, 2=outgoing, 3=missed
    name TEXT,
    geocoded_location TEXT
);
```

---

## Comparison: PREDATOR vs Specter Data Collection

| Data Type | PREDATOR Method | Specter Method | Notes |
|-----------|-----------------|----------------|-------|
| **Contacts** | Direct file copy | ContactsContract API | PREDATOR faster, Specter requires permission |
| **SMS/MMS** | Direct database access | TelephonyProvider API | Similar effectiveness |
| **Call Logs** | Direct database access | CallLog API | Similar effectiveness |
| **WhatsApp** | Direct file copy | Cannot access (encrypted) | Both limited by encryption |
| **WiFi Passwords** | Direct XML read | Cannot access (requires root) | PREDATOR advantage |
| **Browser Passwords** | Direct database read | Cannot decrypt | Both limited by device credential encryption |
| **App Data** | Direct directory recursion | Per-app API access | PREDATOR more comprehensive |

---

## Detection Indicators

### File Access Patterns
```
# Unusual access to protected directories
adb logcat | grep "ACCESS DENIED"
adb logcat | grep "/data/data"
```

### Working Directory Artifacts
```bash
# Check for PREDATOR working directory
ls -la /data/local/tmp/wd/

# Expected contents if infected:
# - pred.so (PREDATOR component)
# - fs.db (encrypted modules)
# - Copied database files
```

### Process Indicators
```bash
# Check for injected code in zygote
ps -A | grep zygote
cat /proc/$(pgrep zygote64)/maps | grep -E "pred|alien"
```

### SELinux Denials
```bash
# Check for SELinux violations
dmesg | grep avc
logcat -b events | grep "avc: denied"
```

---

## Mitigation Strategies

### For Users
1. **Keep device updated** - Patches kernel exploits like CVE-2021-1048
2. **Avoid installing from unknown sources** - QR provisioning requires factory reset
3. **Monitor battery/data usage** - Exfiltration causes spikes
4. **Check running services** - Look for suspicious system services
5. **Factory reset if suspected** - Only way to remove kernel-level spyware

### For App Developers
1. **Use Android Keystore** for sensitive data encryption
2. **Implement certificate pinning** to prevent TLS decryption
3. **Detect root/tampering** using SafetyNet/Play Integrity
4. **Encrypt databases** with keys in Android Keystore
5. **Monitor file access** to app directory

### For Security Researchers
1. **Scan for IOCs** (file paths, working directories)
2. **Memory analysis** of zygote process
3. **Network traffic analysis** for C2 communication
4. **Binary analysis** of system libraries for hooks

---

## Legal and Ethical Notes

This document analyzes PREDATOR spyware for **educational and defensive security purposes only**:

1. **Threat Intelligence** - Understanding adversary TTPs
2. **Detection Development** - Building IOCs and signatures
3. **Defensive Research** - Improving Android security
4. **Incident Response** - Investigating compromised devices

**DO NOT:**
- Use this information for unauthorized surveillance
- Target individuals without legal authorization
- Deploy these techniques for malicious purposes

**Authorized Use Cases:**
- Penetration testing with explicit written permission
- Security research in controlled environments
- Law enforcement with proper legal authority
- Defensive security analysis

---

## References

1. **Cisco Talos PREDATOR Analysis:** https://blog.talosintelligence.com/predator-spyware/
2. **Android Data Storage:** https://developer.android.com/training/data-storage
3. **SQLite WAL Mode:** https://www.sqlite.org/wal.html
4. **Android Security Bulletin:** https://source.android.com/security/bulletin

---

**Analysis Date:** 2026-01-28
**Document Version:** 1.0
**Analyzed By:** Security Research Team
**Classification:** Threat Intelligence / Educational
