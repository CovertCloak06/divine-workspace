# Scripture Alarm - Development Notes

## Project Overview
Android alarm clock app that reads Bible verses aloud using Text-to-Speech instead of traditional alarm sounds. Gift for wife.

## Current Status (Jan 9, 2025)

### Core Features
- Alarm scheduling with day-of-week selection
- Text-to-Speech verse reading on alarm trigger
- **Full KJV Bible included** (31,100 verses, 66 books)
- Multiple scripture source options
- Sequential or random verse selection
- Brief vibration before TTS starts
- Full-screen alarm activity with dismiss/repeat
- Gradual volume wake-up (starts at 30%, increases over 30 seconds)
- Personalized greeting with user's name

### Scripture Source Options
- **Curated Categories** - Hand-picked verses (Morning, Encouragement, Psalms, Proverbs, Gospels, General)
- **Full Bible (Random)** - Any verse from entire KJV
- **Old Testament Only** - Genesis through Malachi
- **New Testament Only** - Matthew through Revelation
- **Specific Book** - Choose from 66 books
- **Specific Chapter** - Choose book + chapter (e.g., Psalm 23, Romans 8)

### Settings
- Voice selection (supports HD/Online voices with labels)
- Speech speed slider (0.5x - 1.5x)
- Voice pitch slider
- Test Voice button
- User name for personalized greeting
- Theme mode (System/Light/Dark)
- **10 Color schemes:**
  - Light: Purple, Blue, Green, Orange, Pink
  - Dark: Dark Purple, Dark Blue, Dark Green, Dark Orange, Teal
- Font size options (Small/Medium/Large)

## Key Files
- `ui/MainActivity.kt` - Main alarm list screen
- `ui/SetAlarmActivity.kt` - Create/edit alarm with scripture source selection
- `ui/SettingsActivity.kt` - All app settings (voice, theme, colors, fonts)
- `ui/AlarmActivity.kt` - Full-screen alarm display with verse
- `alarm/AlarmService.kt` - Foreground service that handles TTS playback
- `alarm/AlarmScheduler.kt` - Alarm scheduling and persistence logic
- `alarm/AlarmReceiver.kt` - BroadcastReceiver for alarm triggers
- `data/AppPreferences.kt` - SharedPreferences wrapper for all settings
- `data/BibleDatabase.kt` - SQLite database helper for full KJV Bible
- `data/BibleVerseRepository.kt` - Curated verse collection (35+ verses)
- `assets/kjv_bible.db` - Full KJV Bible SQLite database (5.1MB)

## Theme System
- 10 color themes defined in `res/values/themes.xml`
- Custom attributes in `res/values/attrs.xml`:
  - `appBackgroundColor` - Main app background
  - `alarmBackgroundColor` - Alarm screen background
  - `cardBackgroundColor` - Card/container backgrounds
  - `textPrimaryColor` - Main text color
  - `textSecondaryColor` - Secondary/hint text color
- Layouts use theme attributes (e.g., `?colorPrimary`, `?textPrimaryColor`)
- Theme applied in onCreate before setContentView via `setTheme()`

## Build Commands
```bash
./gradlew assembleDebug
~/platform-tools/adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## GitHub
- Repo: https://github.com/CovertCloak06/scripture-alarm
- Latest release: v1.0.0-beta

## Known Issues / Future Enhancements
1. **Snooze** - Currently just dismisses alarm (TODO: implement proper snooze with reschedule)
2. **Category imagery** - User wants to add images to categories (paused - waiting for images)
3. **Daily reading plans** - Structured reading schedules (planned)
4. **Custom verses** - Let users add their own favorite verses (planned)
5. **Reading options** - Repeat verse, include/exclude reference, intro/outro phrases (planned)
