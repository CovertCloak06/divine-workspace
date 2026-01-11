# Scripture Alarm

An Android alarm clock app that wakes you up with Bible verses instead of traditional alarm tones.

## Features

- **Scripture Wake-Up**: Instead of a jarring alarm tone, wake up to God's Word being read aloud
- **Text-to-Speech**: Uses Android's built-in TTS to read verses naturally
- **Random or Sequential**: Choose to hear random verses or read through them in order
- **Category Selection**: Filter verses by category:
  - Morning verses
  - Encouragement
  - Psalms
  - Proverbs
  - Gospel of Matthew
  - Gospel of Mark
  - Gospel of Luke
  - Gospel of John
  - General
- **Repeating Alarms**: Set alarms to repeat on specific days of the week
- **Full-Screen Display**: Beautiful full-screen display of the verse when alarm triggers

## Upcoming Features

- [ ] Select specific books of the Bible
- [ ] Add custom verses
- [ ] Read consecutive verses (next verse each day)
- [ ] Multiple Bible translations
- [ ] Snooze with different verse
- [ ] Dark mode

## Building

1. Clone the repository
2. Open in Android Studio
3. Sync Gradle files
4. Build and run on device or emulator

## Requirements

- Android 8.0 (API 26) or higher
- Text-to-Speech engine installed (usually pre-installed)

## Permissions

- **SCHEDULE_EXACT_ALARM**: For precise alarm timing
- **RECEIVE_BOOT_COMPLETED**: Restore alarms after device restart
- **WAKE_LOCK**: Keep device awake during alarm
- **VIBRATE**: Vibration pattern for alarm
- **POST_NOTIFICATIONS**: Show alarm notifications
- **FOREGROUND_SERVICE**: Keep alarm service running

## License

MIT License
