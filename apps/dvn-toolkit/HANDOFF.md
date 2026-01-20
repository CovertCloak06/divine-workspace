# Handoff Notes for New Claude Session

## Project: DVN Toolkit Android App
**Location**: `/home/gh0st/dvn/scripts/android_app/`

## What This Is
A Kivy-based Android app containing 130+ Python security/utility tools. The app has a cyberpunk-themed UI with tool categories, a command arguments input section, and a terminal-style output display.

## Current State (Jan 15, 2026)
**The app is WORKING.** Core functionality has been tested and verified:
- Tool selection works
- Tool execution via exec() works
- Terminal output displays correctly
- No more overlay/duplication bugs

## Key Files to Know
1. **main.py** (1369 lines) - The entire Kivy app
2. **buildozer.spec** - Android build configuration
3. **tools/** - Directory with 130+ Python scripts by category
4. **CLAUDE.md** - Comprehensive project documentation (READ THIS FIRST)
5. **SESSION_LOG_20260115.md** - Detailed log of this debug session

## Critical Technical Details

### Tool Execution
Tools run via `exec()` NOT subprocess (Android doesn't have python3 in PATH):
```python
with open(tool_path, 'r') as f:
    tool_code = f.read()
sys.argv = [tool_path] + args.split()
exec(compile(tool_code, tool_path, 'exec'), tool_globals)
```

### Build Process
```bash
cd /home/gh0st/dvn/scripts/android_app
rm -rf .buildozer/android/app .buildozer/android/platform/build-arm64-v8a_armeabi-v7a/dists/dvntoolkit
buildozer android debug
adb install -r bin/dvntoolkit-1.0.0-arm64-v8a_armeabi-v7a-debug.apk
```

### Testing Device
- Samsung SM-S938U (S24 Ultra)
- Android 16
- Screen: 1080x2340
- Use scrcpy v3.3.4: `/home/gh0st/Downloads/scrcpy-linux-x86_64-v3.3.4/scrcpy`

## Bugs Fixed This Session
1. **Overlay/duplication** - Added `self.clear_widgets()` to `ToolScreen.build_ui()` (line 701-703)
2. **Redundant processing** - Simplified `_display_output()` method (line 1042-1045)

## What Still Needs Testing
- Individual tool execution for all 130+ tools
- HELP/EXAMPLES/STOP button tap coordinates
- Theme switching
- Terminal scrolling with very large output

## If User Reports UI Issues
1. Check if `clear_widgets()` is being called before `build_ui()`
2. Check the logcat: `adb logcat -d --pid=$(adb shell pidof com.gh0st.dvntoolkit)`
3. Take screenshot: `adb exec-out screencap -p > /tmp/screenshot.png`

## Important Buildozer Settings
```
android.no-byte-compile-python = True  # Required for exec() to work
requirements = python3,kivy==2.3.1,filetype
```

## Quick Reference - ADB Tap Coordinates
```bash
adb shell input tap 540 200   # Select tool on main screen
adb shell input tap 183 345   # Tap RUN button
adb shell input tap 950 165   # Tap HELP button
```
