# DVN Toolkit Android App v2.0

## Overview
Modern card-based Android app for the DVN Scripts Toolkit - 130+ Python security/utility tools with enterprise-grade UI, rich documentation, and dynamic forms.

## Build Location
```
/home/gh0st/dvn/scripts/android_app/
```

## APK Output
```
bin/dvntoolkit-1.0.0-arm64-v8a_armeabi-v7a-debug.apk
```

## v2.0 Architecture (New)

```
android_app/
├── main.py                    # Original monolithic app (legacy)
├── main_v2.py                 # NEW: Slim entry point for v2
├── app/
│   ├── __init__.py
│   ├── screens/
│   │   ├── dashboard.py       # Card grid + favorites + recent + search
│   │   ├── tool_detail.py     # Rich documentation + dynamic form
│   │   ├── output.py          # Visual results + progress
│   │   └── settings.py        # Preferences + theme picker
│   ├── components/
│   │   ├── tool_card.py       # Reusable card widget (ToolCard, ToolCardSmall)
│   │   ├── form_builder.py    # Dynamic form generation from metadata
│   │   ├── input_fields.py    # Text, Dropdown, Checkbox, File inputs
│   │   └── output_renderer.py # Terminal, Tables, Progress, JSON
│   ├── data/
│   │   ├── tool_registry.py   # Core tools with rich metadata
│   │   ├── tool_registry_full.py  # All 126+ tools
│   │   └── persistence.py     # Favorites, recents, settings (JSON storage)
│   └── utils/
│       └── theme_manager.py   # Theme definitions + management
├── tools/                     # 126+ Python tool scripts (unchanged)
├── assets/                    # App icons
├── buildozer.spec             # Android build config
└── themes/                    # Additional theme assets
```

## Key Features (v2.0)

### 1. Card-Based Dashboard
- 2-column grid of tool cards with icons
- Favorites section (horizontal scroll, pinned tools)
- Recents section (last 5 used tools)
- Search bar with real-time filtering
- Category tabs: All, Offensive, Security, Network, etc.
- Bottom navigation: Home, Favorites, Recent, Settings

### 2. Rich Tool Documentation
Each tool has comprehensive metadata:
```python
{
    'docs': {
        'short_desc': 'One-line description',
        'full_desc': 'Detailed multi-paragraph explanation...',
        'when_to_use': ['Use case 1', 'Use case 2'],
        'real_world_example': 'Scenario: ...',
        'expected_output': 'What you\'ll see',
        'warnings': ['Only scan authorized systems'],
        'prerequisites': ['Network access'],
    }
}
```

### 3. Dynamic Forms
- Text inputs with placeholders and validation
- Dropdowns for options (timing, level, type)
- Checkboxes for boolean flags
- File pickers for file inputs
- Number inputs with constraints
- Presets: Quick Scan, Full Scan, Stealth, etc.

### 4. Visual Output
- Progress indicator with animation
- Terminal-style output with timestamps
- Copy to clipboard
- Run again functionality
- Clear output

### 5. Persistence
- Favorites saved to JSON
- Recent tools tracked (last 10)
- Theme preference saved
- Settings persisted

## Screen Flow

```
DASHBOARD
├── Search bar
├── Favorites (horizontal scroll)
├── Recent (horizontal scroll)
├── Category tabs
└── Tool cards (2-col grid)
        │
        ▼ tap card
TOOL DETAIL
├── Back | Title | Favorite | Help
├── Documentation card
├── Warnings card (if any)
├── Presets: [Quick] [Full] [Stealth]
├── Dynamic form inputs
└── [RESET] [▶ RUN]
        │
        ▼ tap RUN
OUTPUT SCREEN
├── Back | Tool Name | Status
├── Progress bar
├── Command display
├── Terminal output (scrollable)
└── [CLEAR] [COPY] [STOP] [RUN AGAIN]
```

## Build Commands

### Using v2 (new modular architecture)
```bash
cd /home/gh0st/dvn/scripts/android_app

# For development testing, rename main.py and use main_v2.py:
# mv main.py main_legacy.py
# mv main_v2.py main.py

# Clean and build
rm -rf .buildozer/android/app .buildozer/android/platform/build-arm64-v8a_armeabi-v7a/dists/dvntoolkit
buildozer android debug

# Install
adb install -r bin/dvntoolkit-1.0.0-arm64-v8a_armeabi-v7a-debug.apk
```

### Quick Test Cycle
```bash
rm -rf .buildozer/android/app
buildozer android debug
adb install -r bin/dvntoolkit-*.apk
adb shell am force-stop com.gh0st.dvntoolkit
adb shell am start -n com.gh0st.dvntoolkit/org.kivy.android.PythonActivity
```

## Theme System

5 built-in themes with consistent color keys:
- **Cyberpunk** (default): Neon green/magenta on dark
- **Matrix**: Classic green terminal
- **Hacker Red**: Red accents on black
- **Ocean Blue**: Cyan/blue tones
- **Light Mode**: Light background

Theme colors available:
```python
theme['bg']           # Main background
theme['bg_secondary'] # Cards, headers
theme['bg_card']      # Card backgrounds
theme['accent']       # Primary accent color
theme['text']         # Main text
theme['text_dim']     # Secondary text
theme['terminal_bg']  # Terminal background
theme['terminal_text']# Terminal text
theme['button_bg']    # Button background
theme['danger']       # Error/danger red
theme['warning']      # Warning yellow
theme['success']      # Success green
theme['card_border']  # Card border color
theme['favorite']     # Favorite star color
```

## Tool Metadata Structure

Full structure for tool definitions:
```python
'tool_id': {
    'id': 'tool_id',
    'name': 'Display Name',
    'script': 'script_name.py',
    'category': 'offensive|security|network|...',
    'icon': 'icon_name',
    'docs': {
        'short_desc': 'Brief description',
        'full_desc': 'Full documentation...',
        'when_to_use': ['Use case 1', 'Use case 2'],
        'real_world_example': 'Scenario description...',
        'expected_output': 'What output looks like',
        'warnings': ['Warning 1', 'Warning 2'],
        'prerequisites': ['Requirement 1'],
    },
    'inputs': [
        {
            'name': 'param_name',
            'type': 'text|number|dropdown|checkbox|file',
            'label': 'Display Label',
            'placeholder': 'Hint text',
            'required': True|False,
            'default': 'default_value',
            'help': 'Help text',
            'flag': '-f',  # CLI flag
            'options': [...],  # For dropdowns
        },
    ],
    'presets': [
        {'name': 'Preset Name', 'values': {'param': 'value'}},
    ],
}
```

## Dependencies

buildozer.spec requirements:
```
requirements = python3,kivy==2.3.1,filetype
```

## File Size Guidelines

Per project rules, files should target 400-500 lines (negotiable if justified). The v2 architecture splits functionality:
- `main_v2.py`: ~120 lines (entry point only)
- `dashboard.py`: ~350 lines (within target)
- `tool_detail.py`: ~380 lines (within target)
- `tool_registry.py`: ~1000 lines (data, acceptable)
- Each component: ~100-400 lines

## Android Execution

Tools run via `exec()` instead of subprocess (Android doesn't have python3 in PATH):
```python
with open(tool_path, 'r') as f:
    tool_code = f.read()
sys.argv = [tool_path] + args
exec(compile(tool_code, tool_path, 'exec'), tool_globals)
```

## Package Info
- Package: com.gh0st.dvntoolkit
- Min SDK: 21
- Target SDK: 33
- Architectures: arm64-v8a, armeabi-v7a

## Debugging

### scrcpy (Screen Mirror)
```bash
/home/gh0st/Downloads/scrcpy-linux-x86_64-v3.3.4/scrcpy
```

### Logcat
```bash
adb logcat -d | grep -i "python\|kivy\|traceback"
adb logcat -d --pid=$(adb shell pidof com.gh0st.dvntoolkit)
```

### ADB Commands
```bash
adb exec-out screencap -p > /tmp/screenshot.png
adb shell input tap 540 200  # Tap coordinates
```

## Migration from v1 to v2

To switch to the new v2 architecture:
1. Backup: `cp main.py main_v1_backup.py`
2. Rename: `mv main_v2.py main.py`
3. Clean build: `rm -rf .buildozer/android/app`
4. Build: `buildozer android debug`

The app/ directory contains all v2 modules and will be included automatically.

## Created

January 2026 - DVN Toolkit v2.0 Redesign
- Card-based dashboard
- Rich documentation system
- Dynamic form generation
- Visual output formatting
- Favorites/recents persistence
