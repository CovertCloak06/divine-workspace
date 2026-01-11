# 🎨 Theme System & Terminal Widget

## Overview

This document covers two major features added to DVN Code Academy:

1. **Theme System** - Light/Dark mode with professional, muted colors for accessibility
2. **Terminal Widget** - Realistic 1-2 line terminal display for project-based learning

---

## 🎨 Theme System

### Features

✅ **Light & Dark Themes**
- Dark theme: Cyberpunk aesthetic with cyan accents
- Light theme: Professional with muted blue tones

✅ **Smart Detection**
- Auto-detects system preference (prefers-color-scheme)
- Saves user choice in localStorage
- Persists across sessions

✅ **Toggle Button**
- Located in navbar
- Shows ☀️ (Light Mode) or 🌙 (Dark Mode)
- Smooth transitions between themes

✅ **Accessibility**
- High contrast mode support
- Readable text in both themes
- WCAG compliant color combinations

### Color Palettes

#### Dark Theme (Cyberpunk)
```css
--primary-color: #00ffff (Cyan)
--bg-primary: #0a0a0a (Near Black)
--text-primary: #ffffff (White)
```

#### Light Theme (Professional)
```css
--primary-color: #2563eb (Blue)
--bg-primary: #ffffff (White)
--text-primary: #0f172a (Dark Gray)
```

### Files Created

1. **`js/theme-manager.js`** (150 lines)
   - ThemeManager class
   - localStorage persistence
   - Auto-detection of system preference
   - Toggle button creation
   - Event dispatching for theme changes

2. **`css/themes.css`** (500+ lines)
   - CSS variables for both themes
   - Component styling with theme support
   - Smooth transitions
   - High contrast mode support
   - Print styles

### Usage

**JavaScript API:**
```javascript
// Get current theme
const theme = window.ThemeManager.getCurrentTheme(); // 'light' or 'dark'

// Set specific theme
window.ThemeManager.setTheme('dark');

// Toggle theme
window.ThemeManager.toggleTheme();

// Listen for theme changes
window.addEventListener('themeChanged', (e) => {
    console.log('New theme:', e.detail.theme);
});
```

**CSS Usage:**
```css
/* Use theme variables in your styles */
.my-component {
    background: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border-primary);
}

/* Theme-specific styles */
[data-theme="light"] .my-component {
    /* Light theme overrides */
}
```

### How It Works

1. **Page Load**:
   - ThemeManager initializes immediately
   - Loads saved theme from localStorage
   - Falls back to system preference if no saved theme
   - Applies theme before page renders (no flash)

2. **User Toggle**:
   - Button click calls `toggleTheme()`
   - Updates `data-theme` attribute on `<html>`
   - CSS variables automatically update
   - Saves preference to localStorage
   - Dispatches 'themeChanged' event

3. **Component Support**:
   - All components use CSS variables
   - Smooth 0.3s transitions
   - No JavaScript changes needed in components

### Browser Support

- ✅ Chrome/Edge 88+
- ✅ Firefox 85+
- ✅ Safari 14+
- ✅ Mobile browsers (iOS Safari, Chrome Android)

---

## 💻 Terminal Widget

### Purpose

A **small, visual terminal display** (1-2 lines) that shows commands in lessons. NOT a full terminal emulator - just a realistic representation for educational purposes.

### Features

✅ **Realistic Appearance**
- macOS-style dots (red, yellow, green)
- Monospace font (Courier New, Monaco)
- Dark/light theme support
- Proper terminal colors

✅ **Command Display**
- Show command with prompt
- Animated typing effect (optional)
- Result messages with ✓ or ✗
- Error messages in red
- Success messages in green

✅ **Interactive Mode**
- User can type commands
- Submit with Enter key
- Validation and feedback
- Command history tracking

✅ **Compact Design**
- Auto height mode (grows with content)
- 1-line mode (minimal)
- 2-line mode (command + result)
- Scrollable for longer output

### Files Created

1. **`js/terminal-widget.js`** (300+ lines)
   - TerminalWidget class
   - Command execution simulation
   - Typing animation
   - Interactive input handling
   - History tracking

2. **`css/terminal-widget.css`** (350+ lines)
   - Realistic terminal styling
   - macOS-style header with dots
   - Theme-aware colors
   - Responsive design
   - Smooth animations

### Usage

#### Basic Example
```javascript
// Create terminal widget
const container = document.getElementById('terminalContainer');
const terminal = new TerminalWidget(container);

// Execute a command
await terminal.executeCommand('mkdir my-project', 'Directory created successfully');

// Show error
terminal.showError('Command not found: mdir');

// Show info
terminal.showInfo('Checking files...');

// Clear terminal
terminal.clear();
```

#### Interactive Example
```javascript
// Create terminal with input
const terminal = new TerminalWidget(container);

terminal.createInput('Type a command...', async (command) => {
    if (command === 'mkdir test') {
        return {
            success: true,
            message: 'Directory "test" created'
        };
    } else {
        return {
            success: false,
            message: 'Unknown command'
        };
    }
});
```

#### Options
```javascript
const terminal = new TerminalWidget(container, {
    prompt: 'student@dvn:~/projects$',  // Custom prompt
    animated: true,                      // Enable typing animation
    showPrompt: true,                    // Show prompt before commands
    height: '2-line'                     // 'auto', '1-line', or '2-line'
});
```

### Component Anatomy

```
┌─────────────────────────────────────────┐
│  ● ● ●           Terminal               │ ← Header with dots
├─────────────────────────────────────────┤
│ student@dvn:~/projects$ mkdir my-site   │ ← Command line
│ ✓ Directory created successfully        │ ← Result line
│ student@dvn:~/projects$ _               │ ← Input (optional)
└─────────────────────────────────────────┘
```

### Lesson Integration

The terminal widget is used in **project-builder** lessons to teach:
- File system navigation
- Creating folders and files
- Professional workflows
- Terminal command basics

**Example Lesson Step:**
```json
{
  "title": "Create Project Folder",
  "content": "Use mkdir to create a folder...",
  "task": {
    "type": "terminal-command",
    "providedCommand": "mkdir my-first-website",
    "allowCustomName": true,
    "expectedAction": "create_directory",
    "successMessage": "✓ Directory created!"
  }
}
```

### Styling

**Dark Theme:**
- Background: `#0a0a0a`
- Text: `#ffffff`
- Prompt: `#00ffff` (cyan)
- Success: `#4caf50` (green)
- Error: `#f44336` (red)

**Light Theme:**
- Background: `#f8fafc`
- Text: `#0f172a`
- Prompt: `#2563eb` (blue)
- Success: `#10b981` (green)
- Error: `#ef4444` (red)

### Animations

**Typing Effect:**
```javascript
// Simulates realistic typing
// Variable speed: 30-70ms per character
// Creates human-like feel
```

**Fade In:**
```css
@keyframes fadeInUp {
    from { opacity: 0; transform: translateY(5px); }
    to { opacity: 1; transform: translateY(0); }
}
```

**Blinking Cursor:**
```css
.terminal-cursor-blink {
    animation: cursorBlink 1s infinite;
}
```

---

## 🎓 Project-Builder Lesson Type

### New Lesson Format

A new lesson type that combines terminal commands with code editing and live preview:

```json
{
  "lessonType": "project-builder",
  "steps": [
    {
      "task": {
        "type": "terminal-command",
        "providedCommand": "mkdir my-project",
        "allowCustomName": true,
        "expectedAction": "create_directory"
      }
    },
    {
      "task": {
        "type": "code-with-terminal",
        "terminalCommand": "code index.html",
        "file": "index.html",
        "starter": "<!DOCTYPE html>..."
      }
    },
    {
      "task": {
        "type": "preview-with-terminal",
        "terminalCommand": "open index.html",
        "showPreview": true
      }
    }
  ]
}
```

### Task Types

#### 1. `terminal-command`
- Shows terminal widget
- Displays provided command
- User copies/types command
- Validates and shows result

#### 2. `code-with-terminal`
- Shows terminal command (`code filename`)
- Opens inline code editor
- User writes code
- Saves and closes editor

#### 3. `preview-with-terminal`
- Shows terminal command (`open filename`)
- Displays live preview (iframe)
- User sees their website

### Benefits

✅ **Realistic Workflow**
- Students learn terminal commands
- Understand project structure
- Professional development habits

✅ **Integrated Learning**
- Terminal + Code + Preview in one place
- No context switching
- Smooth learning experience

✅ **Progressive Complexity**
- Start with simple commands
- Build to full projects
- Confidence building

---

## 📁 File Structure

```
/home/gh0st/dvn/code-academy/
├── css/
│   ├── themes.css              ← Theme system CSS
│   └── terminal-widget.css     ← Terminal styling
├── js/
│   ├── theme-manager.js        ← Theme switching logic
│   └── terminal-widget.js      ← Terminal component
├── lessons/
│   └── project-builder-demo.json  ← Sample project lesson
└── index.html                  ← Updated with new imports
```

---

## 🚀 Next Steps

### Immediate TODOs

1. **Integrate Terminal into Tutorial Engine**
   - Add support for `terminal-command` task type
   - Add support for `code-with-terminal` task type
   - Add support for `preview-with-terminal` task type
   - Update `tutorial-engine.js` with render methods

2. **Virtual File System**
   - Create `js/file-system.js` component
   - Track created folders and files
   - Show file tree sidebar
   - Enable project download as ZIP

3. **OS-Specific Lessons**
   - Create Windows path (PowerShell/CMD)
   - Create Mac path (Zsh/Bash)
   - Create Linux path (Bash)
   - Add OS detection and path selection

### Future Enhancements

1. **Terminal Features**
   - Tab completion
   - Command history (up arrow)
   - Copy/paste support
   - Syntax highlighting in commands

2. **Project Features**
   - Multi-file editing
   - File renaming/deletion
   - Folder structure visualization
   - Git integration (simulated)

3. **Learning Paths**
   - Full CLI/Terminal course
   - Git & GitHub course
   - Node.js/npm course
   - Deployment course

---

## 🎯 User Experience Goals

### Theme System
- **Accessibility**: Users with light sensitivity can use light theme
- **Preference**: Auto-detects system setting
- **Consistency**: Same theme across all pages
- **Performance**: No flash of unstyled content

### Terminal Widget
- **Familiarity**: Looks like real terminals
- **Simplicity**: Not overwhelming for beginners
- **Education**: Teaches real-world commands
- **Integration**: Seamlessly fits into lessons

---

## 📝 Testing Checklist

### Theme System
- [ ] Light theme applies correctly
- [ ] Dark theme applies correctly
- [ ] Toggle button works
- [ ] Theme persists after page reload
- [ ] System preference detection works
- [ ] All components support both themes
- [ ] Smooth transitions (no jarring changes)
- [ ] High contrast mode works
- [ ] Print styles work (light background)

### Terminal Widget
- [ ] Terminal displays correctly
- [ ] Commands show with proper styling
- [ ] Results display (success/error)
- [ ] Typing animation works
- [ ] Interactive input accepts commands
- [ ] Enter key submits commands
- [ ] Cursor blinks realistically
- [ ] Scrolling works for long output
- [ ] Both themes display correctly
- [ ] Responsive on mobile

---

## 🎨 Design Philosophy

### Theme System
> "Give users control over their learning environment. Some prefer dark for focus, others need light for readability. Professional learners appreciate muted, non-distracting colors."

### Terminal Widget
> "Teach the way professionals work, but keep it simple. Show real commands without overwhelming beginners. Make terminal usage approachable, not scary."

---

**Built with ⚡ by Divine Node**
**Part of the DVN Code Academy**

Last Updated: 2026-01-10
