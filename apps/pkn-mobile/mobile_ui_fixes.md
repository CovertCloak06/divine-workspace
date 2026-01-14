# PKN Mobile UI Fixes - Jan 13, 2026

## Issues Fixed

### 1. White Keyboard Emoji (⌨️)
**Problem:** Keyboard emoji from settings modal headers appearing in top-left corner on mobile
**Location:** Lines 679 and 1015 in `pkn.html`
- `<h3>⌨️ Command Line Access</h3>` (settings modal)
- `<h3>⌨️ Keyboard Shortcuts</h3>` (keyboard shortcuts modal)

**Fix:**
```css
/* Hide settings group headers that contain emojis */
.settings-group h3 {
    display: none !important;
}

/* Hide modal headers that contain emojis */
.modal-header h3 {
    display: none !important;
}
```

### 2. Transparent Vertical Rectangle with White Line
**Problem:** Hoverstrip (sidebar trigger) still partially visible on mobile despite CSS hiding
**Cause:** Only `display: none` wasn't enough - element still occupied space and showed borders

**Fix:**
```css
.hover-strip,
#hoverStrip {
    display: none !important;
    opacity: 0 !important;
    visibility: hidden !important;
    width: 0 !important;
    height: 0 !important;
    pointer-events: none !important;
}

/* Also hide all child elements */
.hover-strip *,
#hoverStrip * {
    display: none !important;
}
```

### 3. White Vertical Line (Sidebar Border)
**Problem:** Sidebar's 2px cyan border showing as white line on left edge
**Cause:** `main.css` sets `border-right: 2px solid var(--theme-primary)` on `.sidebar`

**Fix:**
```css
.sidebar {
    border-right: none !important;
    border: none !important;
}
```

### 4. White Rectangle Below Keyboard Position
**Problem:** Modal overlay or settings section partially visible when should be hidden
**Cause:** Modals needed explicit `opacity` and `visibility` overrides, not just `display: none`

**Fix:**
```css
.settings-modal,
.files-manager-modal,
.ai-models-modal,
.image-generator-modal,
.modal-overlay {
    display: none !important;
    opacity: 0 !important;
    visibility: hidden !important;
}

/* Allow showing when explicitly opened */
.settings-modal.show,
.files-manager-modal.show,
.ai-models-modal.show,
.image-generator-modal.show,
.modal-overlay.show {
    display: flex !important;
    opacity: 1 !important;
    visibility: visible !important;
}
```

### 5. Input Container Transparency
**Problem:** Welcome screen showing through input container
**Cause:** `background: var(--bg-primary)` was resolving to a transparent/light color on mobile

**Fix:**
```css
.input-container {
    background: #0a0a0a !important;  /* Solid dark background */
    z-index: 1000 !important;         /* Above other content */
}

/* Add padding to prevent overlap */
#messagesContainer,
.chat-content {
    padding-bottom: 70px !important;
}
```

## Files Modified

**Primary file:** `~/pkn-phone/css/mobile.css` (6.6KB, 257 lines)

**Key sections:**
- Lines 12-26: Hoverstrip elimination
- Lines 38-42: Sidebar border removal
- Lines 44-56: Help icons and emoji headers hiding
- Lines 58-74: Modal visibility controls
- Lines 151-163: Input container solid background

## Testing

**Server:** `http://192.168.12.183:8010/pkn.html`
**Hard refresh required:** Add `?v=6` or clear browser cache

**Verified fixes:**
- ✅ No keyboard emoji in top-left
- ✅ No transparent rectangle on left edge
- ✅ No white line running vertically
- ✅ No white rectangle below header
- ✅ Input container solid black, no bleed-through
- ✅ Sidebar still opens/closes with swipe gesture

## Key Learnings

1. **Multiple CSS properties needed for complete hiding:**
   - `display: none` - removes from layout
   - `opacity: 0` - makes invisible
   - `visibility: hidden` - hides from screen readers
   - `width/height: 0` - removes dimensions
   - `pointer-events: none` - disables interaction

2. **Emoji headers leak through modals:**
   - Settings modals contain `<h3>` tags with emojis
   - These can appear outside their containers on mobile
   - Hide parent headers, not just help icons

3. **CSS variables can resolve unexpectedly:**
   - `var(--bg-primary)` may be white in light mode
   - Use explicit hex colors for critical mobile elements

4. **Borders show as white lines:**
   - Theme color borders may appear white on some devices
   - Remove all borders on mobile for clean edge-to-edge layout

## Related Files

- `~/pkn-phone/pkn.html` - Main HTML (contains emoji headers)
- `~/pkn-phone/css/main.css` - Desktop CSS (defines hoverstrip, sidebar)
- `~/pkn-phone/backend/agents/manager.py` - OpenAI API integration
- `~/pkn-phone/.env` - API keys
