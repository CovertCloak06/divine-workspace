# PKN Changelog

## 2026-01-05 - Welcome Screen & UI Fixes

### Fixed
- **Welcome screen overlay issue**: Welcome screen now properly hidden by default (`display: none` in CSS)
- Welcome screen completely removed from DOM when first message is sent
- `showWelcomeScreen()` now actively removes welcome screen if messages exist (handles all setTimeout calls)
- `hideWelcomeScreen()` uses `.remove()` to completely delete element from DOM

### Changed
- **Agent switcher FAB button styling**: Made more subtle and less intrusive
  - Size reduced: 56px → 44px (40px on mobile)
  - Background: Translucent `rgba(0, 255, 255, 0.15)` instead of solid bright cyan
  - Default opacity: 60% (100% on hover)
  - Soft border and subtle shadow
  - Icon size: 32px → 24px with 80% opacity
- Removed backup CSS files: `css/main.css.backup`, `css/multi_agent.css.backup`

### Technical Details
- Modified `/home/gh0st/pkn/css/main.css`:
  - Line 1806: `.welcome-screen { display: none; }` - Hidden by default
  - Lines 2070-2097: Updated `.agent-switcher-fab` styling for subtle appearance

- Modified `/home/gh0st/pkn/app.js`:
  - Lines 338-343: `hideWelcomeScreen()` - Removes element from DOM
  - Lines 347-363: `showWelcomeScreen()` - Actively removes if messages exist

- Modified `/home/gh0st/pkn/pkn.html`:
  - Line 806: Reduced FAB icon size and added opacity

### Context for Future Sessions
**Problem**: Welcome screen was showing over chat messages after user sent first message
**Root Cause**: Multiple `setTimeout(() => showWelcomeScreen(), 50)` calls throughout app.js (lines 757, 2355, 2372, 2405, 2533) were re-showing the screen
**Solution**:
1. CSS: Hidden by default
2. JS: `hideWelcomeScreen()` removes from DOM completely
3. JS: `showWelcomeScreen()` checks for messages and removes if they exist

## Previous Changes
See git history for earlier changes (Phase 1-3 UX improvements, multi-agent system, etc.)
