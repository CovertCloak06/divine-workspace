# PKN Mobile - Pending Tasks (2026-01-17)

## UI Fixes Needed

### 1. Missing Tool Documentation
The following tool sections need guidance/documentation added:
- [ ] Network Tools
- [ ] Android Tools
- [ ] CLI Utilities
- [ ] Developer Tools

Each tool should have a brief description of what it does and how to use it.

### 2. Input Parameter Fields
- [ ] Some input fields are too tight (need more padding/width)
- [ ] Some input fields may be missing content/placeholders
- [ ] Review all tool input forms for consistency

### 3. Broken Image Icons (Box with X)
- [ ] Find and fix all instances of missing images showing "box with X"
- [ ] Check `img/` directory for missing assets
- [ ] Update references or add placeholder images

### 4. General Review
- [ ] Do a full pass through all tool sections
- [ ] Ensure consistent styling across all tools
- [ ] Test each tool's UI on mobile

---

## Completed This Session
- [x] Created Divine Debugger module (`js/debugger.js`)
- [x] Integrated debugger into PKN (sidebar toggle)
- [x] Created service-worker.js for cache busting
- [x] Created deploy-to-phone.sh script
- [x] Cleaned phone of all old PKN/Divine/backup artifacts (~50MB)
- [x] Fresh deployed to ~/pkn-phone via SSH
- [x] Verified debugger toggle works
