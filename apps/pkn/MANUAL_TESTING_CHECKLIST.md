# PKN Manual Testing Checklist

**Purpose**: Catch UI, runtime, and visual bugs that static analysis tools can't detect

**When to Use**:
- After major code changes
- Before deploying to production
- When bugs are reported
- After modularization/refactoring

---

## Pre-Testing Setup

- [ ] Server running: `./pkn_control.sh start-all`
- [ ] Server status: `./pkn_control.sh status` shows `✓ DivineNode (8010)`
- [ ] Browser DevTools open (F12)
- [ ] Debugger extension loaded (if testing with it)
- [ ] Clear browser cache/localStorage (Ctrl+Shift+Delete)

---

## 1. Page Load & Initialization

### Basic Loading
- [ ] Page loads without errors (check DevTools Console)
- [ ] No 404 errors for CSS/JS files (check Network tab)
- [ ] Welcome screen appears on first load
- [ ] All CSS styles applied correctly (no FOUC - Flash of Unstyled Content)

### JavaScript Initialization
- [ ] Check console for "PKN Logger initialized" message
- [ ] No JavaScript errors in console
- [ ] `window.pknLogger` exists (check in console)
- [ ] All modules loaded successfully

**Screenshot**: Initial page load

---

## 2. Layout & Responsiveness

### Sidebar
- [ ] Sidebar toggles open/close with button
- [ ] **CRITICAL**: Sidebar fully hides when closed (no sticking out)
- [ ] Sidebar animation smooth
- [ ] Sidebar width appropriate (~250-300px)
- [ ] Sidebar content readable and accessible

### Window Resizing
- [ ] Layout stable at 1920x1080 (full HD)
- [ ] Layout stable at 1366x768 (common laptop)
- [ ] Layout stable at 1024x768 (small screen)
- [ ] No horizontal scrollbar at any size
- [ ] **CRITICAL**: No duplicate buttons at different window sizes
- [ ] Chat messages container resizes correctly

### Mobile/Narrow View
- [ ] Sidebar collapses to hamburger menu (<768px width)
- [ ] Input area remains accessible
- [ ] Send button visible and clickable

**Screenshots**: Full width, medium, narrow

---

## 3. Chat Interface

### Message Input
- [ ] Can type in message input box
- [ ] Placeholder text visible and customizable
- [ ] **CRITICAL**: Placeholder customization has submit button/way to save
- [ ] Input expands for multi-line messages
- [ ] Enter key sends message (with Shift+Enter for new line)
- [ ] Input clears after sending

### Send Button
- [ ] **CRITICAL**: Send button shows ONLY arrow icon (➤), NO "SEND" text
- [ ] Send button visible and clickable
- [ ] Send button disabled when input empty
- [ ] Send button changes to STOP button while streaming
- [ ] **CRITICAL**: Only ONE STOP button appears (no duplicates)

### Message Display
- [ ] Messages appear in chat container
- [ ] User messages right-aligned (or styled differently)
- [ ] AI messages left-aligned
- [ ] Timestamps visible (if enabled)
- [ ] Messages scroll automatically to bottom
- [ ] Long messages wrap correctly (no overflow)
- [ ] Code blocks syntax highlighted
- [ ] Copy code button works on code blocks

### Streaming Responses
- [ ] AI responses stream character-by-character
- [ ] Streaming smooth (no stuttering)
- [ ] STOP button stops streaming
- [ ] After stop, partial response saved
- [ ] Can send new message after stopping

**Screenshots**: Chat with multiple messages, code block, long message

---

## 4. Context Menus

### Chat Context Menu
- [ ] Right-click on chat opens context menu
- [ ] **CRITICAL**: Context menu appears near click location (not way below)
- [ ] Menu options visible and readable
- [ ] Can select menu options
- [ ] Menu closes after selection
- [ ] Menu closes when clicking outside

### Project Context Menu
- [ ] Right-click on project opens context menu
- [ ] **CRITICAL**: Context menu positioned correctly
- [ ] All project actions available (rename, delete, etc.)
- [ ] Actions work as expected

**Screenshots**: Context menu open, positioned correctly

---

## 5. Modals & Overlays

### Settings Modal
- [ ] Settings icon/button opens modal
- [ ] Modal appears centered on screen
- [ ] Modal overlay darkens background
- [ ] Can scroll through settings if needed
- [ ] All settings categories accessible
- [ ] Settings save when clicking "Save"
- [ ] Modal closes with X button
- [ ] Modal closes when clicking outside (if enabled)

### File Explorer
- [ ] File explorer opens from sidebar
- [ ] **CRITICAL**: Can navigate file system
- [ ] Can select files
- [ ] Can upload files via drag-drop
- [ ] Paperclip button (file upload) works
- [ ] Uploaded files appear in file list
- [ ] Can delete files

### Other Modals
- [ ] Keyboard shortcuts modal opens and displays correctly
- [ ] Model selector modal works
- [ ] OSINT tools modal accessible

**Screenshots**: Each modal open

---

## 6. Quick Actions (Welcome Screen)

### Quick Action Buttons
- [ ] "New Chat" button works
- [ ] "Upload File" button works
- [ ] "Settings" button works
- [ ] **CRITICAL**: "Debug" button works (opens debug panel/tools)
- [ ] Other quick actions work as intended

**Screenshot**: Welcome screen with quick actions

---

## 7. Agents & Models

### Agent Selector
- [ ] Agent selector visible (FAB or dropdown)
- [ ] Can select different agents
- [ ] Selected agent persists across messages
- [ ] Agent selection updates UI indicator

### Model Selection
- [ ] Can view available models
- [ ] Can select different model
- [ ] Model selection persists
- [ ] Different models work correctly

**Screenshot**: Agent selector open

---

## 8. File Operations

### File Upload
- [ ] Can click paperclip to browse files
- [ ] Can drag-drop files into chat
- [ ] Upload progress indicator appears
- [ ] Uploaded files listed
- [ ] Can reference uploaded files in chat
- [ ] Can delete uploaded files

### File Explorer (Sidebar)
- [ ] **CRITICAL**: File explorer navigation works
- [ ] Can browse directories
- [ ] Can view file contents
- [ ] Can select files to attach

**Screenshot**: File upload in progress, file list

---

## 9. Plugins

### Plugin Loading
- [ ] **CRITICAL**: Plugins load and display in sidebar
- [ ] Plugin list shows available plugins
- [ ] Plugin icons/names visible

### Plugin Functionality
- [ ] Can activate/deactivate plugins
- [ ] Active plugins work as expected
- [ ] Plugin UI appears when activated
- [ ] Plugins don't interfere with each other

**Screenshot**: Plugin list, active plugin

---

## 10. OSINT Tools

### OSINT Access
- [ ] OSINT tools accessible from sidebar/menu
- [ ] OSINT UI loads correctly
- [ ] All OSINT tools listed

### OSINT Functionality
- [ ] WHOIS lookup works
- [ ] Email validation works
- [ ] IP lookup works
- [ ] DNS lookup works
- [ ] Other OSINT tools work
- [ ] Results display correctly

**Screenshot**: OSINT tool results

---

## 11. Code Features

### Syntax Highlighting
- [ ] Code blocks highlighted correctly
- [ ] Language detection works
- [ ] Highlighting colors readable

### Code Copy
- [ ] Copy button appears on code blocks
- [ ] Copy button copies code to clipboard
- [ ] Toast notification shows "Copied!"

### Code Editing
- [ ] Code editor (if available) works
- [ ] Syntax highlighting in editor
- [ ] Can save edits

**Screenshot**: Code block with syntax highlighting

---

## 12. Error Handling

### Visual Error Display
- [ ] Errors display toast notifications
- [ ] Error messages readable and helpful
- [ ] Errors don't break UI
- [ ] Can dismiss error messages

### Network Errors
- [ ] Backend offline shows error
- [ ] Timeout errors handled gracefully
- [ ] 404 errors show helpful message
- [ ] 500 errors logged and displayed

### Console Errors
- [ ] Open DevTools Console (F12)
- [ ] No JavaScript errors during normal use
- [ ] No React/Vue warnings (if using framework)
- [ ] Network tab shows all requests successful

**Screenshots**: Error toast, network error, console logs

---

## 13. Performance

### Load Time
- [ ] Page loads in <3 seconds
- [ ] First meaningful paint <1 second
- [ ] Interactive in <2 seconds

### Runtime Performance
- [ ] Chat scrolling smooth (60fps)
- [ ] No lag when typing
- [ ] No lag when switching agents
- [ ] Streaming responses smooth
- [ ] Long conversations don't slow down

### Memory
- [ ] Memory usage stable over time
- [ ] No memory leaks (check DevTools Performance Monitor)
- [ ] LocalStorage not filling up excessively

**Screenshot**: DevTools Performance tab

---

## 14. Accessibility

### Keyboard Navigation
- [ ] Can tab through interactive elements
- [ ] Enter key works on buttons
- [ ] Escape key closes modals
- [ ] Keyboard shortcuts work

### Visual
- [ ] Sufficient color contrast
- [ ] Focus indicators visible
- [ ] No text too small to read
- [ ] Icons have tooltips/labels

### Screen Reader (if applicable)
- [ ] Buttons have aria-labels
- [ ] Images have alt text
- [ ] Form inputs labeled

---

## 15. Theme & Appearance

### Theme Switching
- [ ] Can switch between light/dark themes
- [ ] Theme persists on reload
- [ ] All elements respect theme
- [ ] No flash when loading theme

### Customization
- [ ] Can customize colors (if feature exists)
- [ ] Can customize fonts (if feature exists)
- [ ] Customizations save correctly

**Screenshots**: Light theme, dark theme

---

## 16. Persistence & State

### LocalStorage
- [ ] Chat history persists on reload
- [ ] Settings persist on reload
- [ ] Selected agent persists
- [ ] Selected model persists
- [ ] Uploaded files persist (or clearly shown as session-only)

### Session Management
- [ ] Can create new session
- [ ] Can switch between sessions
- [ ] Can delete sessions
- [ ] Session data isolated correctly

**Screenshot**: Multiple sessions

---

## 17. Advanced Features

### Multi-Agent System
- [ ] Agent classification works
- [ ] Correct agent selected for task
- [ ] Can override agent selection
- [ ] Multi-agent responses formatted correctly

### RAG (if enabled)
- [ ] Document search works
- [ ] Relevant documents retrieved
- [ ] Sources cited in responses

### Code Execution (if enabled)
- [ ] Can execute code safely
- [ ] Results display correctly
- [ ] Sandboxing prevents harmful code

**Screenshots**: Agent routing, RAG results

---

## 18. Browser Compatibility

Test in multiple browsers:

### Chrome/Edge (Chromium)
- [ ] All features work
- [ ] No console errors
- [ ] Layout correct

### Firefox
- [ ] All features work
- [ ] No console errors
- [ ] Layout correct

### Safari (if available)
- [ ] All features work
- [ ] No console errors
- [ ] Layout correct

**Note**: Document any browser-specific issues

---

## 19. Stress Testing

### Long Sessions
- [ ] Can send 100+ messages without slowdown
- [ ] Can keep page open for 1+ hour
- [ ] Memory usage stable

### Large Inputs
- [ ] Can send very long messages (5000+ chars)
- [ ] Can upload large files (within limit)
- [ ] Can handle large AI responses

### Rapid Actions
- [ ] Can send messages rapidly
- [ ] Can spam buttons without breaking UI
- [ ] Can switch agents rapidly

**Screenshot**: Long conversation, performance metrics

---

## 20. Security

### Input Validation
- [ ] XSS attempts blocked (try `<script>alert('XSS')</script>`)
- [ ] SQL injection attempts handled (try `' OR '1'='1`)
- [ ] File upload restrictions enforced

### Authentication (if enabled)
- [ ] Can't access without login
- [ ] Session timeout works
- [ ] Logout works

---

## Bug Report Template

When you find a bug, document:

```markdown
### Bug: [Short Description]

**Severity**: Critical / High / Medium / Low

**Location**: [Where in UI]

**Expected**: [What should happen]

**Actual**: [What actually happens]

**Reproduce**:
1. Step 1
2. Step 2
3. Step 3

**Screenshots**: [Attach screenshots]

**Console Errors**: [Any JS errors]

**Network Errors**: [Any failed requests]

**Browser**: [Chrome 120, Firefox 115, etc.]

**Window Size**: [1920x1080, 1366x768, etc.]
```

---

## Post-Testing

### Review Checklist
- [ ] All critical bugs documented
- [ ] Screenshots organized
- [ ] Console logs reviewed
- [ ] Network requests reviewed
- [ ] Performance metrics recorded

### Create Issues
- [ ] Create GitHub issues for bugs
- [ ] Prioritize critical bugs
- [ ] Assign to appropriate milestone

### Re-Test After Fixes
- [ ] Verify each fix
- [ ] Regression test (ensure fix didn't break anything else)
- [ ] Update checklist if needed

---

## Automated Testing Tools

To complement manual testing:

1. **Browser DevTools**
   - Console: Check for errors
   - Network: Check requests/responses
   - Performance: Monitor CPU/Memory
   - Elements: Inspect DOM/CSS

2. **Lighthouse Audit**
   - Run: DevTools → Lighthouse → Generate Report
   - Check: Performance, Accessibility, Best Practices, SEO

3. **PKN Logger**
   - Open console: `pknLogger.getLogs()`
   - Export logs: `pknLogger.exportLogs()`
   - View stats: DevTools extension → 📊 Stats button

4. **Debugger Extension**
   - Element inspector
   - Console live view
   - Network monitoring
   - Code analysis

---

## Checklist Usage

### For Quick Testing (10 minutes)
Focus on:
- Page load (Section 1)
- Chat interface (Section 3)
- Critical bugs from FRONTEND_BUGS.md

### For Comprehensive Testing (1 hour)
Complete all sections

### For Release Testing (2 hours)
- Complete all sections
- Test in all browsers
- Run stress tests
- Run Lighthouse audit
- Export logs and review

---

**Last Updated**: 2026-01-11
**Version**: 1.0
**Related Docs**: FRONTEND_BUGS.md, BACKEND_MIGRATION.md, CLAUDE.md
