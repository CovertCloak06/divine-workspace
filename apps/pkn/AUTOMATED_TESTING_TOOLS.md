# Automated Testing Tools for PKN

**Purpose**: Catch runtime errors, visual bugs, performance issues, and UX problems automatically

**Date**: 2026-01-11

---

## Tools by Category

### 1. Browser Automation (E2E Testing) - **Catches Runtime & UX Bugs**

**Best Tools:**

#### Playwright (Recommended for PKN)
- ✅ Fast, reliable, modern
- ✅ Built-in visual comparison
- ✅ Network interception
- ✅ Screenshot/video recording
- ✅ Works with Python and JavaScript
- ✅ Free and open source

**What it catches:**
- ✅ Duplicate STOP buttons (can count elements)
- ✅ Send button showing wrong text (can check element content)
- ✅ Debug button not working (can test clicks)
- ✅ Plugins not loading (can wait for elements)
- ✅ File explorer navigation (can test navigation)
- ✅ Context menu positioning (can measure coordinates)
- ✅ JavaScript errors (listens to console)
- ✅ Network failures (intercepts requests)

**Installation:**
```bash
pip install playwright
playwright install chromium
```

#### Alternatives:
- **Cypress**: JavaScript only, great UI, slower than Playwright
- **Selenium**: Older, more complex, works everywhere
- **Puppeteer**: Chrome only, good for screenshots

---

### 2. Visual Regression Testing - **Catches Layout & CSS Bugs**

**Best Tools:**

#### Playwright Visual Comparisons (Recommended)
Built into Playwright, no extra cost.

**What it catches:**
- ✅ Sidebar not hiding completely (visual difference)
- ✅ Context menu wrong position (pixel-perfect comparison)
- ✅ Welcome screen layout issues
- ✅ Any CSS changes that break layout
- ✅ Responsive design breakpoints

**How it works:**
1. Take screenshot of correct UI (baseline)
2. Take screenshot after changes (comparison)
3. Tool highlights pixel differences
4. You approve or reject changes

#### Alternatives:
- **BackstopJS**: Free, JavaScript-based
- **Percy**: Paid service, great UI ($39/month)
- **Chromatic**: Paid, integrates with Storybook

---

### 3. Runtime Error Tracking - **Catches JavaScript Errors in Production**

**Best Tools:**

#### Sentry (Recommended)
- ✅ Catches all JavaScript errors automatically
- ✅ Shows stack traces, user context
- ✅ Groups similar errors
- ✅ Email/Slack alerts
- ✅ Free tier: 5,000 errors/month

**What it catches:**
- ✅ All JavaScript runtime errors
- ✅ Unhandled promise rejections
- ✅ Network request failures
- ✅ Performance issues
- ✅ User session replay

**Installation:**
```bash
npm install @sentry/browser
```

**Setup** (2 lines of code):
```javascript
import * as Sentry from "@sentry/browser";
Sentry.init({ dsn: "your-project-dsn" });
```

#### Alternatives:
- **LogRocket**: Session replay + error tracking ($99/month)
- **Bugsnag**: Similar to Sentry
- **Rollbar**: Good for backend errors too
- **Our PKNLogger**: Free, local-only, good for development

---

### 4. Performance Monitoring - **Catches Slow Code & Memory Leaks**

**Best Tools:**

#### Lighthouse (Built into Chrome DevTools)
- ✅ Free
- ✅ Already installed
- ✅ Measures page load, performance, accessibility, SEO
- ✅ Gives actionable recommendations

**What it catches:**
- ✅ Slow page load times
- ✅ Large JavaScript bundles
- ✅ Render-blocking resources
- ✅ Accessibility issues
- ✅ Best practice violations

**How to run:**
1. Open Chrome DevTools (F12)
2. Click "Lighthouse" tab
3. Click "Generate report"

**Automated via CLI:**
```bash
npm install -g lighthouse
lighthouse http://localhost:8010 --view
```

#### Alternatives:
- **WebPageTest**: Online service, very detailed
- **Chrome DevTools Performance Tab**: Manual profiling
- **SpeedCurve**: Paid monitoring service

---

### 5. Accessibility Testing - **Catches A11y Issues**

**Best Tools:**

#### axe DevTools (Free Chrome Extension)
- ✅ Scans page for accessibility issues
- ✅ Shows what's wrong and how to fix
- ✅ WCAG 2.1 compliance checking

**What it catches:**
- ✅ Missing alt text on images
- ✅ Low color contrast
- ✅ Missing ARIA labels
- ✅ Keyboard navigation issues
- ✅ Form input labels

#### Alternatives:
- **WAVE**: Browser extension
- **Pa11y**: Command-line tool
- **Lighthouse accessibility audit**

---

## What We'll Build for PKN

### Automated Test Suite Using Playwright

I'll create scripts that automatically test everything in your manual checklist:

**tests/e2e/test_ui_bugs.py** - Tests for all 8 frontend bugs:
```python
from playwright.sync_api import sync_playwright

def test_sidebar_hiding():
    """Test that sidebar fully hides when closed"""
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto("http://localhost:8010")

        # Click sidebar toggle
        page.click(".toggle-btn")

        # Wait for animation
        page.wait_for_timeout(500)

        # Check sidebar is completely hidden
        sidebar = page.locator(".sidebar.hidden")
        box = sidebar.bounding_box()

        # Sidebar should be off-screen (x < 0)
        assert box['x'] + box['width'] <= 0, "Sidebar still visible!"

        browser.close()

def test_no_duplicate_stop_buttons():
    """Test that only ONE stop button appears"""
    # ... test implementation

def test_send_button_shows_arrow_only():
    """Test send button shows arrow, not 'SEND' text"""
    # ... test implementation
```

**tests/visual/test_layout.py** - Visual regression tests:
```python
def test_sidebar_closed_layout(page):
    """Visual test: sidebar closed"""
    page.goto("http://localhost:8010")
    page.click(".toggle-btn")  # Close sidebar
    page.wait_for_timeout(500)

    # Compare to baseline screenshot
    page.screenshot(path="screenshots/sidebar-closed.png")
    # Playwright will auto-compare to baseline

def test_context_menu_position(page):
    """Visual test: context menu appears near click"""
    # ... implementation
```

**tests/performance/test_load_times.py** - Performance tests:
```python
def test_page_load_performance(page):
    """Ensure page loads in < 3 seconds"""
    # ... implementation
```

---

## Recommended Stack for PKN

### Essential (Implement Now)
1. ✅ **Playwright** - E2E testing, visual regression
2. ✅ **Lighthouse** - Performance (already available)
3. ✅ **PKNLogger** - Runtime errors (we just built this!)

### Optional (Nice to Have)
4. **Sentry** - Production error tracking (when you deploy)
5. **axe DevTools** - Accessibility (install extension)

### Not Needed Yet
- **Cypress** - Playwright is better for Python projects
- **Percy/Chromatic** - Expensive, Playwright visual comparison works fine
- **LogRocket** - Expensive, PKNLogger + Sentry covers it

---

## Implementation Plan

### Phase 1: Setup Playwright (15 minutes)
```bash
cd /home/gh0st/dvn/divine-workspace/apps/pkn
pip install playwright pytest-playwright
playwright install chromium

# Create test structure
mkdir -p tests/{e2e,visual,performance}
```

### Phase 2: Write Tests for 8 Frontend Bugs (2 hours)
I'll create tests that check:
- ✅ Sidebar fully hides
- ✅ Context menus positioned correctly
- ✅ No duplicate STOP buttons
- ✅ Send button shows arrow only
- ✅ Debug button works
- ✅ Plugins load
- ✅ File explorer navigates
- ✅ Placeholder has submit button

### Phase 3: Visual Regression Baseline (30 minutes)
Generate baseline screenshots for:
- Welcome screen
- Chat with messages
- Settings modal
- OSINT tools
- File explorer
- All responsive breakpoints

### Phase 4: CI Integration (30 minutes)
Add to GitHub Actions / pre-commit:
```yaml
- name: Run E2E tests
  run: pytest tests/e2e/

- name: Run visual tests
  run: pytest tests/visual/ --update-snapshots
```

---

## Cost Comparison

| Tool | Cost | What It Does |
|------|------|--------------|
| Playwright | FREE | E2E + Visual regression |
| Lighthouse | FREE | Performance monitoring |
| PKNLogger | FREE | Runtime errors (dev) |
| axe DevTools | FREE | Accessibility |
| Sentry | FREE (5k errors/mo) | Production error tracking |
| **Total** | **$0/month** | **All essential testing** |

**Paid alternatives cost:**
- Percy: $39/month
- LogRocket: $99/month
- Chromatic: $149/month
- **Total**: $287/month (not needed!)

---

## Example: Full Automated Test

**tests/e2e/test_frontend_bugs.py**:

```python
import pytest
from playwright.sync_api import expect

@pytest.fixture
def page(browser):
    page = browser.new_page()
    page.goto("http://localhost:8010")
    return page

def test_sidebar_hiding(page):
    """Bug #1: Sidebar should fully hide"""
    # Open sidebar
    sidebar = page.locator(".sidebar")
    expect(sidebar).not_to_have_class("hidden")

    # Close sidebar
    page.click(".toggle-btn")
    page.wait_for_timeout(300)

    # Check it's hidden
    expect(sidebar).to_have_class("hidden")

    # Check it's visually off-screen
    box = sidebar.bounding_box()
    assert box['x'] + box['width'] <= 0, "Sidebar still visible!"

def test_context_menu_position(page):
    """Bug #2: Context menu should appear near click"""
    # Find a chat item
    chat_item = page.locator(".history-item").first

    # Right-click to open menu
    chat_item.click(button="right")

    # Get menu position
    menu = page.locator(".history-menu")
    expect(menu).to_be_visible()

    menu_box = menu.bounding_box()
    item_box = chat_item.bounding_box()

    # Menu should be within 50px of click location
    y_diff = abs(menu_box['y'] - item_box['y'])
    assert y_diff < 50, f"Menu too far from click: {y_diff}px"

def test_no_duplicate_stop_buttons(page):
    """Bug #3: Only ONE stop button during send"""
    # Type message
    page.fill("#messageInput", "Test message")

    # Send message
    page.click(".send-btn")

    # Wait for streaming to start
    page.wait_for_timeout(500)

    # Count STOP buttons
    stop_buttons = page.locator("[data-state='stop'], .send-btn:has-text('STOP')")
    count = stop_buttons.count()

    assert count == 1, f"Found {count} STOP buttons, expected 1"

def test_send_button_arrow_only(page):
    """Bug #4: Send button should show arrow, not 'SEND' text"""
    send_btn = page.locator(".send-btn")

    # Check button doesn't contain 'SEND' text
    text_content = send_btn.text_content()
    assert "SEND" not in text_content, "Send button shows 'SEND' text"

    # Check button has arrow icon (➤ or similar)
    # This depends on your implementation

def test_debug_button_works(page):
    """Bug #5: Debug quick action should work"""
    # Click debug button
    debug_btn = page.locator("button:has-text('Debug')")
    debug_btn.click()

    # Check debug panel appears
    debug_panel = page.locator("#debugPanel, .debug-panel")
    expect(debug_panel).to_be_visible()

def test_plugins_load(page):
    """Bug #6: Plugins should load and display"""
    # Wait for plugins to load (may be async)
    page.wait_for_timeout(2000)

    # Check plugin section has items
    plugins = page.locator(".plugin-item, .sidebar-section:has-text('Plugins') .history-item")
    count = plugins.count()

    assert count > 0, "No plugins loaded"

def test_file_explorer_navigation(page):
    """Bug #7: File explorer should navigate"""
    # Open file explorer
    page.click("button:has-text('Files')")

    # Wait for file list
    file_list = page.locator("#filesPanel .file-item")
    expect(file_list.first).to_be_visible()

    # Click a folder
    folder = page.locator(".file-item[data-type='directory']").first
    if folder.count() > 0:
        folder.click()

        # Check navigation happened (URL or content changed)
        # Implementation depends on your file explorer

def test_placeholder_customization(page):
    """Bug #8: Placeholder should have submit button"""
    # Open settings or placeholder customization
    # This test depends on where the feature is located

    page.click("button:has-text('Settings')")
    page.click("text=Placeholder")

    # Look for submit/save button
    submit_btn = page.locator("button:has-text('Save'), button:has-text('Submit')")
    expect(submit_btn).to_be_visible()

# Visual regression tests
def test_visual_sidebar_closed(page):
    """Visual: Sidebar closed layout"""
    page.click(".toggle-btn")
    page.wait_for_timeout(300)
    expect(page).to_have_screenshot("sidebar-closed.png")

def test_visual_context_menu(page):
    """Visual: Context menu position"""
    page.locator(".history-item").first.click(button="right")
    expect(page).to_have_screenshot("context-menu.png")

# Performance tests
def test_page_load_time(page):
    """Performance: Page loads in < 3 seconds"""
    import time
    start = time.time()
    page.goto("http://localhost:8010")
    page.wait_for_load_state("networkidle")
    duration = time.time() - start

    assert duration < 3.0, f"Page took {duration}s to load"
```

**Run tests:**
```bash
pytest tests/e2e/test_frontend_bugs.py -v
pytest tests/e2e/test_frontend_bugs.py::test_sidebar_hiding  # Run one test
pytest tests/ --headed  # See browser window
pytest tests/ --screenshot=on --video=on  # Record everything
```

---

## Next Steps

Would you like me to:

1. ✅ **Create the full Playwright test suite** (all 8 bugs + visual regression)?
2. ✅ **Setup Sentry for production error tracking**?
3. ✅ **Create automated Lighthouse performance tests**?
4. ✅ **Setup CI/CD to run tests on every commit**?

Let me know which ones you want, and I'll build them now!

---

**TL;DR:**
- **Playwright** = Automated browser testing (catches runtime & UX bugs)
- **Lighthouse** = Performance testing (catches slow code)
- **Sentry** = Production error tracking (catches bugs users hit)
- **All FREE** and can catch the bugs static analysis can't!

I can set these up for you right now. Which would you like first?
