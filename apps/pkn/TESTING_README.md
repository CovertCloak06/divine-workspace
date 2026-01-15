## 🚀 PKN Automated Testing Suite - Complete Guide

**Status**: ✅ Fully Implemented
**Date**: 2026-01-11
**Time to Setup**: 10 minutes
**Cost**: $0/month (all free tools)

---

## What's Included

Your PKN project now has **professional-grade automated testing** that catches bugs before users see them:

### ✅ **E2E Tests** (Playwright)
- Tests all 8 documented frontend bugs automatically
- Runs in real browser (Chromium)
- Takes screenshots/videos of failures
- **Run with**: `./scripts/run-tests.sh e2e`

### ✅ **Visual Regression Tests**
- Compares screenshots to detect layout changes
- Catches CSS bugs automatically
- Baseline management included
- **Run with**: `./scripts/run-tests.sh visual`

### ✅ **Performance Tests**
- Page load < 3 seconds
- No memory leaks
- Fast API responses
- **Run with**: `./scripts/run-tests.sh performance`

### ✅ **Sentry Error Tracking**
- Catches ALL production errors
- Stack traces + user context
- Session replay videos
- **Setup guide**: `SENTRY_SETUP.md`

### ✅ **CI/CD Pipeline** (GitHub Actions)
- Runs all tests on every commit
- Automatic screenshots on failure
- Performance reports
- **File**: `.github/workflows/test.yml`

---

## Quick Start (5 Minutes)

### 1. Install Dependencies

```bash
# Install Python testing dependencies
pip install -r requirements-test.txt

# Install Playwright browsers
playwright install chromium

# Verify installation
pytest --version
playwright --version
```

### 2. Run Your First Test

```bash
# Make sure PKN server is running
./pkn_control.sh start-all

# Run E2E tests for all 8 bugs
./scripts/run-tests.sh e2e

# Or run all tests
./scripts/run-tests.sh all
```

### 3. View Results

- **Console**: See pass/fail in terminal
- **Screenshots**: `tests/screenshots/comparison/` (on failures)
- **Videos**: `tests/screenshots/videos/` (on failures)
- **Report**: `pytest-report.html` (if HTML report enabled)

---

## Test Commands Reference

### Using the Test Runner Script

```bash
# E2E tests (all 8 frontend bugs)
./scripts/run-tests.sh e2e

# Visual regression tests
./scripts/run-tests.sh visual

# Performance tests
./scripts/run-tests.sh performance

# All tests
./scripts/run-tests.sh all

# Lighthouse audit
./scripts/run-tests.sh lighthouse

# Update visual baselines
./scripts/run-tests.sh baselines
```

### Options

```bash
# Run with visible browser (good for debugging)
./scripts/run-tests.sh e2e --headed

# Keep server running after tests
./scripts/run-tests.sh e2e --keep-server

# Record all test videos
./scripts/run-tests.sh e2e --video=on
```

### Using pytest Directly

```bash
# Run specific test file
pytest tests/e2e/test_frontend_bugs.py -v

# Run specific test
pytest tests/e2e/test_frontend_bugs.py::TestFrontendBugs::test_bug1_sidebar_fully_hides -v

# Run with markers
pytest -m e2e -v              # Only E2E tests
pytest -m visual -v           # Only visual tests
pytest -m "bug and critical" -v  # Critical bug tests only

# Run in parallel (faster)
pytest tests/e2e/ -n auto -v

# Generate HTML report
pytest tests/e2e/ -v --html=report.html --self-contained-html
```

---

## What Each Test Does

### E2E Tests (`tests/e2e/test_frontend_bugs.py`)

**Tests all 8 documented bugs**:

1. ✅ **Sidebar Hiding** - Verifies sidebar fully hides (Bug #1)
   - Checks `transform: translateX(-100%)`
   - Verifies `visibility: hidden`
   - Measures position (should be off-screen)

2. ✅ **Context Menu Position** - Menu appears near click (Bug #2)
   - Right-clicks history item
   - Measures menu distance from click
   - Asserts < 50px difference

3. ✅ **No Duplicate STOP Buttons** - Only ONE stop button (Bug #3)
   - Tests at 3 window sizes (1920x1080, 1366x768, 1024x768)
   - Sends message, waits for streaming
   - Counts STOP buttons (must be ≤ 1)

4. ✅ **Send Button Arrow Only** - No "SEND" text (Bug #4)
   - Checks button text content
   - Asserts "SEND" not present
   - Verifies arrow icon exists

5. ✅ **Debug Button Works** - Opens debug panel (Bug #5)
   - Clicks debug quick action
   - Waits for debug panel
   - Asserts panel is visible

6. ✅ **Plugins Load** - Displays plugin list (Bug #6)
   - Waits 3 seconds for async loading
   - Counts plugin items
   - Asserts > 0 plugins found

7. ✅ **File Explorer Navigation** - Can browse files (Bug #7)
   - Opens file explorer
   - Clicks folder
   - Verifies navigation occurred

8. ✅ **Placeholder Submit Button** - Save mechanism exists (Bug #8)
   - Opens settings
   - Finds placeholder input
   - Asserts submit button present

**Also tests critical paths**:
- Send and receive message
- Page loads without errors
- All essential UI elements present

### Visual Tests (`tests/visual/test_visual_regression.py`)

**Captures screenshots and compares**:

- Welcome screen layout
- Sidebar open/closed states
- Chat with messages
- Context menu position
- Settings modal
- Send button (normal and STOP states)
- Responsive layouts (4 viewport sizes)
- OSINT tools panel
- File explorer
- Plugins section
- Code blocks with syntax highlighting
- Toast notifications
- Dark/light themes

**How it works**:
1. Takes screenshot of UI element
2. Compares to baseline screenshot
3. Highlights pixel differences
4. Fails test if differences exceed threshold

### Performance Tests (`tests/performance/test_performance.py`)

**Measures speed and efficiency**:

- **Page Load**: < 3 seconds
- **DOM Interactive**: < 1 second
- **First Paint**: < 1 second
- **Message Send**: UI updates < 500ms
- **Sidebar Animation**: < 600ms
- **Input Lag**: < 100ms
- **Memory Leaks**: < 50MB growth after 10 messages
- **Scroll Performance**: < 200ms
- **API Response Times**:
  - Health endpoint: < 100ms
  - Chat API: < 2 seconds to start
- **Lighthouse Metrics**:
  - First Contentful Paint: < 1.8s
  - Render-blocking resources: < 5
- **Modal Open/Close**: < 300ms
- **Context Menu**: < 100ms

---

## CI/CD Integration

### What Happens on Git Push

Every time you push code to GitHub:

1. **Backend Tests** run (if you have them)
2. **E2E Tests** run all 8 bug checks
3. **Visual Tests** compare against baselines
4. **Performance Tests** ensure speed targets met
5. **Lighthouse Audit** checks performance score

### Viewing Results

1. Go to GitHub repository
2. Click "Actions" tab
3. Click on latest workflow run
4. See pass/fail for each test suite

### Artifacts on Failure

If tests fail, GitHub Actions uploads:
- 📸 **Screenshots** of failures
- 🎥 **Videos** of test execution
- 📊 **HTML reports** with details
- ⚡ **Performance metrics**

Download from Actions → Workflow Run → Artifacts

### Manual Trigger

Run tests without pushing code:

1. Go to Actions tab
2. Click "PKN Automated Tests"
3. Click "Run workflow"
4. Choose branch
5. Click "Run"

---

## Sentry Error Tracking

### Setup (10 minutes)

1. **Create account**: https://sentry.io/signup/
2. **Create project**: "PKN-Frontend" (JavaScript)
3. **Copy DSN**: `https://abc@o123.ingest.sentry.io/456`
4. **Add to HTML**: See `SENTRY_SETUP.md` for code snippet

### What It Captures

- ✅ All JavaScript errors with stack traces
- ✅ User context (what they were doing)
- ✅ Session replay (video of their session)
- ✅ Performance issues (slow API calls)
- ✅ Breadcrumbs (events leading to error)

### Integration with PKNLogger

Sentry automatically integrates with your PKNLogger:
- All `error` level logs sent to Sentry
- All logs become breadcrumbs
- Network requests tracked

### Dashboard

View errors at: https://sentry.io/organizations/your-org/projects/

Shows:
- Error count and affected users
- Stack traces with line numbers
- Session replays
- Trends over time
- Email/Slack alerts

---

## Troubleshooting

### "Tests can't connect to server"

```bash
# Manually start server
./pkn_control.sh start-all

# Verify it's running
curl http://localhost:8010/health

# Run tests with existing server
KEEP_SERVER=true ./scripts/run-tests.sh e2e
```

### "Playwright browsers not installed"

```bash
playwright install chromium
playwright install-deps  # Install system dependencies
```

### "Tests are flaky (pass/fail randomly)"

```bash
# Run test multiple times
pytest tests/e2e/test_frontend_bugs.py::test_name --count=5 -v

# Add explicit waits in test code
page.wait_for_timeout(500)  # Wait 500ms
page.wait_for_selector(".element", state="visible")  # Wait for element
```

### "Visual tests always fail"

```bash
# Update baselines (after verifying changes are correct)
./scripts/run-tests.sh baselines

# Or manually
pytest tests/visual/ --update-snapshots
```

### "Performance tests fail locally but pass in CI"

Performance tests are sensitive to system load. If your machine is busy:

```bash
# Skip performance tests locally
pytest tests/e2e/ tests/visual/ -v  # Skip tests/performance/

# Or mark as xfail
pytest tests/performance/ -v --runxfail
```

### "Tests take too long"

```bash
# Run in parallel (requires pytest-xdist)
pytest tests/e2e/ -n auto -v  # Auto-detect CPU cores

# Run specific tests only
pytest tests/e2e/test_frontend_bugs.py::TestFrontendBugs::test_bug1_sidebar_fully_hides -v

# Use markers
pytest -m "critical and not slow" -v
```

---

## File Structure

```
apps/pkn/
├── tests/
│   ├── conftest.py                 # Shared fixtures
│   ├── e2e/
│   │   └── test_frontend_bugs.py   # All 8 bug tests
│   ├── visual/
│   │   └── test_visual_regression.py
│   ├── performance/
│   │   └── test_performance.py
│   └── screenshots/
│       ├── baseline/                # Reference images
│       ├── comparison/              # Test screenshots
│       └── videos/                  # Test recordings
│
├── .github/workflows/
│   └── test.yml                     # CI/CD configuration
│
├── scripts/
│   └── run-tests.sh                 # Test runner script
│
├── frontend/js/utils/
│   ├── logger.js                    # PKNLogger (already built)
│   └── sentry-init.js               # Sentry integration
│
├── pytest.ini                       # Pytest configuration
├── requirements-test.txt            # Test dependencies
├── .lighthouserc.json               # Lighthouse config
│
└── Documentation:
    ├── TESTING_README.md            # This file
    ├── AUTOMATED_TESTING_TOOLS.md   # Tool comparison
    ├── SENTRY_SETUP.md              # Sentry guide
    ├── MANUAL_TESTING_CHECKLIST.md  # Manual tests
    └── LOGGING_AND_DEBUGGING_IMPROVEMENTS.md
```

---

## Best Practices

### When to Run Tests

**Locally**:
- ✅ Before committing code
- ✅ After fixing a bug
- ✅ After adding a feature
- ✅ Before creating PR

**In CI**:
- ✅ On every push (automatic)
- ✅ On every PR (automatic)
- ✅ Daily scheduled run (catches regressions)
- ✅ Before deploying to production

### Writing New Tests

1. **Add to existing test file** if related:
   ```python
   def test_new_feature(page: Page):
       """Test description"""
       # Test code here
   ```

2. **Use fixtures** from `conftest.py`:
   ```python
   def test_with_message(page: Page, send_message):
       send_message("Hello")
       # Test continues...
   ```

3. **Mark tests appropriately**:
   ```python
   @pytest.mark.e2e
   @pytest.mark.slow
   def test_large_file_upload(page: Page):
       # ...
   ```

4. **Add descriptive assertions**:
   ```python
   assert count == 1, f"Found {count} buttons (expected 1)"
   ```

### Maintaining Tests

**Update baselines** when UI changes intentionally:
```bash
./scripts/run-tests.sh baselines
git add tests/screenshots/baseline/
git commit -m "Update visual test baselines"
```

**Keep tests fast**:
- Use `page.wait_for_selector()` instead of `wait_for_timeout()`
- Run expensive tests in parallel
- Mark slow tests with `@pytest.mark.slow`

**Review failures** quickly:
- Check screenshot in `tests/screenshots/comparison/`
- Watch video in `tests/screenshots/videos/`
- Read error message carefully

---

## Advanced Usage

### Running Tests in Docker

```bash
# Build test image
docker build -f Dockerfile.test -t pkn-tests .

# Run tests
docker run --rm pkn-tests pytest tests/e2e/ -v
```

### Pre-commit Hook

Add to `.git/hooks/pre-commit`:

```bash
#!/bin/bash
# Run critical tests before allowing commit

echo "Running critical tests..."
./scripts/run-tests.sh e2e -m critical

if [ $? -ne 0 ]; then
    echo "Tests failed! Commit aborted."
    exit 1
fi
```

### Custom Test Reports

Generate JSON report for analysis:

```bash
pytest tests/e2e/ -v --json-report --json-report-file=test-results.json
```

Parse with:

```python
import json
data = json.load(open('test-results.json'))
print(f"Tests run: {data['summary']['total']}")
print(f"Passed: {data['summary']['passed']}")
print(f"Failed: {data['summary']['failed']}")
```

---

## Cost Summary

| Tool | Purpose | Cost |
|------|---------|------|
| Playwright | E2E + Visual testing | FREE |
| pytest | Test framework | FREE |
| GitHub Actions | CI/CD (2000 min/month) | FREE |
| Sentry | Error tracking (5k errors/mo) | FREE |
| Lighthouse | Performance auditing | FREE |
| **Total** | **Complete test suite** | **$0/month** |

---

## What's Next?

### Optional Enhancements

1. **Add Backend Tests**: Test Flask API endpoints
2. **Integration Tests**: Test frontend + backend together
3. **Load Testing**: Use Locust to test under load
4. **Accessibility Tests**: Use axe-core for a11y
5. **Security Tests**: Add OWASP ZAP scanning

### Monitoring in Production

1. **Setup Sentry**: See `SENTRY_SETUP.md`
2. **Add Analytics**: Track feature usage
3. **Real User Monitoring**: Performance in the wild
4. **Uptime Monitoring**: UptimeRobot (free)

---

## Summary

**You now have**:
- ✅ Automated tests for all 8 frontend bugs
- ✅ Visual regression testing
- ✅ Performance monitoring
- ✅ CI/CD pipeline
- ✅ Error tracking (Sentry setup)
- ✅ Easy test runner scripts

**Run tests**:
```bash
./scripts/run-tests.sh all
```

**Setup Sentry** (optional but recommended):
```bash
# See SENTRY_SETUP.md for 10-minute guide
```

**Questions?** Check the other docs:
- `AUTOMATED_TESTING_TOOLS.md` - Tool comparison
- `SENTRY_SETUP.md` - Production error tracking
- `MANUAL_TESTING_CHECKLIST.md` - Complement to automated tests

---

**Built with**: Playwright, pytest, Sentry, GitHub Actions
**Cost**: $0/month
**Maintenance**: ~1 hour/month (reviewing test results)
**Value**: Catches bugs before users see them! 🎯
