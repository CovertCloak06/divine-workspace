"""
Pytest configuration and shared fixtures for PKN tests
"""
import pytest
import os
from pathlib import Path
from playwright.sync_api import sync_playwright, Browser, Page, BrowserContext

# Test configuration
BASE_URL = os.getenv("PKN_TEST_URL", "http://localhost:8010")
HEADLESS = os.getenv("PKN_TEST_HEADLESS", "true").lower() == "true"
SCREENSHOT_DIR = Path(__file__).parent / "screenshots"
BASELINE_DIR = SCREENSHOT_DIR / "baseline"
COMPARISON_DIR = SCREENSHOT_DIR / "comparison"

# Ensure screenshot directories exist
BASELINE_DIR.mkdir(parents=True, exist_ok=True)
COMPARISON_DIR.mkdir(parents=True, exist_ok=True)


@pytest.fixture(scope="session")
def browser_type_launch_args():
    """Browser launch arguments"""
    return {
        "headless": HEADLESS,
        "args": [
            "--disable-blink-features=AutomationControlled",
            "--no-sandbox",
        ],
    }


@pytest.fixture(scope="session")
def browser_context_args():
    """Browser context arguments"""
    return {
        "viewport": {"width": 1920, "height": 1080},
        "screen": {"width": 1920, "height": 1080},
        "ignore_https_errors": True,
        "record_video_dir": SCREENSHOT_DIR / "videos" if os.getenv("RECORD_VIDEO") else None,
    }


@pytest.fixture
def page(browser: Browser, browser_context_args):
    """
    Provides a fresh browser page for each test
    Automatically navigates to BASE_URL
    """
    context = browser.new_context(**browser_context_args)
    page = context.new_page()

    # Setup console message capturing
    console_messages = []
    page.on("console", lambda msg: console_messages.append({
        "type": msg.type,
        "text": msg.text,
        "location": msg.location,
    }))

    # Setup error capturing
    page_errors = []
    page.on("pageerror", lambda err: page_errors.append(str(err)))

    # Attach captured data to page object
    page.console_messages = console_messages
    page.page_errors = page_errors

    # Navigate to base URL
    page.goto(BASE_URL, wait_until="networkidle")

    yield page

    # Cleanup
    context.close()


@pytest.fixture
def authenticated_page(page: Page):
    """
    Page with authentication (if needed)
    Currently PKN doesn't require auth, but this is here for future use
    """
    # If you add authentication later, login here
    return page


@pytest.fixture
def wait_for_pkn_ready(page: Page):
    """
    Wait for PKN to be fully initialized
    Checks that pknLogger exists and welcome screen or messages loaded
    """
    def _wait():
        page.wait_for_function("""
            window.pknLogger !== undefined &&
            (document.getElementById('welcomeScreen') !== null ||
             document.getElementById('messagesContainer')?.children.length > 0)
        """, timeout=10000)

    return _wait


@pytest.fixture
def send_message(page: Page):
    """
    Helper function to send a chat message
    """
    def _send(message_text: str, wait_for_response: bool = True):
        # Type message
        page.fill("#messageInput", message_text)

        # Click send
        page.click(".send-btn")

        if wait_for_response:
            # Wait for response to appear (look for assistant message)
            page.wait_for_selector(".message.assistant", timeout=30000)

        return page

    return _send


@pytest.fixture
def clear_chat(page: Page):
    """
    Helper to clear chat and start fresh
    """
    def _clear():
        # Click new chat button if it exists
        new_chat_btn = page.locator("button:has-text('New Chat'), button[title*='New']")
        if new_chat_btn.count() > 0:
            new_chat_btn.first.click()

        return page

    return _clear


@pytest.fixture
def take_screenshot(page: Page):
    """
    Helper to take and save screenshots
    """
    def _screenshot(name: str, full_page: bool = False):
        screenshot_path = COMPARISON_DIR / f"{name}.png"
        page.screenshot(path=str(screenshot_path), full_page=full_page)
        return screenshot_path

    return _screenshot


@pytest.fixture
def check_console_errors(page: Page):
    """
    Check for JavaScript console errors
    """
    def _check():
        errors = [msg for msg in page.console_messages if msg["type"] == "error"]
        page_errors = page.page_errors

        all_errors = errors + [{"type": "exception", "text": err} for err in page_errors]

        return all_errors

    return _check


@pytest.fixture(autouse=True)
def test_timing(request):
    """
    Automatically time each test
    """
    import time
    start = time.time()
    yield
    duration = time.time() - start

    # Add timing to test report
    request.node.user_properties.append(("duration", f"{duration:.2f}s"))


# Markers
def pytest_configure(config):
    """Register custom markers"""
    config.addinivalue_line("markers", "e2e: End-to-end browser tests")
    config.addinivalue_line("markers", "visual: Visual regression tests")
    config.addinivalue_line("markers", "performance: Performance tests")
    config.addinivalue_line("markers", "bug: Tests for specific bug fixes")
    config.addinivalue_line("markers", "critical: Critical path tests")


# Test reporting hooks
def pytest_runtest_makereport(item, call):
    """
    Attach screenshot to failed tests
    """
    if call.when == "call" and call.excinfo is not None:
        # Test failed, take screenshot
        if hasattr(item, "funcargs") and "page" in item.funcargs:
            page = item.funcargs["page"]
            screenshot_path = COMPARISON_DIR / f"FAILED-{item.name}.png"
            try:
                page.screenshot(path=str(screenshot_path))
                print(f"\n📸 Screenshot saved: {screenshot_path}")
            except Exception as e:
                print(f"\n❌ Failed to take screenshot: {e}")
