"""
E2E Tests for PKN Frontend Bugs
Tests all 8 critical bugs documented in FRONTEND_BUGS.md

Run with: pytest tests/e2e/test_frontend_bugs.py -v
"""
import pytest
import re
from playwright.sync_api import Page, expect


@pytest.mark.e2e
@pytest.mark.bug
@pytest.mark.critical
class TestFrontendBugs:
    """Test suite for documented frontend bugs"""

    def test_bug1_sidebar_fully_hides(self, page: Page):
        """
        Bug #1: Sidebar doesn't hide completely
        Expected: Sidebar fully hidden when closed (transform: translateX(-100%))
        Actual: Sticks out ~1/3 of the way
        """
        # Wait for page to load
        page.wait_for_load_state("networkidle")

        # Find sidebar
        sidebar = page.locator(".sidebar")
        expect(sidebar).to_be_visible()

        # Find and click toggle button to close sidebar
        toggle_btn = page.locator(".toggle-btn")
        toggle_btn.click()

        # Wait for animation to complete
        page.wait_for_timeout(500)

        # Check sidebar has 'hidden' class
        expect(sidebar).to_have_class(re.compile(r".*hidden.*"))

        # Check sidebar is fully off-screen
        # Get bounding box
        box = sidebar.bounding_box()
        assert box is not None, "Sidebar bounding box not found"

        # Sidebar should be completely off-screen (x + width <= 0)
        right_edge = box['x'] + box['width']
        assert right_edge <= 5, f"Sidebar still visible! Right edge at {right_edge}px (should be ≤0)"

        # Check visibility is hidden
        is_visible = sidebar.evaluate("el => getComputedStyle(el).visibility")
        assert is_visible == "hidden", f"Sidebar visibility should be 'hidden', got '{is_visible}'"

    def test_bug2_context_menu_positioning(self, page: Page):
        """
        Bug #2: Context menu appears way lower than it should
        Expected: Menu appears near click location
        Actual: Menu appears way lower than click point
        """
        page.wait_for_load_state("networkidle")

        # Create a test chat first (needed for context menu)
        # Type and send a message to create a chat item
        if page.locator("#messageInput").is_visible():
            page.fill("#messageInput", "Test message for context menu")
            page.click(".send-btn")
            page.wait_for_timeout(2000)

        # Find a history item (chat in sidebar)
        history_item = page.locator(".history-item").first

        if history_item.count() == 0:
            pytest.skip("No history items available to test context menu")

        # Get position of history item
        item_box = history_item.bounding_box()

        # Right-click to open context menu
        history_item.click(button="right")

        # Wait for menu to appear
        menu = page.locator(".history-menu, .context-menu")
        expect(menu).to_be_visible(timeout=2000)

        # Get menu position
        menu_box = menu.bounding_box()

        # Menu should appear close to click location (within 50px vertically)
        y_diff = abs(menu_box['y'] - (item_box['y'] + item_box['height']))

        assert y_diff < 50, f"Context menu too far from click: {y_diff}px away (should be <50px)"

    def test_bug3_no_duplicate_stop_buttons(self, page: Page, send_message):
        """
        Bug #3: Two STOP buttons appear
        Expected: Only ONE STOP button during streaming
        Actual: Two STOP buttons visible at certain window sizes
        """
        page.wait_for_load_state("networkidle")

        # Test at multiple window sizes (bug appears at certain sizes)
        test_sizes = [
            {"width": 1920, "height": 1080},  # Full HD
            {"width": 1366, "height": 768},   # Laptop
            {"width": 1024, "height": 768},   # Tablet
        ]

        for size in test_sizes:
            # Set viewport size
            page.set_viewport_size(size)
            page.wait_for_timeout(300)

            # Send a message to trigger streaming
            page.fill("#messageInput", "Count to 10 slowly")
            page.click(".send-btn")

            # Wait a moment for streaming to start
            page.wait_for_timeout(500)

            # Count STOP buttons
            # Look for buttons with "STOP" text or data-state="stop" attribute
            stop_buttons = page.locator(".send-btn[data-state='stop'], button:has-text('STOP')")

            count = stop_buttons.count()

            # Take screenshot if duplicate found
            if count > 1:
                page.screenshot(path=f"tests/screenshots/comparison/duplicate-stop-{size['width']}x{size['height']}.png")

            assert count <= 1, f"Found {count} STOP buttons at {size['width']}x{size['height']} (expected 1)"

            # Click stop to end streaming
            if count == 1:
                stop_buttons.first.click()
                page.wait_for_timeout(500)

    def test_bug4_send_button_arrow_only(self, page: Page):
        """
        Bug #4: Send button shows "SEND" + arrow
        Expected: Just arrow icon (➤)
        Actual: Shows "SEND" text + arrow
        """
        page.wait_for_load_state("networkidle")

        # Find send button
        send_btn = page.locator(".send-btn")
        expect(send_btn).to_be_visible()

        # Get button text content
        text_content = send_btn.text_content()

        # Button should NOT contain "SEND" text (only arrow icon)
        assert "SEND" not in text_content.upper(), f"Send button shows 'SEND' text: '{text_content}' (should only show arrow icon)"

        # Check if button has arrow (➤ or similar Unicode arrow)
        # Common arrow characters: ➤ ▶ → ⏵
        has_arrow = any(char in text_content for char in ["➤", "▶", "→", "⏵", "►"])

        # Or check for SVG/icon element
        has_icon = send_btn.locator("svg, .icon, i").count() > 0

        assert has_arrow or has_icon, "Send button should have an arrow icon"

    def test_bug5_debug_quick_action_works(self, page: Page):
        """
        Bug #5: Debug quick action doesn't do anything
        Expected: Opens debug panel
        Actual: Nothing happens on click
        """
        page.wait_for_load_state("networkidle")

        # Look for debug button in welcome screen or quick actions
        debug_btn = page.locator("button:has-text('Debug'), .quick-action:has-text('Debug')")

        if debug_btn.count() == 0:
            pytest.skip("Debug button not found (may be removed or renamed)")

        # Click debug button
        debug_btn.first.click()

        # Wait for debug panel/modal to appear
        page.wait_for_timeout(500)

        # Check for debug panel, debugger modal, or DevTools extension
        debug_panel = page.locator("#debugPanel, .debug-panel, .debugger-modal, [data-panel='debug']")

        is_visible = debug_panel.is_visible()

        assert is_visible, "Debug panel did not open after clicking Debug button"

    def test_bug6_plugins_load_and_display(self, page: Page):
        """
        Bug #6: Plugins missing/not working
        Expected: List of available plugins
        Actual: No plugins shown
        """
        page.wait_for_load_state("networkidle")

        # Wait extra time for plugins to load async
        page.wait_for_timeout(3000)

        # Look for plugins section in sidebar
        plugins_section = page.locator(".sidebar-section:has-text('Plugins'), #pluginsSection")

        if plugins_section.count() == 0:
            pytest.skip("Plugins section not found in sidebar")

        # Check if plugins section is collapsed
        is_collapsed = plugins_section.evaluate("el => el.classList.contains('collapsed')")

        if is_collapsed:
            # Expand plugins section
            plugins_header = page.locator(".sidebar-section-header:has-text('Plugins')")
            plugins_header.click()
            page.wait_for_timeout(300)

        # Look for plugin items
        plugin_items = page.locator(".plugin-item, .sidebar-section:has-text('Plugins') .history-item")

        count = plugin_items.count()

        # Take screenshot for debugging
        if count == 0:
            page.screenshot(path="tests/screenshots/comparison/no-plugins-loaded.png")

        assert count > 0, f"No plugins loaded (found {count} plugin items)"

    def test_bug7_file_explorer_navigation_works(self, page: Page):
        """
        Bug #7: File explorer navigation broken
        Expected: Can navigate file system
        Actual: Navigation doesn't work
        Note: File upload button (paperclip) DOES work
        """
        page.wait_for_load_state("networkidle")

        # Open file explorer from sidebar
        files_btn = page.locator("button:has-text('Files'), .sidebar-section-header:has-text('Files')")

        if files_btn.count() == 0:
            pytest.skip("Files button not found")

        files_btn.first.click()
        page.wait_for_timeout(500)

        # Check if file explorer panel appears
        files_panel = page.locator("#filesPanel, .files-panel, .file-explorer")

        expect(files_panel).to_be_visible()

        # Look for file list or file tree
        file_list = page.locator(".file-item, .file-tree-item, .file-entry")

        if file_list.count() == 0:
            # No files yet, check if there's an upload prompt
            upload_prompt = page.locator("text=/upload|drop|no files/i")
            has_prompt = upload_prompt.count() > 0
            assert has_prompt, "File explorer opened but shows no files or upload prompt"
            pytest.skip("No files to test navigation")

        # Try clicking a folder if one exists
        folder = page.locator(".file-item[data-type='directory'], .folder, .file-tree-item.directory").first

        if folder.count() > 0:
            # Get current state (path or file count)
            initial_state = page.evaluate("() => document.querySelector('.current-path, .breadcrumb')?.textContent || ''")

            # Click folder
            folder.click()
            page.wait_for_timeout(300)

            # Check if navigation happened (state changed)
            new_state = page.evaluate("() => document.querySelector('.current-path, .breadcrumb')?.textContent || ''")

            assert initial_state != new_state, "File explorer navigation did not update (state unchanged)"

    def test_bug8_placeholder_customization_has_submit(self, page: Page):
        """
        Bug #8: Placeholder customization no submit button
        Expected: Way to submit/save placeholder changes
        Actual: No submit button/mechanism
        """
        page.wait_for_load_state("networkidle")

        # Open settings (where placeholder customization likely is)
        settings_btn = page.locator("button:has-text('Settings'), [data-action='settings']")

        if settings_btn.count() == 0:
            pytest.skip("Settings button not found")

        settings_btn.first.click()
        page.wait_for_timeout(500)

        # Look for placeholder customization section
        placeholder_section = page.locator("text=/placeholder|input.*text/i").first

        if placeholder_section.count() == 0:
            pytest.skip("Placeholder customization section not found")

        # Scroll to placeholder section
        placeholder_section.scroll_into_view_if_needed()

        # Look for placeholder input field
        placeholder_input = page.locator("input[placeholder*='placeholder'], input[name*='placeholder'], textarea[name*='placeholder']")

        if placeholder_input.count() == 0:
            pytest.skip("Placeholder input field not found")

        # Look for submit/save button near placeholder input
        # Check within same container or modal
        container = placeholder_input.locator("xpath=ancestor::div[@class][1]")

        submit_btn = container.locator("button:has-text('Save'), button:has-text('Submit'), button:has-text('Apply'), button[type='submit']")

        has_submit = submit_btn.count() > 0

        # Take screenshot for debugging
        if not has_submit:
            page.screenshot(path="tests/screenshots/comparison/placeholder-no-submit.png")

        assert has_submit, "Placeholder customization has no submit/save button"


# Additional helper tests
@pytest.mark.e2e
class TestCriticalPaths:
    """Tests for critical user paths"""

    def test_send_and_receive_message(self, page: Page, send_message, check_console_errors):
        """Critical: User can send message and receive response"""
        page.wait_for_load_state("networkidle")

        # Send message
        send_message("Hello, this is a test message", wait_for_response=True)

        # Check response appeared
        messages = page.locator(".message")
        assert messages.count() >= 2, "No response received"

        # Check for console errors
        errors = check_console_errors()
        assert len(errors) == 0, f"JavaScript errors during chat: {errors}"

    def test_page_loads_without_errors(self, page: Page, check_console_errors):
        """Critical: Page loads without JavaScript errors"""
        page.wait_for_load_state("networkidle")

        # Wait a bit for async loading
        page.wait_for_timeout(2000)

        # Check for errors
        errors = check_console_errors()

        # Filter out known harmless errors (if any)
        critical_errors = [e for e in errors if "failed to load" not in e["text"].lower()]

        assert len(critical_errors) == 0, f"Page has JavaScript errors: {critical_errors}"

    def test_all_critical_elements_present(self, page: Page):
        """Critical: All essential UI elements are present"""
        page.wait_for_load_state("networkidle")

        critical_elements = {
            "Message input": "#messageInput",
            "Send button": ".send-btn",
            "Messages container": "#messagesContainer",
            "Sidebar": ".sidebar",
            "Toggle button": ".toggle-btn",
        }

        missing = []
        for name, selector in critical_elements.items():
            if page.locator(selector).count() == 0:
                missing.append(name)

        assert len(missing) == 0, f"Missing critical elements: {missing}"
