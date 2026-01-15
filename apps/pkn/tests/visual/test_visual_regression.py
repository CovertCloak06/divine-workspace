"""
Visual Regression Tests for PKN
Compares screenshots against baseline to detect visual changes

Run with: pytest tests/visual/ -v
Update baselines: pytest tests/visual/ --update-snapshots
"""
import pytest
from playwright.sync_api import Page, expect


@pytest.mark.visual
class TestVisualRegression:
    """Visual regression test suite"""

    def test_visual_welcome_screen(self, page: Page):
        """Visual: Welcome screen layout"""
        page.wait_for_load_state("networkidle")

        # Ensure welcome screen is visible
        welcome = page.locator("#welcomeScreen, .welcome-screen")
        if welcome.count() > 0 and welcome.is_visible():
            expect(page).to_have_screenshot("welcome-screen.png", full_page=True)
        else:
            pytest.skip("Welcome screen not visible")

    def test_visual_sidebar_open(self, page: Page):
        """Visual: Sidebar in open state"""
        page.wait_for_load_state("networkidle")

        # Ensure sidebar is open
        sidebar = page.locator(".sidebar")
        if "hidden" in sidebar.get_attribute("class"):
            page.click(".toggle-btn")
            page.wait_for_timeout(500)

        expect(page).to_have_screenshot("sidebar-open.png", full_page=True)

    def test_visual_sidebar_closed(self, page: Page):
        """Visual: Sidebar in closed state (Bug #1)"""
        page.wait_for_load_state("networkidle")

        # Close sidebar
        sidebar = page.locator(".sidebar")
        if "hidden" not in sidebar.get_attribute("class"):
            page.click(".toggle-btn")
            page.wait_for_timeout(500)

        expect(page).to_have_screenshot("sidebar-closed.png", full_page=True)

    def test_visual_chat_with_messages(self, page: Page, send_message):
        """Visual: Chat interface with messages"""
        page.wait_for_load_state("networkidle")

        # Send a test message
        send_message("Hello, this is a test message")

        # Wait for response
        page.wait_for_selector(".message.assistant", timeout=30000)

        expect(page).to_have_screenshot("chat-with-messages.png", full_page=True)

    def test_visual_context_menu(self, page: Page):
        """Visual: Context menu position (Bug #2)"""
        page.wait_for_load_state("networkidle")

        # Create a chat first
        if page.locator("#messageInput").is_visible():
            page.fill("#messageInput", "Test")
            page.click(".send-btn")
            page.wait_for_timeout(2000)

        # Open context menu
        history_item = page.locator(".history-item").first
        if history_item.count() > 0:
            history_item.click(button="right")
            page.wait_for_timeout(300)

            expect(page).to_have_screenshot("context-menu-position.png")
        else:
            pytest.skip("No history items for context menu")

    def test_visual_settings_modal(self, page: Page):
        """Visual: Settings modal layout"""
        page.wait_for_load_state("networkidle")

        # Open settings
        settings_btn = page.locator("button:has-text('Settings')")
        if settings_btn.count() > 0:
            settings_btn.click()
            page.wait_for_timeout(500)

            expect(page).to_have_screenshot("settings-modal.png")
        else:
            pytest.skip("Settings button not found")

    def test_visual_send_button_normal(self, page: Page):
        """Visual: Send button in normal state (Bug #4)"""
        page.wait_for_load_state("networkidle")

        # Focus on send button area
        send_btn = page.locator(".send-btn")
        send_btn.scroll_into_view_if_needed()

        # Take screenshot of input area
        input_container = page.locator(".input-container, .chat-input")
        expect(input_container).to_have_screenshot("send-button-normal.png")

    def test_visual_send_button_during_send(self, page: Page):
        """Visual: Send button changes to STOP during streaming (Bug #3)"""
        page.wait_for_load_state("networkidle")

        # Send message
        page.fill("#messageInput", "Count to 10")
        page.click(".send-btn")

        # Wait briefly for streaming to start
        page.wait_for_timeout(500)

        # Screenshot of STOP button
        input_container = page.locator(".input-container, .chat-input")
        expect(input_container).to_have_screenshot("send-button-stop-state.png")

    @pytest.mark.parametrize("viewport", [
        {"width": 1920, "height": 1080},  # Desktop
        {"width": 1366, "height": 768},   # Laptop
        {"width": 1024, "height": 768},   # Tablet
        {"width": 768, "height": 1024},   # Tablet portrait
    ])
    def test_visual_responsive_layouts(self, page: Page, viewport):
        """Visual: Test responsive layouts at different sizes"""
        page.set_viewport_size(viewport)
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(500)

        size_name = f"{viewport['width']}x{viewport['height']}"
        expect(page).to_have_screenshot(f"responsive-{size_name}.png", full_page=True)

    def test_visual_osint_tools(self, page: Page):
        """Visual: OSINT tools panel"""
        page.wait_for_load_state("networkidle")

        # Open OSINT tools
        osint_btn = page.locator("button:has-text('OSINT'), .sidebar-section-header:has-text('OSINT')")
        if osint_btn.count() > 0:
            osint_btn.first.click()
            page.wait_for_timeout(500)

            expect(page).to_have_screenshot("osint-tools-panel.png")
        else:
            pytest.skip("OSINT tools not found")

    def test_visual_file_explorer(self, page: Page):
        """Visual: File explorer panel (Bug #7)"""
        page.wait_for_load_state("networkidle")

        # Open file explorer
        files_btn = page.locator("button:has-text('Files')")
        if files_btn.count() > 0:
            files_btn.first.click()
            page.wait_for_timeout(500)

            expect(page).to_have_screenshot("file-explorer-panel.png")
        else:
            pytest.skip("Files button not found")

    def test_visual_plugins_section(self, page: Page):
        """Visual: Plugins section (Bug #6)"""
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(3000)  # Wait for plugins to load

        # Scroll to plugins section
        plugins = page.locator(".sidebar-section:has-text('Plugins')")
        if plugins.count() > 0:
            plugins.scroll_into_view_if_needed()

            expect(plugins).to_have_screenshot("plugins-section.png")
        else:
            pytest.skip("Plugins section not found")


@pytest.mark.visual
class TestVisualComponents:
    """Visual tests for individual components"""

    def test_visual_message_user(self, page: Page):
        """Visual: User message styling"""
        page.wait_for_load_state("networkidle")

        page.fill("#messageInput", "This is a user message")
        page.click(".send-btn")
        page.wait_for_timeout(1000)

        user_msg = page.locator(".message.user, .message-user").last
        expect(user_msg).to_have_screenshot("message-user.png")

    def test_visual_message_assistant(self, page: Page, send_message):
        """Visual: Assistant message styling"""
        page.wait_for_load_state("networkidle")

        send_message("Hello")

        assistant_msg = page.locator(".message.assistant, .message-assistant").last
        expect(assistant_msg).to_have_screenshot("message-assistant.png")

    def test_visual_code_block(self, page: Page, send_message):
        """Visual: Code block with syntax highlighting"""
        page.wait_for_load_state("networkidle")

        # Request code from AI
        send_message("Write a simple Python hello world function")

        # Wait for code block
        code_block = page.locator("pre code, .code-block").first
        if code_block.count() > 0:
            expect(code_block).to_have_screenshot("code-block-highlighted.png")
        else:
            pytest.skip("No code block in response")

    def test_visual_thinking_animation(self, page: Page):
        """Visual: Thinking dots animation"""
        page.wait_for_load_state("networkidle")

        # Send message
        page.fill("#messageInput", "Think about this")
        page.click(".send-btn")

        # Catch thinking animation
        page.wait_for_timeout(200)

        thinking = page.locator(".thinking, .thinking-dots")
        if thinking.count() > 0 and thinking.is_visible():
            expect(thinking).to_have_screenshot("thinking-animation.png")
        else:
            pytest.skip("Thinking animation not visible")

    def test_visual_toast_notification(self, page: Page):
        """Visual: Toast notification styling"""
        page.wait_for_load_state("networkidle")

        # Trigger a toast (copy code block or similar)
        # This depends on your implementation
        # For now, inject a test toast
        page.evaluate("""
            if (window.showToast) {
                window.showToast('Test notification', 'info');
            }
        """)

        page.wait_for_timeout(300)

        toast = page.locator(".toast, .notification")
        if toast.count() > 0:
            expect(toast).to_have_screenshot("toast-notification.png")


@pytest.mark.visual
class TestVisualThemes:
    """Visual tests for theme variations"""

    def test_visual_dark_theme(self, page: Page):
        """Visual: Dark theme (default)"""
        page.wait_for_load_state("networkidle")

        # Ensure dark theme is active
        body = page.locator("body")
        body.evaluate("el => el.classList.remove('light-mode')")

        page.wait_for_timeout(300)

        expect(page).to_have_screenshot("theme-dark.png", full_page=True)

    def test_visual_light_theme(self, page: Page):
        """Visual: Light theme"""
        page.wait_for_load_state("networkidle")

        # Enable light theme
        body = page.locator("body")
        body.evaluate("el => el.classList.add('light-mode')")

        page.wait_for_timeout(300)

        expect(page).to_have_screenshot("theme-light.png", full_page=True)
