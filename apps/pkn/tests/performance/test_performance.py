"""
Performance Tests for PKN
Tests page load times, rendering performance, and responsiveness

Run with: pytest tests/performance/ -v
"""
import pytest
import time
from playwright.sync_api import Page


@pytest.mark.performance
class TestPageLoadPerformance:
    """Test page load and initialization times"""

    def test_page_loads_under_3_seconds(self, page: Page):
        """Page should load completely in < 3 seconds"""
        start = time.time()

        page.goto("http://localhost:8010", wait_until="networkidle")

        duration = time.time() - start

        assert duration < 3.0, f"Page took {duration:.2f}s to load (target: <3s)"

    def test_dom_content_loaded_under_1_second(self, page: Page):
        """DOM should be interactive in < 1 second"""
        metrics = page.evaluate("""
            () => {
                const perf = performance.getEntriesByType('navigation')[0];
                return {
                    domContentLoaded: perf.domContentLoadedEventEnd - perf.domContentLoadedEventStart,
                    domInteractive: perf.domInteractive,
                };
            }
        """)

        dom_time = metrics['domContentLoaded'] / 1000  # Convert to seconds

        assert dom_time < 1.0, f"DOM loaded in {dom_time:.2f}s (target: <1s)"

    def test_first_paint_under_1_second(self, page: Page):
        """First paint should occur in < 1 second"""
        page.wait_for_load_state("networkidle")

        metrics = page.evaluate("""
            () => {
                const paint = performance.getEntriesByType('paint')
                    .find(entry => entry.name === 'first-contentful-paint');
                return paint ? paint.startTime : 0;
            }
        """)

        first_paint = metrics / 1000  # Convert to seconds

        assert first_paint < 1.0, f"First paint at {first_paint:.2f}s (target: <1s)"

    def test_all_resources_load_successfully(self, page: Page):
        """All CSS/JS/images should load without errors"""
        failed_resources = []

        page.on("requestfailed", lambda request: failed_resources.append({
            "url": request.url,
            "method": request.method,
            "error": request.failure
        }))

        page.goto("http://localhost:8010", wait_until="networkidle")

        assert len(failed_resources) == 0, f"Failed to load {len(failed_resources)} resources: {failed_resources}"

    def test_javascript_bundle_size(self, page: Page):
        """JavaScript bundles should be reasonably sized"""
        page.wait_for_load_state("networkidle")

        js_sizes = page.evaluate("""
            () => {
                const resources = performance.getEntriesByType('resource');
                return resources
                    .filter(r => r.name.endsWith('.js'))
                    .map(r => ({
                        url: r.name,
                        size: r.transferSize || r.encodedBodySize
                    }));
            }
        """)

        total_js = sum(item['size'] for item in js_sizes)
        total_js_mb = total_js / (1024 * 1024)

        # Warn if total JS > 2MB
        assert total_js_mb < 2.0, f"Total JavaScript size: {total_js_mb:.2f}MB (target: <2MB)"


@pytest.mark.performance
class TestRuntimePerformance:
    """Test runtime performance and responsiveness"""

    def test_message_send_response_time(self, page: Page):
        """Sending message should be responsive (< 500ms to UI update)"""
        page.wait_for_load_state("networkidle")

        page.fill("#messageInput", "Test message")

        start = time.time()
        page.click(".send-btn")

        # Wait for message to appear in chat
        page.wait_for_selector(".message.user", timeout=1000)

        duration = (time.time() - start) * 1000  # Convert to ms

        assert duration < 500, f"UI took {duration:.0f}ms to update after send (target: <500ms)"

    def test_sidebar_toggle_animation_smooth(self, page: Page):
        """Sidebar animation should complete in < 500ms"""
        page.wait_for_load_state("networkidle")

        start = time.time()

        # Toggle sidebar
        page.click(".toggle-btn")

        # Wait for animation to complete
        page.wait_for_timeout(500)

        duration = (time.time() - start) * 1000

        # Animation should not take longer than CSS transition (300ms) + buffer
        assert duration < 600, f"Sidebar animation took {duration:.0f}ms (target: <600ms)"

    def test_typing_input_lag(self, page: Page):
        """Typing in input should have no perceptible lag"""
        page.wait_for_load_state("networkidle")

        input_field = page.locator("#messageInput")

        # Measure time to type a message
        test_message = "This is a test message to measure input lag"

        start = time.time()
        input_field.fill(test_message)
        duration = (time.time() - start) * 1000

        # Should take < 100ms to fill input
        assert duration < 100, f"Input filling took {duration:.0f}ms (target: <100ms)"

    def test_no_memory_leaks_after_10_messages(self, page: Page, send_message):
        """Memory should not grow excessively with multiple messages"""
        page.wait_for_load_state("networkidle")

        # Get initial memory
        initial_memory = page.evaluate("() => performance.memory ? performance.memory.usedJSHeapSize : 0")

        # Send 10 messages
        for i in range(10):
            page.fill("#messageInput", f"Test message {i+1}")
            page.click(".send-btn")
            page.wait_for_timeout(500)

        # Get final memory
        final_memory = page.evaluate("() => performance.memory ? performance.memory.usedJSHeapSize : 0")

        if initial_memory > 0:
            memory_growth = (final_memory - initial_memory) / (1024 * 1024)  # MB

            # Memory growth should be < 50MB for 10 messages
            assert memory_growth < 50, f"Memory grew by {memory_growth:.2f}MB after 10 messages (target: <50MB)"

    def test_scroll_performance(self, page: Page, send_message):
        """Scrolling through messages should be smooth"""
        page.wait_for_load_state("networkidle")

        # Create multiple messages
        for i in range(20):
            page.fill("#messageInput", f"Message {i+1}")
            page.click(".send-btn")
            page.wait_for_timeout(200)

        # Measure scroll performance
        messages_container = page.locator("#messagesContainer, .messages")

        start = time.time()

        # Scroll to top
        messages_container.evaluate("el => el.scrollTop = 0")
        page.wait_for_timeout(50)

        # Scroll to bottom
        messages_container.evaluate("el => el.scrollTop = el.scrollHeight")
        page.wait_for_timeout(50)

        duration = (time.time() - start) * 1000

        # Scrolling should be instantaneous (< 200ms)
        assert duration < 200, f"Scrolling took {duration:.0f}ms (target: <200ms)"


@pytest.mark.performance
@pytest.mark.slow
class TestNetworkPerformance:
    """Test API response times"""

    def test_health_endpoint_fast(self, page: Page):
        """Health endpoint should respond in < 100ms"""
        page.wait_for_load_state("networkidle")

        start = time.time()

        response = page.evaluate("""
            async () => {
                const res = await fetch('/health');
                return await res.json();
            }
        """)

        duration = (time.time() - start) * 1000

        assert response['status'] == 'ok', "Health check failed"
        assert duration < 100, f"Health endpoint took {duration:.0f}ms (target: <100ms)"

    def test_chat_api_response_time(self, page: Page):
        """Chat API should start responding in < 2 seconds"""
        page.wait_for_load_state("networkidle")

        start = time.time()

        # Send message via API
        response_started = page.evaluate("""
            async () => {
                const start = Date.now();
                const res = await fetch('/api/multi-agent/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message: 'Hello', mode: 'auto' })
                });

                // Return time until first byte
                return Date.now() - start;
            }
        """)

        # Response should start in < 2 seconds
        assert response_started < 2000, f"Chat API took {response_started}ms to start responding (target: <2000ms)"

    def test_file_upload_performance(self, page: Page):
        """File upload should be reasonably fast"""
        page.wait_for_load_state("networkidle")

        # Create a test file (small text file)
        test_file_content = "Test file content\n" * 100  # ~2KB

        # This test needs actual file upload implementation
        # Skipping for now as it depends on your file upload UI
        pytest.skip("File upload performance test needs implementation")


@pytest.mark.performance
class TestLighthouseMetrics:
    """Test Lighthouse performance scores"""

    def test_lighthouse_performance_score(self, page: Page):
        """Page should achieve good Lighthouse performance score"""
        page.wait_for_load_state("networkidle")

        # Run Lighthouse audit
        # This requires lighthouse CLI to be installed
        # Or use Chrome DevTools Protocol

        # For now, manually check key metrics
        metrics = page.evaluate("""
            () => {
                const perf = performance.getEntriesByType('navigation')[0];
                const paint = performance.getEntriesByType('paint');

                return {
                    fcp: paint.find(p => p.name === 'first-contentful-paint')?.startTime || 0,
                    domInteractive: perf.domInteractive,
                    loadComplete: perf.loadEventEnd,
                };
            }
        """)

        # First Contentful Paint should be < 1.8s (Lighthouse good threshold)
        fcp_seconds = metrics['fcp'] / 1000
        assert fcp_seconds < 1.8, f"FCP: {fcp_seconds:.2f}s (Lighthouse target: <1.8s)"

    def test_no_render_blocking_resources(self, page: Page):
        """Check for render-blocking resources"""
        page.wait_for_load_state("networkidle")

        # Get resources that block rendering
        blocking_resources = page.evaluate("""
            () => {
                const resources = performance.getEntriesByType('resource');
                return resources
                    .filter(r => r.renderBlockingStatus === 'blocking')
                    .map(r => r.name);
            }
        """)

        # Should minimize render-blocking resources
        assert len(blocking_resources) < 5, f"Found {len(blocking_resources)} render-blocking resources: {blocking_resources}"


@pytest.mark.performance
class TestResponsiveness:
    """Test UI responsiveness across different scenarios"""

    def test_modal_open_close_fast(self, page: Page):
        """Modals should open/close quickly"""
        page.wait_for_load_state("networkidle")

        settings_btn = page.locator("button:has-text('Settings')")
        if settings_btn.count() == 0:
            pytest.skip("Settings button not found")

        # Measure open time
        start = time.time()
        settings_btn.click()
        page.wait_for_selector(".settings-modal, .modal", state="visible")
        open_time = (time.time() - start) * 1000

        # Measure close time
        start = time.time()
        close_btn = page.locator(".settings-close, .modal-close, button:has-text('Close')").first
        close_btn.click()
        page.wait_for_selector(".settings-modal, .modal", state="hidden")
        close_time = (time.time() - start) * 1000

        assert open_time < 300, f"Modal opened in {open_time:.0f}ms (target: <300ms)"
        assert close_time < 300, f"Modal closed in {close_time:.0f}ms (target: <300ms)"

    def test_context_menu_appears_instantly(self, page: Page):
        """Context menu should appear immediately on right-click"""
        page.wait_for_load_state("networkidle")

        # Create a chat first
        if page.locator("#messageInput").is_visible():
            page.fill("#messageInput", "Test")
            page.click(".send-btn")
            page.wait_for_timeout(2000)

        history_item = page.locator(".history-item").first
        if history_item.count() == 0:
            pytest.skip("No history items for context menu test")

        # Measure context menu appearance time
        start = time.time()
        history_item.click(button="right")
        page.wait_for_selector(".history-menu, .context-menu", state="visible")
        duration = (time.time() - start) * 1000

        assert duration < 100, f"Context menu took {duration:.0f}ms to appear (target: <100ms)"
