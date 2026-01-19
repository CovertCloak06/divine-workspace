/**
 * Welcome Screen Module
 * Handles the welcome/landing screen display and example prompts
 */

/**
 * Hide the welcome screen
 */
export function hideWelcomeScreen() {
    const welcomeScreen = document.getElementById('welcomeScreen');
    if (welcomeScreen) {
        welcomeScreen.style.display = 'none';
    }
}

/**
 * Show the welcome screen (only if no messages exist)
 */
export function showWelcomeScreen() {
    const messagesContainer = document.getElementById('messagesContainer');
    const welcomeScreen = document.getElementById('welcomeScreen');

    if (!welcomeScreen) return;

    const hasMessages = messagesContainer?.querySelectorAll('.message').length > 0;

    // Only show if no messages
    if (!hasMessages) {
        welcomeScreen.style.display = 'flex';
    }
}

/**
 * Send an example prompt from the welcome screen
 * @param {string} exampleText - The example text to send
 */
export function sendExample(exampleText) {
    const messageInput = document.getElementById('messageInput');
    if (messageInput) {
        messageInput.value = exampleText;
        hideWelcomeScreen();
        // Call the global sendMessage function
        if (typeof window.sendMessage === 'function') {
            window.sendMessage();
        }
    }
}

// Expose to window for HTML onclick handlers
window.showWelcomeScreen = showWelcomeScreen;
window.hideWelcomeScreen = hideWelcomeScreen;
window.sendExample = sendExample;
