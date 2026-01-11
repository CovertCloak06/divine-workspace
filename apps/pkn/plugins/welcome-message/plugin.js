/**
 * Welcome Message Plugin
 * Example plugin demonstrating the plugin system
 * Shows a customizable welcome message when PKN loads
 */

import { PluginBase } from '../../js/plugin-base.js';

export class WelcomeMessagePlugin extends PluginBase {
    constructor(manifest) {
        super(manifest);
        this.messageElement = null;
    }

    /**
     * Initialize the plugin
     */
    async init() {
        await super.init();
        console.log(`[${this.name}] Plugin initialized`);

        // Load saved settings or use defaults
        const savedSettings = this.getSettings();
        const defaults = {
            message: this.manifest.settings.message.default,
            duration: this.manifest.settings.duration.default,
            position: this.manifest.settings.position.default
        };

        this.loadSettings({ ...defaults, ...savedSettings });

        // Inject CSS
        this.injectCSS(this.getCSS());
    }

    /**
     * Enable the plugin
     */
    async enable() {
        await super.enable();
        console.log(`[${this.name}] Plugin enabled`);

        // Subscribe to app initialization event
        this.subscribe('app:initialized', () => {
            this.showWelcomeMessage();
        });

        // If app is already initialized, show message now
        if (window.appInitialized) {
            this.showWelcomeMessage();
        }
    }

    /**
     * Disable the plugin
     */
    async disable() {
        await super.disable();
        console.log(`[${this.name}] Plugin disabled`);

        // Hide message if visible
        this.hideWelcomeMessage();
    }

    /**
     * Destroy the plugin
     */
    async destroy() {
        this.hideWelcomeMessage();
        this.removeCSS();
        await super.destroy();
    }

    /**
     * Show the welcome message
     */
    showWelcomeMessage() {
        const message = this.getSetting('message', 'Welcome to Divine Node!');
        const duration = this.getSetting('duration', 3000);
        const position = this.getSetting('position', 'top-right');

        // Create message element
        this.messageElement = document.createElement('div');
        this.messageElement.className = `welcome-message welcome-message-${position}`;
        this.messageElement.innerHTML = `
            <div class="welcome-message-icon">⚡</div>
            <div class="welcome-message-text">${message}</div>
            <button class="welcome-message-close" onclick="this.parentElement.remove()">×</button>
        `;

        document.body.appendChild(this.messageElement);

        // Animate in
        setTimeout(() => {
            this.messageElement.classList.add('visible');
        }, 100);

        // Auto-hide after duration
        setTimeout(() => {
            this.hideWelcomeMessage();
        }, duration);

        // Emit event
        this.emit('welcomeMessage:shown', { message, duration, position });
    }

    /**
     * Hide the welcome message
     */
    hideWelcomeMessage() {
        if (!this.messageElement) return;

        this.messageElement.classList.remove('visible');
        setTimeout(() => {
            if (this.messageElement && this.messageElement.parentElement) {
                this.messageElement.remove();
                this.messageElement = null;
            }
        }, 300); // Wait for fade-out animation
    }

    /**
     * Get plugin CSS
     */
    getCSS() {
        return `
            .welcome-message {
                position: fixed;
                z-index: 10000;
                background: rgba(0, 30, 30, 0.95);
                border: 1px solid var(--theme-primary, #00FFFF);
                border-radius: 8px;
                padding: 16px 20px;
                min-width: 280px;
                max-width: 400px;
                display: flex;
                align-items: center;
                gap: 12px;
                box-shadow: 0 0 20px rgba(0, 255, 255, 0.3);
                opacity: 0;
                transform: translateY(-20px);
                transition: all 0.3s ease;
            }

            .welcome-message.visible {
                opacity: 1;
                transform: translateY(0);
            }

            .welcome-message-top-left {
                top: 20px;
                left: 20px;
            }

            .welcome-message-top-right {
                top: 20px;
                right: 20px;
            }

            .welcome-message-bottom-left {
                bottom: 20px;
                left: 20px;
            }

            .welcome-message-bottom-right {
                bottom: 20px;
                right: 20px;
            }

            .welcome-message-icon {
                font-size: 24px;
                flex-shrink: 0;
                animation: pulse 2s ease-in-out infinite;
            }

            .welcome-message-text {
                flex: 1;
                color: var(--theme-primary, #00FFFF);
                font-size: 14px;
                font-weight: 500;
            }

            .welcome-message-close {
                background: transparent;
                border: none;
                color: var(--theme-primary, #00FFFF);
                font-size: 24px;
                cursor: pointer;
                padding: 0;
                width: 24px;
                height: 24px;
                display: flex;
                align-items: center;
                justify-content: center;
                opacity: 0.6;
                transition: opacity 0.2s;
            }

            .welcome-message-close:hover {
                opacity: 1;
            }

            @keyframes pulse {
                0%, 100% {
                    transform: scale(1);
                    opacity: 1;
                }
                50% {
                    transform: scale(1.1);
                    opacity: 0.8;
                }
            }
        `;
    }
}

export default WelcomeMessagePlugin;
