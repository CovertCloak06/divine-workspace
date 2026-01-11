/**
 * Plugin Base Class
 * All plugins should extend this class
 * Provides standard lifecycle methods and core API access
 */

import eventBus from './event-bus.js';

export class PluginBase {
    constructor(manifest) {
        this.manifest = manifest;
        this.id = manifest.id;
        this.name = manifest.name;
        this.version = manifest.version;
        this.enabled = false;
        this.initialized = false;
        this.settings = {};
        this.eventSubscriptions = [];
    }

    /**
     * Initialize the plugin
     * Override this in your plugin class
     */
    async init() {
        console.log(`[Plugin:${this.name}] Initializing...`);
        this.initialized = true;
    }

    /**
     * Enable the plugin
     * Override this for custom enable logic
     */
    async enable() {
        if (this.enabled) return;
        console.log(`[Plugin:${this.name}] Enabling...`);
        this.enabled = true;
        this.emit('plugin:enabled', { pluginId: this.id });
    }

    /**
     * Disable the plugin
     * Override this for custom disable logic
     */
    async disable() {
        if (!this.enabled) return;
        console.log(`[Plugin:${this.name}] Disabling...`);
        this.enabled = false;
        this.emit('plugin:disabled', { pluginId: this.id });
    }

    /**
     * Destroy the plugin (cleanup)
     * Override this for custom cleanup
     */
    async destroy() {
        console.log(`[Plugin:${this.name}] Destroying...`);
        this.unsubscribeAll();
        this.enabled = false;
        this.initialized = false;
    }

    /**
     * Subscribe to an event (tracked for cleanup)
     * @param {string} eventName - Event to listen for
     * @param {Function} callback - Callback function
     */
    subscribe(eventName, callback) {
        const unsubscribe = eventBus.on(eventName, callback, this);
        this.eventSubscriptions.push(unsubscribe);
        return unsubscribe;
    }

    /**
     * Subscribe to an event once
     * @param {string} eventName - Event to listen for
     * @param {Function} callback - Callback function
     */
    subscribeOnce(eventName, callback) {
        const unsubscribe = eventBus.once(eventName, callback, this);
        this.eventSubscriptions.push(unsubscribe);
        return unsubscribe;
    }

    /**
     * Emit an event
     * @param {string} eventName - Event name
     * @param {*} data - Event data
     */
    emit(eventName, data) {
        eventBus.emit(eventName, data);
    }

    /**
     * Unsubscribe from all events (cleanup)
     */
    unsubscribeAll() {
        this.eventSubscriptions.forEach(unsubscribe => unsubscribe());
        this.eventSubscriptions = [];
    }

    /**
     * Get plugin setting
     * @param {string} key - Setting key
     * @param {*} defaultValue - Default value if not set
     */
    getSetting(key, defaultValue = null) {
        return this.settings[key] !== undefined ? this.settings[key] : defaultValue;
    }

    /**
     * Set plugin setting
     * @param {string} key - Setting key
     * @param {*} value - Setting value
     */
    setSetting(key, value) {
        this.settings[key] = value;
        this.emit('plugin:settingChanged', {
            pluginId: this.id,
            key,
            value
        });
    }

    /**
     * Load settings from storage
     * @param {object} settings - Settings object
     */
    loadSettings(settings) {
        this.settings = { ...settings };
    }

    /**
     * Get all settings
     */
    getSettings() {
        return { ...this.settings };
    }

    // ============================================
    // Core API Access (available to all plugins)
    // ============================================

    /**
     * Show a toast notification
     * @param {string} message - Message to show
     * @param {number} duration - Duration in ms
     * @param {string} type - success, error, info
     */
    showToast(message, duration = 3000, type = 'info') {
        if (window.showToast) {
            window.showToast(message, duration, type);
        }
    }

    /**
     * Add a message to the chat
     * @param {string} role - 'user' or 'assistant'
     * @param {string} content - Message content
     */
    addChatMessage(role, content) {
        if (window.addMessage) {
            window.addMessage(role, content);
        }
    }

    /**
     * Get current chat messages
     */
    getChatMessages() {
        return window.currentMessages || [];
    }

    /**
     * Send a message to an agent
     * @param {string} message - Message to send
     * @param {string} agent - Agent to use (optional)
     */
    async sendToAgent(message, agent = null) {
        if (window.sendMessage) {
            await window.sendMessage(message, agent);
        }
    }

    /**
     * Create a UI element for the plugin
     * @param {string} html - HTML string
     * @param {string} containerId - Container to append to
     * @returns {HTMLElement} Created element
     */
    createUI(html, containerId = 'messagesContainer') {
        const container = document.getElementById(containerId);
        if (!container) return null;

        const wrapper = document.createElement('div');
        wrapper.className = `plugin-ui plugin-${this.id}`;
        wrapper.innerHTML = html;
        container.appendChild(wrapper);
        return wrapper;
    }

    /**
     * Remove plugin UI
     */
    removeUI() {
        const elements = document.querySelectorAll(`.plugin-${this.id}`);
        elements.forEach(el => el.remove());
    }

    /**
     * Inject CSS for the plugin
     * @param {string} css - CSS string
     */
    injectCSS(css) {
        const styleId = `plugin-style-${this.id}`;
        let style = document.getElementById(styleId);

        if (!style) {
            style = document.createElement('style');
            style.id = styleId;
            document.head.appendChild(style);
        }

        style.textContent = css;
    }

    /**
     * Remove plugin CSS
     */
    removeCSS() {
        const style = document.getElementById(`plugin-style-${this.id}`);
        if (style) style.remove();
    }

    /**
     * Make an API request
     * @param {string} endpoint - API endpoint
     * @param {object} options - Fetch options
     */
    async apiRequest(endpoint, options = {}) {
        try {
            const response = await fetch(endpoint, {
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                },
                ...options
            });

            if (!response.ok) {
                throw new Error(`API request failed: ${response.statusText}`);
            }

            return await response.json();
        } catch (error) {
            console.error(`[Plugin:${this.name}] API request error:`, error);
            throw error;
        }
    }

    /**
     * Get info about this plugin
     */
    getInfo() {
        return {
            id: this.id,
            name: this.name,
            version: this.version,
            enabled: this.enabled,
            initialized: this.initialized,
            description: this.manifest.description,
            author: this.manifest.author
        };
    }
}

export default PluginBase;
