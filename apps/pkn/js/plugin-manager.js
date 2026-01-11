/**
 * Plugin Manager
 * Orchestrates plugin lifecycle: loading, initialization, enabling/disabling
 * Manages plugin state and dependencies
 */

import eventBus from './event-bus.js';

class PluginManager {
    constructor() {
        this.plugins = new Map(); // pluginId -> plugin instance
        this.manifests = new Map(); // pluginId -> manifest
        this.initialized = false;
        this.storageKey = 'pkn_plugin_states';
    }

    /**
     * Initialize the plugin system
     */
    async init() {
        if (this.initialized) return;

        console.log('[PluginManager] Initializing plugin system...');

        // Load plugin states from localStorage
        this.loadStates();

        // Subscribe to plugin events
        eventBus.on('plugin:enabled', (data) => {
            this.saveState(data.pluginId, true);
        });

        eventBus.on('plugin:disabled', (data) => {
            this.saveState(data.pluginId, false);
        });

        this.initialized = true;
        eventBus.emit('pluginManager:initialized');
        console.log('[PluginManager] Initialized successfully');
    }

    /**
     * Register a plugin
     * @param {object} manifest - Plugin manifest
     * @param {class} PluginClass - Plugin class (extends PluginBase)
     */
    async register(manifest, PluginClass) {
        const { id, name, version } = manifest;

        if (this.plugins.has(id)) {
            console.warn(`[PluginManager] Plugin "${name}" already registered`);
            return false;
        }

        console.log(`[PluginManager] Registering plugin: ${name} v${version}`);

        // Validate manifest
        if (!this.validateManifest(manifest)) {
            console.error(`[PluginManager] Invalid manifest for plugin "${name}"`);
            return false;
        }

        // Check dependencies
        if (manifest.dependencies) {
            const missingDeps = this.checkDependencies(manifest.dependencies);
            if (missingDeps.length > 0) {
                console.error(`[PluginManager] Plugin "${name}" missing dependencies:`, missingDeps);
                return false;
            }
        }

        try {
            // Create plugin instance
            const plugin = new PluginClass(manifest);

            // Store plugin and manifest
            this.plugins.set(id, plugin);
            this.manifests.set(id, manifest);

            // Initialize plugin
            await plugin.init();

            // Auto-enable if previously enabled or if autoEnable is true
            const savedState = this.getState(id);
            const shouldEnable = savedState !== null ? savedState : manifest.autoEnable === true;

            if (shouldEnable) {
                await this.enable(id);
            }

            eventBus.emit('plugin:registered', { pluginId: id, plugin });
            console.log(`[PluginManager] Plugin "${name}" registered successfully`);

            return true;
        } catch (error) {
            console.error(`[PluginManager] Error registering plugin "${name}":`, error);
            return false;
        }
    }

    /**
     * Unregister a plugin
     * @param {string} pluginId - Plugin ID
     */
    async unregister(pluginId) {
        if (!this.plugins.has(pluginId)) {
            console.warn(`[PluginManager] Plugin "${pluginId}" not found`);
            return false;
        }

        const plugin = this.plugins.get(pluginId);
        console.log(`[PluginManager] Unregistering plugin: ${plugin.name}`);

        try {
            // Disable and destroy plugin
            if (plugin.enabled) {
                await this.disable(pluginId);
            }
            await plugin.destroy();

            // Remove from registry
            this.plugins.delete(pluginId);
            this.manifests.delete(pluginId);

            eventBus.emit('plugin:unregistered', { pluginId });
            console.log(`[PluginManager] Plugin "${plugin.name}" unregistered successfully`);

            return true;
        } catch (error) {
            console.error(`[PluginManager] Error unregistering plugin "${pluginId}":`, error);
            return false;
        }
    }

    /**
     * Enable a plugin
     * @param {string} pluginId - Plugin ID
     */
    async enable(pluginId) {
        const plugin = this.plugins.get(pluginId);
        if (!plugin) {
            console.warn(`[PluginManager] Plugin "${pluginId}" not found`);
            return false;
        }

        if (plugin.enabled) {
            return true; // Already enabled
        }

        try {
            await plugin.enable();
            this.saveState(pluginId, true);
            console.log(`[PluginManager] Plugin "${plugin.name}" enabled`);
            return true;
        } catch (error) {
            console.error(`[PluginManager] Error enabling plugin "${pluginId}":`, error);
            return false;
        }
    }

    /**
     * Disable a plugin
     * @param {string} pluginId - Plugin ID
     */
    async disable(pluginId) {
        const plugin = this.plugins.get(pluginId);
        if (!plugin) {
            console.warn(`[PluginManager] Plugin "${pluginId}" not found`);
            return false;
        }

        if (!plugin.enabled) {
            return true; // Already disabled
        }

        try {
            await plugin.disable();
            this.saveState(pluginId, false);
            console.log(`[PluginManager] Plugin "${plugin.name}" disabled`);
            return true;
        } catch (error) {
            console.error(`[PluginManager] Error disabling plugin "${pluginId}":`, error);
            return false;
        }
    }

    /**
     * Toggle plugin enabled state
     * @param {string} pluginId - Plugin ID
     */
    async toggle(pluginId) {
        const plugin = this.plugins.get(pluginId);
        if (!plugin) return false;

        return plugin.enabled ? await this.disable(pluginId) : await this.enable(pluginId);
    }

    /**
     * Get a plugin instance
     * @param {string} pluginId - Plugin ID
     */
    getPlugin(pluginId) {
        return this.plugins.get(pluginId);
    }

    /**
     * Get plugin manifest
     * @param {string} pluginId - Plugin ID
     */
    getManifest(pluginId) {
        return this.manifests.get(pluginId);
    }

    /**
     * Get all plugins
     * @returns {Array} Array of plugin objects
     */
    getAllPlugins() {
        return Array.from(this.plugins.values()).map(plugin => plugin.getInfo());
    }

    /**
     * Get enabled plugins
     * @returns {Array} Array of enabled plugins
     */
    getEnabledPlugins() {
        return Array.from(this.plugins.values())
            .filter(plugin => plugin.enabled)
            .map(plugin => plugin.getInfo());
    }

    /**
     * Check if a plugin is enabled
     * @param {string} pluginId - Plugin ID
     */
    isEnabled(pluginId) {
        const plugin = this.plugins.get(pluginId);
        return plugin ? plugin.enabled : false;
    }

    /**
     * Validate plugin manifest
     * @param {object} manifest - Plugin manifest
     */
    validateManifest(manifest) {
        const required = ['id', 'name', 'version'];
        for (const field of required) {
            if (!manifest[field]) {
                console.error(`[PluginManager] Manifest missing required field: ${field}`);
                return false;
            }
        }
        return true;
    }

    /**
     * Check plugin dependencies
     * @param {Array} dependencies - Array of plugin IDs
     * @returns {Array} Array of missing dependency IDs
     */
    checkDependencies(dependencies) {
        return dependencies.filter(depId => !this.plugins.has(depId));
    }

    /**
     * Save plugin enabled state to localStorage
     * @param {string} pluginId - Plugin ID
     * @param {boolean} enabled - Enabled state
     */
    saveState(pluginId, enabled) {
        const states = this.loadStates();
        states[pluginId] = enabled;
        localStorage.setItem(this.storageKey, JSON.stringify(states));
    }

    /**
     * Get plugin enabled state from localStorage
     * @param {string} pluginId - Plugin ID
     * @returns {boolean|null} Enabled state or null if not saved
     */
    getState(pluginId) {
        const states = this.loadStates();
        return states[pluginId] !== undefined ? states[pluginId] : null;
    }

    /**
     * Load all plugin states from localStorage
     * @returns {object} Plugin states object
     */
    loadStates() {
        try {
            const data = localStorage.getItem(this.storageKey);
            return data ? JSON.parse(data) : {};
        } catch (error) {
            console.error('[PluginManager] Error loading plugin states:', error);
            return {};
        }
    }

    /**
     * Update plugin settings
     * @param {string} pluginId - Plugin ID
     * @param {object} settings - Settings object
     */
    updateSettings(pluginId, settings) {
        const plugin = this.plugins.get(pluginId);
        if (!plugin) return false;

        plugin.loadSettings(settings);
        this.saveSettings(pluginId, settings);
        return true;
    }

    /**
     * Save plugin settings to localStorage
     * @param {string} pluginId - Plugin ID
     * @param {object} settings - Settings object
     */
    saveSettings(pluginId, settings) {
        const key = `${this.storageKey}_settings_${pluginId}`;
        localStorage.setItem(key, JSON.stringify(settings));
    }

    /**
     * Load plugin settings from localStorage
     * @param {string} pluginId - Plugin ID
     * @returns {object} Settings object
     */
    loadSettings(pluginId) {
        const key = `${this.storageKey}_settings_${pluginId}`;
        try {
            const data = localStorage.getItem(key);
            return data ? JSON.parse(data) : {};
        } catch (error) {
            console.error(`[PluginManager] Error loading settings for ${pluginId}:`, error);
            return {};
        }
    }

    /**
     * Debug: Log plugin system state
     */
    debug() {
        console.log('[PluginManager] Debug Info:');
        console.log('  Total Plugins:', this.plugins.size);
        console.log('  Enabled Plugins:', this.getEnabledPlugins().length);
        console.log('  Plugins:', this.getAllPlugins());
        eventBus.debug();
    }

    /**
     * Destroy plugin manager (cleanup)
     */
    async destroy() {
        console.log('[PluginManager] Destroying all plugins...');

        for (const [pluginId, plugin] of this.plugins) {
            try {
                await plugin.destroy();
            } catch (error) {
                console.error(`[PluginManager] Error destroying plugin ${pluginId}:`, error);
            }
        }

        this.plugins.clear();
        this.manifests.clear();
        this.initialized = false;

        console.log('[PluginManager] Destroyed successfully');
    }
}

// Create singleton instance
const pluginManager = new PluginManager();

// Export both class and singleton
export { PluginManager, pluginManager };
export default pluginManager;
