/**
 * Plugins UI
 * Handles the Plugins Manager modal interface
 */

import { pluginManager } from './plugin-manager.js';
import { showToast } from './utils.js';

/**
 * Open Plugins Manager modal
 */
export function openPluginsManager() {
    const modal = document.getElementById('pluginsModal');
    if (!modal) return;

    modal.classList.remove('hidden');
    modal.style.display = 'flex';

    // Render plugins list
    renderPluginsList();
}

/**
 * Close Plugins Manager modal
 */
export function closePluginsManager() {
    const modal = document.getElementById('pluginsModal');
    if (!modal) return;

    modal.classList.add('hidden');
    modal.style.display = 'none';
}

/**
 * Render the list of plugins
 */
export function renderPluginsList() {
    const container = document.getElementById('pluginsList');
    if (!container) return;

    const plugins = pluginManager.getAllPlugins();

    if (plugins.length === 0) {
        container.innerHTML = `
            <div style="text-align: center; padding: 32px; color: #666;">
                <div style="font-size: 48px; margin-bottom: 16px;">🔌</div>
                <p>No plugins installed</p>
                <p style="font-size: 12px; margin-top: 8px;">
                    <a href="plugins/README.md" target="_blank" style="color: var(--theme-primary);">
                        Learn how to create plugins
                    </a>
                </p>
            </div>
        `;
        return;
    }

    let html = '';

    plugins.forEach(plugin => {
        const manifest = pluginManager.getManifest(plugin.id);
        const enabled = plugin.enabled;

        html += `
            <div class="plugin-item" data-plugin-id="${plugin.id}">
                <div class="plugin-header">
                    <div class="plugin-info">
                        <div class="plugin-name">${plugin.name}</div>
                        <div class="plugin-version">v${plugin.version}</div>
                        ${plugin.author ? `<div class="plugin-author">by ${plugin.author}</div>` : ''}
                    </div>
                    <label class="plugin-toggle">
                        <input type="checkbox"
                               ${enabled ? 'checked' : ''}
                               onchange="togglePlugin('${plugin.id}')" />
                        <span class="toggle-slider"></span>
                    </label>
                </div>
                <div class="plugin-description">${plugin.description || 'No description'}</div>
                ${manifest.settings && Object.keys(manifest.settings).length > 0 ? `
                    <div class="plugin-settings">
                        <button class="plugin-settings-btn" onclick="openPluginSettings('${plugin.id}')">
                            ⚙️ Settings
                        </button>
                    </div>
                ` : ''}
            </div>
        `;
    });

    container.innerHTML = html;
}

/**
 * Toggle plugin enabled state
 * @param {string} pluginId - Plugin ID
 */
export async function togglePlugin(pluginId) {
    const success = await pluginManager.toggle(pluginId);
    const plugin = pluginManager.getPlugin(pluginId);

    if (success) {
        const state = plugin.enabled ? 'enabled' : 'disabled';
        showToast(`Plugin ${plugin.name} ${state}`, 2000, 'success');
        renderPluginsList(); // Re-render to update UI
    } else {
        showToast(`Failed to toggle plugin ${pluginId}`, 3000, 'error');
    }
}

/**
 * Open plugin settings modal
 * @param {string} pluginId - Plugin ID
 */
export function openPluginSettings(pluginId) {
    const manifest = pluginManager.getManifest(pluginId);
    const plugin = pluginManager.getPlugin(pluginId);

    if (!manifest || !manifest.settings) {
        showToast('This plugin has no settings', 2000, 'info');
        return;
    }

    // TODO: Create settings modal
    showToast('Plugin settings coming soon!', 2000, 'info');
}

// Make functions globally available for onclick handlers
window.openPluginsManager = openPluginsManager;
window.closePluginsManager = closePluginsManager;
window.togglePlugin = togglePlugin;
window.openPluginSettings = openPluginSettings;
