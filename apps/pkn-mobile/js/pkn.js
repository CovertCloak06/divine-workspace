/**
 * PKN Frontend Entry Point
 * Imports all modules for the application
 */

// Core
import { init } from './core/main.js';
import './core/event-bus.js';

// Expose init globally for inline scripts in HTML
window.init = init;

// UI Components
import './ui/chat.js';
import './ui/multi_agent_ui.js';
import { OSINTTools } from './ui/osint_ui.js';
import { openPluginsManager, closePluginsManager, togglePlugin, openPluginSettings, renderPluginsList } from './ui/plugins-ui.js';

// Expose OSINT and Plugins functions globally for HTML onclick handlers
window.OSINTTools = OSINTTools;
window.openPluginsManager = openPluginsManager;
window.closePluginsManager = closePluginsManager;
window.togglePlugin = togglePlugin;
window.openPluginSettings = openPluginSettings;
window.renderPluginsList = renderPluginsList;

// Features
import './features/files.js';
import './features/images.js';
import './features/models.js';
import './features/settings.js';
import './features/projects.js';
import './features/autocomplete.js';
import './features/agent_quality.js';
import './features/plugin-manager.js';
import './features/plugin-base.js';

// Utilities
import './utils/storage.js';
import './utils/utils.js';
import './utils/theme-utils.js';

// API
import './api/capacitor-backend.js';

console.log('✅ PKN Frontend loaded');
