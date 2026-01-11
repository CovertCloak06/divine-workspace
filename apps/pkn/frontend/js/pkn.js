/**
 * PKN Frontend Entry Point
 * Imports all modules for the application
 */

// Core
import './core/main.js';
import './core/event-bus.js';

// UI Components
import './ui/chat.js';
import './ui/multi_agent_ui.js';
import './ui/osint_ui.js';
import './ui/plugins-ui.js';

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
