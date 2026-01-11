/**
 * Settings Module
 * Handles application settings and appearance customization
 */

import { showToast } from './utils.js';
import { loadSettings, saveSettings, DEFAULT_SETTINGS, loadChatsFromStorage, saveChatsToStorage, loadProjectsFromStorage, saveProjectsFromStorage } from './storage.js';

/**
 * Toggle settings overlay visibility
 */
export function toggleSettings() {
    const settingsOverlay = document.getElementById('settingsOverlay');
    const fullHistoryToggle = document.getElementById('fullHistoryToggle');

    if (!settingsOverlay) return;

    const visible = settingsOverlay.style.display === 'flex';

    if (!visible) {
        let chat = null;
        const currentProjectId = window.currentProjectId;
        const currentChatId = window.currentChatId;

        if (currentProjectId) {
            const projects = loadProjectsFromStorage();
            const project = projects.find(p => p.id === currentProjectId);
            chat = project && project.chats ? project.chats.find(c => c.id === currentChatId) : null;
        } else {
            const chats = loadChatsFromStorage();
            chat = chats.find(c => c.id === currentChatId);
        }

        if (fullHistoryToggle) {
            fullHistoryToggle.checked = chat ? !!chat.useFullHistory : true;
        }

        updateSettingsUI();

        // Update storage usage display
        const storageEl = document.getElementById('storageUsage');
        if (storageEl) storageEl.textContent = getStorageUsage() + ' MB';
    }

    settingsOverlay.style.display = visible ? 'none' : 'flex';
}

/**
 * Update settings UI with current values
 */
export function updateSettingsUI() {
    const settings = loadSettings();

    // Temperature
    const tempSlider = document.getElementById('temperatureSlider');
    const tempValue = document.getElementById('temperatureValue');
    if (tempSlider) {
        tempSlider.value = settings.temperature;
        if (tempValue) tempValue.textContent = settings.temperature;
    }

    // Max Tokens
    const tokensSlider = document.getElementById('maxTokensSlider');
    const tokensValue = document.getElementById('maxTokensValue');
    if (tokensSlider) {
        tokensSlider.value = settings.maxTokens;
        if (tokensValue) tokensValue.textContent = settings.maxTokens;
    }

    // Enter to Send
    const enterToSend = document.getElementById('enterToSend');
    if (enterToSend) enterToSend.checked = settings.enterToSend !== false;

    // Show Timestamps
    const showTimestamps = document.getElementById('showTimestamps');
    if (showTimestamps) showTimestamps.checked = settings.showTimestamps === true;

    // Appearance settings
    const chatFontFamily = document.getElementById('chatFontFamily');
    if (chatFontFamily) chatFontFamily.value = settings.chatFontFamily || DEFAULT_SETTINGS.chatFontFamily;

    const chatFontSize = document.getElementById('chatFontSize');
    const chatFontSizeValue = document.getElementById('chatFontSizeValue');
    if (chatFontSize) {
        chatFontSize.value = settings.chatFontSize || DEFAULT_SETTINGS.chatFontSize;
        if (chatFontSizeValue) chatFontSizeValue.textContent = (settings.chatFontSize || DEFAULT_SETTINGS.chatFontSize) + 'px';
    }

    const uiFontFamily = document.getElementById('uiFontFamily');
    if (uiFontFamily) uiFontFamily.value = settings.uiFontFamily || DEFAULT_SETTINGS.uiFontFamily;

    const inputTextColor = document.getElementById('inputTextColor');
    if (inputTextColor) inputTextColor.value = settings.inputTextColor || DEFAULT_SETTINGS.inputTextColor;

    const outputTextColor = document.getElementById('outputTextColor');
    if (outputTextColor) outputTextColor.value = settings.outputTextColor || DEFAULT_SETTINGS.outputTextColor;

    // API Keys
    const openaiKey = document.getElementById('openaiKey');
    if (openaiKey) openaiKey.value = settings.apiKeys?.openai || '';

    const groqKey = document.getElementById('groqKey');
    if (groqKey) groqKey.value = settings.apiKeys?.groq || '';

    const togetherKey = document.getElementById('togetherKey');
    if (togetherKey) togetherKey.value = settings.apiKeys?.together || '';

    const huggingfaceKey = document.getElementById('huggingfaceKey');
    if (huggingfaceKey) huggingfaceKey.value = settings.apiKeys?.huggingface || '';
}

/**
 * Apply appearance settings to the DOM
 */
export function applyAppearanceSettings() {
    try {
        const settings = loadSettings();
        const root = document.documentElement;
        if (!root) return;

        root.style.setProperty('--chat-font-family', settings.chatFontFamily || DEFAULT_SETTINGS.chatFontFamily);
        // Chat font size (in px)
        root.style.setProperty('--chat-font-size', (settings.chatFontSize || DEFAULT_SETTINGS.chatFontSize) + 'px');
        root.style.setProperty('--ui-font-family', settings.uiFontFamily || DEFAULT_SETTINGS.uiFontFamily);
        root.style.setProperty('--input-text-color', settings.inputTextColor || DEFAULT_SETTINGS.inputTextColor);
        root.style.setProperty('--output-text-color', settings.outputTextColor || DEFAULT_SETTINGS.outputTextColor);
    } catch (e) {
        console.error('applyAppearanceSettings error', e);
    }
}

/**
 * Save chat font family setting
 * @param {string} value - Font family value
 */
export function saveChatFontFamily(value) {
    const settings = loadSettings();
    settings.chatFontFamily = value;
    saveSettings(settings);
    applyAppearanceSettings();
}

/**
 * Save UI font family setting
 * @param {string} value - Font family value
 */
export function saveUIFontFamily(value) {
    const settings = loadSettings();
    settings.uiFontFamily = value;
    saveSettings(settings);
    applyAppearanceSettings();
}

/**
 * Save input text color setting
 * @param {string} value - Color value
 */
export function saveInputTextColor(value) {
    const settings = loadSettings();
    settings.inputTextColor = value;
    saveSettings(settings);
    applyAppearanceSettings();
}

/**
 * Save output text color setting
 * @param {string} value - Color value
 */
export function saveOutputTextColor(value) {
    const settings = loadSettings();
    settings.outputTextColor = value;
    saveSettings(settings);
    applyAppearanceSettings();
}

/**
 * Save chat font size setting
 * @param {number} value - Font size in pixels
 */
export function saveChatFontSize(value) {
    const settings = loadSettings();
    settings.chatFontSize = parseInt(value, 10) || DEFAULT_SETTINGS.chatFontSize;
    saveSettings(settings);
    applyAppearanceSettings();
    const lbl = document.getElementById('chatFontSizeValue');
    if (lbl) lbl.textContent = settings.chatFontSize + 'px';
}

/**
 * Get current localStorage usage in MB
 * @returns {string} Storage usage in MB
 */
export function getStorageUsage() {
    let total = 0;
    for (let key in localStorage) {
        if (localStorage.hasOwnProperty(key)) {
            total += localStorage[key].length * 2; // UTF-16 = 2 bytes per char
        }
    }
    return (total / 1024 / 1024).toFixed(2); // MB
}

/**
 * Format bytes into human-readable string
 * @param {number} bytes - Number of bytes
 * @returns {string} Formatted file size
 */
export function formatFileSize(bytes) {
    if (bytes === undefined || bytes === null) return '0 B';
    const thresh = 1024;
    if (Math.abs(bytes) < thresh) return bytes + ' B';
    const units = ['KB', 'MB', 'GB', 'TB', 'PB'];
    let u = -1;
    do {
        bytes /= thresh;
        ++u;
    } while (Math.abs(bytes) >= thresh && u < units.length - 1);
    const precision = (bytes < 10) ? 2 : (bytes < 100 ? 1 : 0);
    return bytes.toFixed(precision) + ' ' + units[u];
}

/**
 * Toggle full history mode for current chat
 */
export function toggleFullHistory() {
    const fullHistoryToggle = document.getElementById('fullHistoryToggle');
    if (!fullHistoryToggle) return;

    const currentProjectId = window.currentProjectId;
    const currentChatId = window.currentChatId;

    if (currentProjectId) {
        const projects = loadProjectsFromStorage();
        const project = projects.find(p => p.id === currentProjectId);
        const chat = project && project.chats ? project.chats.find(c => c.id === currentChatId) : null;
        if (chat) {
            chat.useFullHistory = !!fullHistoryToggle.checked;
            chat.updatedAt = Date.now();
            saveProjectsToStorage(projects);
            window.renderProjects && window.renderProjects();
        }
    } else {
        let chats = loadChatsFromStorage();
        const chat = chats.find(c => c.id === currentChatId);
        if (chat) {
            chat.useFullHistory = !!fullHistoryToggle.checked;
            chat.updatedAt = Date.now();
            saveChatsToStorage(chats);
            window.renderHistory && window.renderHistory();
        }
    }
}

/**
 * Confirm and delete all chats
 */
export function confirmDeleteAllChats() {
    if (confirm('Are you sure you want to delete all chats? This cannot be undone.')) {
        localStorage.removeItem('parakleon_chats_v1');
        localStorage.removeItem('currentChatId');
        window.currentChatId = null;

        const messagesContainer = document.getElementById('messagesContainer');
        if (messagesContainer) messagesContainer.innerHTML = '';

        toggleSettings();
        window.renderHistory && window.renderHistory(); // Re-render to show the "+ New chat" button

        // Show system message without saving to chat
        const systemDiv = document.createElement('div');
        systemDiv.className = 'message system-message';
        systemDiv.textContent = 'All chats deleted.';
        if (messagesContainer) messagesContainer.appendChild(systemDiv);
    }
}

/**
 * Confirm and delete all projects
 */
export function confirmDeleteAllProjects() {
    if (confirm('Are you sure you want to delete all projects? This will delete all project chats and cannot be undone.')) {
        localStorage.removeItem('parakleon_projects_v1');
        if (window.currentProjectId) {
            window.currentProjectId = null;
            window.currentChatId = null;
            const messagesContainer = document.getElementById('messagesContainer');
            if (messagesContainer) messagesContainer.innerHTML = '';
        }
        toggleSettings();
        window.renderProjects && window.renderProjects();
        window.renderHistory && window.renderHistory();

        // Show system message without saving to chat
        const messagesContainer = document.getElementById('messagesContainer');
        const systemDiv = document.createElement('div');
        systemDiv.className = 'message system-message';
        systemDiv.textContent = 'All projects deleted.';
        if (messagesContainer) messagesContainer.appendChild(systemDiv);
    }
}

/**
 * Save temperature setting
 * @param {number} value - Temperature value
 */
export function saveTemperature(value) {
    const settings = loadSettings();
    settings.temperature = parseFloat(value) || DEFAULT_SETTINGS.temperature;
    saveSettings(settings);
    window.ACTIVE_TEMPERATURE = settings.temperature;
}

/**
 * Save max tokens setting
 * @param {number} value - Max tokens value
 */
export function saveMaxTokens(value) {
    const settings = loadSettings();
    settings.maxTokens = parseInt(value, 10) || DEFAULT_SETTINGS.maxTokens;
    saveSettings(settings);
    window.ACTIVE_MAX_TOKENS = settings.maxTokens;
}

/**
 * Save Top P setting
 * @param {number} value - Top P value
 */
export function saveTopP(value) {
    const settings = loadSettings();
    settings.topP = parseFloat(value) || DEFAULT_SETTINGS.topP || 0.9;
    saveSettings(settings);
    window.ACTIVE_TOP_P = settings.topP;
}

/**
 * Save frequency penalty setting
 * @param {number} value - Frequency penalty value
 */
export function saveFrequencyPenalty(value) {
    const settings = loadSettings();
    settings.frequencyPenalty = parseFloat(value) || 0;
    saveSettings(settings);
    window.ACTIVE_FREQUENCY_PENALTY = settings.frequencyPenalty;
}

/**
 * Save presence penalty setting
 * @param {number} value - Presence penalty value
 */
export function savePresencePenalty(value) {
    const settings = loadSettings();
    settings.presencePenalty = parseFloat(value) || 0;
    saveSettings(settings);
    window.ACTIVE_PRESENCE_PENALTY = settings.presencePenalty;
}

/**
 * Save enter to send setting
 * @param {boolean} value - Enter to send enabled
 */
export function saveEnterToSend(value) {
    const settings = loadSettings();
    settings.enterToSend = !!value;
    saveSettings(settings);
}

/**
 * Save show timestamps setting
 * @param {boolean} value - Show timestamps enabled
 */
export function saveShowTimestamps(value) {
    const settings = loadSettings();
    settings.showTimestamps = !!value;
    saveSettings(settings);
}

/**
 * Save API key for a provider
 * @param {string} provider - Provider name
 * @param {string} value - API key value
 */
export function saveApiKey(provider, value) {
    const settings = loadSettings();
    if (!settings.apiKeys) settings.apiKeys = {};
    settings.apiKeys[provider] = value;
    saveSettings(settings);
    showToast(`${provider} API key saved`, 2000, 'success');
}
