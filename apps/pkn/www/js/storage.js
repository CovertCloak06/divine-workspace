/**
 * Storage Module
 * Handles all localStorage operations for the application
 */

// Storage keys
export const STORAGE_KEY = 'parakleon_chats_v1';
export const PROJECTS_KEY = 'parakleon_projects_v1';
export const MODELS_KEY = 'parakleon_models_v1';
export const SETTINGS_KEY = 'parakleon_settings_v1';

// Default settings
export const DEFAULT_SETTINGS = {
    temperature: 0.7,
    maxTokens: 2048,
    enterToSend: true,
    showTimestamps: false,
    defaultModel: 'openai',
    // Appearance settings (editable in Settings -> Appearance)
    chatFontFamily: 'Dancing Script, cursive',
    // Font size for chat messages and input (in px)
    chatFontSize: 15,
    uiFontFamily: 'Inter, sans-serif',
    inputTextColor: '#ffffff',
    outputTextColor: '#ffd8e0',
    apiKeys: {
        openai: '',
        groq: '',
        together: '',
        huggingface: ''
    }
};

/**
 * Load chats from localStorage
 * @returns {Array} Array of chat objects
 */
export function loadChatsFromStorage() {
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (!raw) return [];
        return JSON.parse(raw);
    } catch (e) {
        console.error('Failed to load history', e);
        return [];
    }
}

/**
 * Save chats to localStorage
 * @param {Array} chats - Array of chat objects to save
 */
export function saveChatsToStorage(chats) {
    try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(chats));
    } catch (e) {
        console.error('Failed to save history', e);
    }
}

/**
 * Load projects from localStorage
 * @returns {Array} Array of project objects
 */
export function loadProjectsFromStorage() {
    try {
        const raw = localStorage.getItem(PROJECTS_KEY);
        if (!raw) return [];
        return JSON.parse(raw);
    } catch (e) {
        console.error('Failed to load projects', e);
        return [];
    }
}

/**
 * Save projects to localStorage
 * @param {Array} projects - Array of project objects to save
 */
export function saveProjectsToStorage(projects) {
    try {
        localStorage.setItem(PROJECTS_KEY, JSON.stringify(projects));
    } catch (e) {
        console.error('Failed to save projects', e);
    }
}

/**
 * Load models from localStorage
 * @returns {Array} Array of model objects
 */
export function loadModelsFromStorage() {
    try {
        const stored = localStorage.getItem(MODELS_KEY);
        if (stored) return JSON.parse(stored);
    } catch (e) {
        console.error('Failed to load models', e);
    }
    // Return empty array - DEFAULT_MODELS are handled in models.js
    return [];
}

/**
 * Save models to localStorage
 * @param {Array} models - Array of model objects to save
 */
export function saveModelsToStorage(models) {
    try {
        localStorage.setItem(MODELS_KEY, JSON.stringify(models));
    } catch (e) {
        console.error('Failed to save models', e);
    }
}

/**
 * Load settings from localStorage
 * @returns {Object} Settings object with defaults merged
 */
export function loadSettings() {
    try {
        const stored = localStorage.getItem(SETTINGS_KEY);
        if (stored) {
            const parsed = JSON.parse(stored);
            return { ...DEFAULT_SETTINGS, ...parsed, apiKeys: { ...DEFAULT_SETTINGS.apiKeys, ...parsed.apiKeys } };
        }
    } catch (e) {
        console.error('Failed to load settings', e);
    }
    return { ...DEFAULT_SETTINGS };
}

/**
 * Save settings to localStorage
 * @param {Object} settings - Settings object to save
 */
export function saveSettings(settings) {
    try {
        localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
    } catch (e) {
        console.error('Failed to save settings', e);
    }
}
