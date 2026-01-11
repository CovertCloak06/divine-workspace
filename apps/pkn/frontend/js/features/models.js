/**
 * Models Module
 * Handles AI model management and selection
 */

import { showToast } from './utils.js';
import { loadModelsFromStorage, saveModelsToStorage, loadSettings } from './storage.js';

// Default models configuration
export const DEFAULT_MODELS = [
    { provider: 'openai', id: 'openai', name: 'gpt-4o-mini', enabled: true },
    // Local llama.cpp Dolphin Phi-2 (direct, legacy endpoint)
    { provider: 'llamacpp', id: 'llamacpp:local', name: '🦙 Dolphin Phi-2 (Uncensored, llama.cpp)', enabled: true },
    // Local llama-server (OpenAI-compatible, any GGUF model)
    { provider: 'llama-server', id: 'llama-server:local', name: '🦙 Local Llama (llama-server, OpenAI API)', enabled: true }
];

export const providerLabels = {
    openai: 'OpenAI',
    groq: 'Groq',
    together: 'Together AI',
    huggingface: 'Hugging Face',
    ollama: 'Ollama (Local)',
    llamacpp: 'llama.cpp (Local)',
    'llama-server': 'llama-server (Local)',
    webllm: 'WebLLM (Browser)',
    custom: 'Custom Models'
};

// Dynamic model state (window-scoped for cross-module access)
if (!window.dynamicOllamaModels) window.dynamicOllamaModels = [];
if (!window.dynamicLlamaCppModels) window.dynamicLlamaCppModels = [];

/**
 * Get all available models (stored + dynamic)
 * @returns {Array} Combined array of all models
 */
export function getAllModels() {
    return [
        ...(window.dynamicOllamaModels || []),
        ...(window.dynamicLlamaCppModels || []),
        ...loadModelsFromStorage().filter(m => m.enabled !== false)
    ];
}

/**
 * Refresh Ollama models from server
 */
export async function refreshOllamaModels() {
    try {
        const res = await fetch('/api/models/ollama');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const models = data.models || [];

        // Store discovered Ollama models on the window object so other refresh functions can merge them
        window.dynamicOllamaModels = models.map(m => ({
            provider: 'ollama',
            id: `ollama:${m.name}`,
            name: m.name,
            enabled: true,
        }));

        // Update all UI that depends on available models
        updateModelSelectDropdown();
        if (window.renderModelsList) window.renderModelsList();
    } catch (e) {
        console.error('Failed to refresh Ollama models', e);
    }
}

/**
 * Refresh llama.cpp models from server
 */
export async function refreshLlamaCppModels() {
    try {
        const res = await fetch('/api/models/llamacpp');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const models = data.models || [];
        window.dynamicLlamaCppModels = models.map(m => ({
            provider: 'llamacpp',
            id: `llamacpp:${m.name}`,
            name: m.name,
            enabled: true,
        }));
        // Refresh UI
        updateModelSelectDropdown();
        if (window.renderModelsList) window.renderModelsList();
    } catch (e) {
        console.error('Failed to refresh llama.cpp models', e);
    }
}

/**
 * Update the model select dropdown with all available models
 */
export function updateModelSelectDropdown() {
    const modelSelect = document.getElementById('modelSelect');
    if (!modelSelect) return;

    // Build a combined list of stored + dynamically discovered models (Ollama, llama.cpp, etc.)
    const storedModels = loadModelsFromStorage() || [];
    let dynamicModels = [];
    try {
        dynamicModels = getAllModels();
    } catch (e) {
        dynamicModels = [];
    }

    // Combine with stored first so stored entries take precedence on naming/metadata
    const combined = [ ...storedModels, ...dynamicModels ];

    // Deduplicate by id while preserving order (stored models first)
    const map = new Map();
    for (const m of combined) {
        if (!m || !m.id) continue;
        if (!map.has(m.id)) map.set(m.id, m);
    }

    // Group by provider
    const providers = {};
    for (const m of map.values()) {
        if (m.enabled === false) continue;
        const provider = m.provider || (m.id && m.id.includes(':') ? m.id.split(':')[0] : 'custom');
        if (!providers[provider]) providers[provider] = [];
        providers[provider].push(m);
    }

    const currentValue = modelSelect.value;
    modelSelect.innerHTML = '';

    Object.keys(providers).forEach(provider => {
        const optgroup = document.createElement('optgroup');
        optgroup.label = providerLabels[provider] || provider;

        providers[provider].forEach(model => {
            const option = document.createElement('option');
            option.value = model.id;
            option.textContent = model.name || model.id;
            optgroup.appendChild(option);
        });

        modelSelect.appendChild(optgroup);
    });

    // Restore selection if still exists
    if (currentValue) {
        const exists = Array.from(modelSelect.options).find(o => o.value === currentValue);
        if (exists) modelSelect.value = currentValue;
    }
}

/**
 * Initialize model selector on load
 */
export function initModelSelector() {
    const models = loadModelsFromStorage();
    // If no models in storage, save defaults
    if (!localStorage.getItem('parakleon_models_v1')) {
        saveModelsToStorage(DEFAULT_MODELS);
    }
    updateModelSelectDropdown();
}

/**
 * Get API key for a specific provider
 * @param {string} provider - Provider name
 * @returns {string} API key
 */
export function getApiKeyForProvider(provider) {
    const settings = loadSettings();
    const storedKey = settings.apiKeys[provider];
    if (storedKey) return storedKey;

    // Fall back to config.js keys
    switch (provider) {
        case 'openai': return window.PARAKLEON_CONFIG?.OPENAI_API_KEY || '';
        case 'groq': return window.PARAKLEON_CONFIG?.GROQ_API_KEY || '';
        case 'together': return window.PARAKLEON_CONFIG?.TOGETHER_API_KEY || '';
        case 'huggingface': return window.PARAKLEON_CONFIG?.HUGGINGFACE_API_KEY || '';
        default: return '';
    }
}

/**
 * Handle model selection change
 */
export function onModelChange() {
    const modelSelect = document.getElementById('modelSelect');
    if (!modelSelect) return;

    const { value } = modelSelect;

    // Update global active model variables
    if (value === 'openai') {
        window.ACTIVE_PROVIDER = 'openai';
        window.ACTIVE_BASE_URL = 'https://api.openai.com/v1/chat/completions';
        window.ACTIVE_MODEL = window.PARAKLEON_CONFIG?.OPENAI_MODEL || 'gpt-4o-mini';
        window.ACTIVE_API_KEY = getApiKeyForProvider('openai');
    } else if (value.startsWith('groq:')) {
        window.ACTIVE_PROVIDER = 'groq';
        const modelName = value.replace('groq:', '');
        window.ACTIVE_BASE_URL = 'https://api.groq.com/openai/v1/chat/completions';
        window.ACTIVE_MODEL = modelName;
        window.ACTIVE_API_KEY = getApiKeyForProvider('groq');
    } else if (value.startsWith('together:')) {
        window.ACTIVE_PROVIDER = 'together';
        const modelName = value.replace('together:', '');
        window.ACTIVE_BASE_URL = 'https://api.together.xyz/v1/chat/completions';
        window.ACTIVE_MODEL = modelName;
        window.ACTIVE_API_KEY = getApiKeyForProvider('together');
    } else if (value.startsWith('huggingface:')) {
        window.ACTIVE_PROVIDER = 'huggingface';
        const modelName = value.replace('huggingface:', '');
        window.ACTIVE_BASE_URL = 'https://api-inference.huggingface.co/models/' + modelName + '/v1/chat/completions';
        window.ACTIVE_MODEL = modelName;
        window.ACTIVE_API_KEY = getApiKeyForProvider('huggingface');
    } else if (value.startsWith('ollama:')) {
        window.ACTIVE_PROVIDER = 'ollama';
        const modelName = value.replace('ollama:', '');
        window.ACTIVE_BASE_URL = (window.PARAKLEON_CONFIG?.OLLAMA_BASE_URL || 'http://localhost:11434/v1') + '/chat/completions';
        window.ACTIVE_MODEL = modelName;
        window.ACTIVE_API_KEY = '';
    } else if (value.startsWith('llamacpp:')) {
        window.ACTIVE_PROVIDER = 'llamacpp';
        const modelName = value.replace('llamacpp:', '');
        window.ACTIVE_BASE_URL = window.PARAKLEON_CONFIG?.LLAMACPP_BASE_URL || 'http://localhost:8080/v1/chat/completions';
        window.ACTIVE_MODEL = modelName;
        window.ACTIVE_API_KEY = '';
    } else if (value.startsWith('llama-server:')) {
        window.ACTIVE_PROVIDER = 'llama-server';
        const modelName = value.replace('llama-server:', '');
        window.ACTIVE_BASE_URL = window.PARAKLEON_CONFIG?.LLAMA_SERVER_URL || 'http://localhost:8080/v1/chat/completions';
        window.ACTIVE_MODEL = modelName;
        window.ACTIVE_API_KEY = '';
    } else if (value.startsWith('webllm:')) {
        window.ACTIVE_PROVIDER = 'webllm';
        const modelName = value.replace('webllm:', '');
        window.ACTIVE_MODEL = modelName;
        window.ACTIVE_API_KEY = '';
    }

    console.log('Model changed to:', value, 'Provider:', window.ACTIVE_PROVIDER);
}
