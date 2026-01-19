// Parakleon Main Chat Application
// Toast notifications: use showToast from js/utils/utils.js (loaded via main.js module)
// Error handling: use formatError from js/utils/errors.js (loaded via main.js module)

// Clear messages while preserving welcome screen
function clearMessages() {
    const container = document.getElementById('messagesContainer');
    if (container) {
        container.querySelectorAll('.message').forEach(el => el.remove());
    }
}

// --- Send Message Handler ---
// Global abort controller for stopping AI responses
let currentAbortController = null;
let userInitiatedStop = false;
let timeoutTriggered = false;

// Welcome screen functions moved to js/ui/welcome-screen.js

// Header agent selector function
function selectHeaderAgent(agentType) {
    // Update UI - remove active class from all buttons
    document.querySelectorAll('.agent-mode-btn').forEach(btn => btn.classList.remove('active'));
    // Add active to selected
    const selectedBtn = document.querySelector(`.agent-mode-btn[data-agent="${agentType}"]`);
    if (selectedBtn) selectedBtn.classList.add('active');

    // Set the agent mode in multi-agent UI if available
    if (window.multiAgentUI && typeof window.multiAgentUI.setMode === 'function') {
        window.multiAgentUI.setMode(agentType);
    }

    console.log(`Agent selected: ${agentType}`);
}

function sendMessage() {
    console.log('sendMessage called, currentAbortController:', currentAbortController);

    // If already processing, abort the current request
    if (currentAbortController) {
        console.log('STOPPING - User clicked stop');
        userInitiatedStop = true;
        currentAbortController.abort();
        currentAbortController = null;

        // Add immediate feedback
        if (typeof showToast === 'function') {
            showToast('Stopping...', 1000, 'info');
        }

        if (sendBtn) {
            sendBtn.textContent = 'SEND';
            sendBtn.disabled = false;
            sendBtn.removeAttribute('data-state');
            sendBtn.style.backgroundColor = '';
            sendBtn.style.borderColor = '';
            sendBtn.style.color = '';
            console.log('Button reset to SEND');
        }
        if (messageInput) {
            messageInput.disabled = false;
            messageInput.focus();
        }
        return;
    }

    const input = messageInput.value.trim();
    if (!input) return;

    // Hide welcome screen AFTER we know there's valid input
    hideWelcomeScreen();

    // Reset stop flag for new request
    userInitiatedStop = false;

    // Disable input during request
    if (messageInput) messageInput.disabled = true;

    // CRITICAL: Change button to Stop with visual feedback
    if (sendBtn) {
        sendBtn.disabled = false; // Keep enabled so user can click to stop
        sendBtn.textContent = ''; // Clear text - CSS ::after handles "STOP" display
        sendBtn.setAttribute('data-state', 'stop');
        console.log('Button changed to STOP with data-state');
    }

    // Add user message to chat and storage immediately
    addMessage(input, 'user', false);
    appendMessageToCurrentChat('user', input);
    messageInput.value = '';
    messageInput.style.height = 'auto'; // Reset height after sending

    // Show thinking/typing animation (AI is responding)
    const thinkingId = 'thinking_' + Date.now();
    addMessage('<span class="thinking-dots"><span class="dot"></span><span class="dot"></span><span class="dot"></span></span>', 'ai', false, [], thinkingId);

    // Prepare chat history for backend
    let chats = loadChatsFromStorage();
    let chat = getCurrentChat(chats);
    let messages = chat && chat.messages ? chat.messages.map(m => ({ role: m.sender === 'user' ? 'user' : 'assistant', content: m.text })) : [];

    // Check which agent is selected
    const selectedAgent = document.querySelector('.agent-mode-btn.active');
    const agentType = selectedAgent ? selectedAgent.getAttribute('data-agent') : 'auto';

    console.log('Selected agent:', agentType);
    console.log('Sending message to multi-agent API');

    // Add timeout handling (120 seconds for multi-agent responses)
    currentAbortController = new AbortController();
    timeoutTriggered = false;
    const timeoutId = setTimeout(() => {
        timeoutTriggered = true;
        currentAbortController.abort();
    }, 120000);

    // Always use multi-agent endpoint (backend preference passed to Flask server)
    fetch('/api/multi-agent/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            message: input,
            mode: agentType,
            history: messages,
            backend: window.AI_BACKEND || 'local'  // 'local' (llama.cpp) or 'cloud' (OpenAI)
        }),
        signal: currentAbortController.signal
    })
    .then(async res => {
        clearTimeout(timeoutId);
        const json = await res.json().catch(()=>({}));
        if (!res.ok) {
            const thinkingElem = document.getElementById(thinkingId);
            if (thinkingElem) thinkingElem.remove();

            // Use formatted error system with recovery suggestions
            const errorMsg = json.error || `HTTP ${res.status}`;
            showFormattedError(errorMsg, 'chat');
            throw new Error(errorMsg);
        }
        return json;
    })
    .then(data => {
        // Remove thinking animation
        const thinkingElem = document.getElementById(thinkingId);
        if (thinkingElem) thinkingElem.remove();

        // Add AI response to chat (multi-agent format)
        console.log('Multi-agent response data:', data);
        let aiText = '';
        if (data.response) {
            // Multi-agent endpoint format
            aiText = data.response;
            if (data.agent_used) {
                console.log('✓ Response from', data.agent_used, 'agent');
            }
        } else if (data.choices && data.choices[0] && data.choices[0].message) {
            aiText = data.choices[0].message.content;
        } else if (data.output) {
            aiText = data.output;
        } else if (data.text) {
            aiText = data.text;
        } else {
            aiText = '[No response]';
            showToast('Received empty response from AI', 3000, 'error');
        }
        console.log('Adding AI message:', aiText.substring(0, 100) + '...');
        addMessage(aiText, 'ai', false);
        appendMessageToCurrentChat('ai', aiText);
    })
    .catch(err => {
        clearTimeout(timeoutId);
        const thinkingElem = document.getElementById(thinkingId);
        if (thinkingElem) thinkingElem.remove();

        // Handle different error types with formatted error system
        if (err.name === 'AbortError') {
            if (userInitiatedStop) {
                // User clicked stop - just show simple toast, no error card
                showToast('Request stopped by user', 2000, 'info');
            } else if (timeoutTriggered) {
                // Timeout - show friendly message
                showToast('Request timed out after 2 minutes. The AI may be busy or the model is loading.', 5000, 'warning');
            } else {
                // Unexpected abort
                showFormattedError('Request was cancelled unexpectedly', 'chat');
            }
        } else {
            // Show formatted error with recovery suggestions
            showFormattedError(err, 'chat');
        }
    })
    .finally(() => {
        // Clear abort controller and reset flags
        currentAbortController = null;
        userInitiatedStop = false;
        timeoutTriggered = false;

        // Re-enable input and button
        if (messageInput) {
            messageInput.disabled = false;
            messageInput.focus(); // Auto-focus for next message
        }
        if (sendBtn) {
            sendBtn.disabled = false;
            sendBtn.textContent = 'SEND';
            sendBtn.removeAttribute('data-state');
            sendBtn.style.backgroundColor = '';
            sendBtn.style.borderColor = '';
            sendBtn.style.color = '';
            console.log('Button reset to SEND in finally');
        }
    });
}

// Message rendering helper: append message to DOM and optionally persist to storage
function addMessage(text, sender = 'user', saveToChat = true, attachments = [], id = null, model = null, timestamp = null) {
    try {
        const container = messagesContainer || document.getElementById('messagesContainer');
        if (!container) return;

        // Safe escape helper (fallback if global escapeHtml not defined yet)
        const esc = (typeof escapeHtml === 'function') ? escapeHtml : (s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'));

        const el = document.createElement('div');
        el.className = 'message ' + (sender ? (sender + '-message') : '');
        if (id) el.id = id;

        // Determine content: allow simple HTML for AI messages (used for thinking animation), escape for others
        let contentHtml = '';
        if (typeof text === 'string') {
            if (sender === 'ai') {
                contentHtml = text; // AI responses may contain minimal HTML (e.g., thinking dots)
            } else {
                contentHtml = '<div>' + esc(text) + '</div>';
            }
        } else {
            contentHtml = '<div>' + esc(String(text)) + '</div>';
        }

        // Attachments (images or links)
        if (attachments && attachments.length) {
            contentHtml += '<div class="message-attachments">';
            attachments.forEach(att => {
                if (!att) return;
                const name = esc(att.name || att.url || 'attachment');
                const url = esc(att.url || '');
                if (url && (/\.(png|jpe?g|gif|webp)$/i.test(url) || (att.contentType && att.contentType.startsWith('image')))) {
                    contentHtml += `<div class="attachment"><img src="${url}" alt="${name}" style="max-width:260px;max-height:260px;border-radius:6px;"/></div>`;
                } else if (url) {
                    contentHtml += `<div class="attachment"><a href="${url}" target="_blank" rel="noopener noreferrer">${name}</a></div>`;
                }
            });
            contentHtml += '</div>';
        }

        const ts = timestamp || Date.now();
        const showTs = (typeof loadSettings === 'function' ? loadSettings().showTimestamps : false);
        const tsHtml = showTs ? `<div class="message-ts">${new Date(ts).toLocaleString()}</div>` : '';

        // Render avatar + message body
        let avatarHtml = '';
        if (sender === 'ai') {
            avatarHtml = `<div class="message-avatar"><img src="img/icchat.png" alt="AI" class="avatar-img"/></div>`;
        } else if (sender === 'user') {
            avatarHtml = `<div class="message-avatar"><div class="user-avatar-text">You:</div></div>`;
        } else {
            avatarHtml = `<div class="message-avatar"></div>`;
        }

        // Hide welcome screen BEFORE adding message (so scroll calculation is correct)
        hideWelcomeScreen();

        // Message action buttons - different for user vs AI messages
        let actionsHtml = '';
        if (sender === 'user') {
            actionsHtml = `
            <div class="message-actions">
                <button class="message-action-btn" onclick="copyMessageText(this)" title="Copy">📋</button>
                <button class="message-action-btn" onclick="editMessage(this)" title="Edit">✏️</button>
                <button class="message-action-btn" onclick="deleteMessage(this)" title="Delete">🗑️</button>
            </div>`;
        } else if (sender === 'ai') {
            actionsHtml = `
            <div class="message-actions">
                <button class="message-action-btn" onclick="copyMessageText(this)" title="Copy">📋</button>
                <button class="message-action-btn" onclick="regenerateResponse(this)" title="Regenerate">🔄</button>
                <button class="message-action-btn" onclick="deleteMessage(this)" title="Delete">🗑️</button>
            </div>`;
        }

        el.innerHTML = `
            <div class="message-row">
                ${avatarHtml}
                <div class="message-body">
                    <div class="message-content">${contentHtml}</div>
                    ${tsHtml}
                    ${actionsHtml}
                </div>
            </div>`;
        container.appendChild(el);
        // Keep scroll at bottom
        container.scrollTop = container.scrollHeight;

        // Persist to storage if requested
        if (saveToChat && typeof appendMessageToCurrentChat === 'function') {
            appendMessageToCurrentChat(sender, typeof text === 'string' ? text : String(text), attachments, id, model);
        }
    } catch (e) {
        console.error('addMessage error', e);
    }
}

// toggleSection moved to js/utils/utils.js (exported to window via main.js)
// networkAction moved to js/core/main.js (exported to window via main.js)

const messagesContainer = document.getElementById('messagesContainer');
const messageInput = document.getElementById('messageInput');
const sendBtn = document.getElementById('sendBtn');
const historyList = document.getElementById('historyList');
const favoritesList = document.getElementById('favoritesList');
const archiveList = document.getElementById('archiveList');
const projectsList = document.getElementById('projectsList');
const fileInput = document.getElementById('fileInput');
const filePreview = document.getElementById('filePreview');
const fileActions = document.getElementById('fileActions');
const modelSelect = document.getElementById('modelSelect');
const settingsOverlay = document.getElementById('settingsOverlay');
const fullHistoryToggle = document.getElementById('fullHistoryToggle');
const stopBtn = document.getElementById('stopBtn');

// 1) dynamic model state
// Use window-scoped arrays so multiple modules and functions can reference dynamic models consistently
window.dynamicOllamaModels = window.dynamicOllamaModels || [];

// 2) refreshOllamaModels moved to js/features/models.js (exported to window via main.js)
// 3) getAllModels moved to js/features/models.js (exported to window via main.js)

// 4) rebuild dropdown DOM
function rebuildModelDropdown() {
    // Keep backward compatibility but centralize dropdown updates
    updateModelSelectDropdown();
}


// 5) hook into DOMContentLoaded and restore sidebar/chat UI
document.addEventListener('DOMContentLoaded', () => {
    // Sidebar toggles - REMOVED event listener that was interfering
    // Headers with onclick attributes handle their own clicks
    // Only non-clickable section headers need toggle functionality (handled by toggleSection)

    // Sidebar open/close (hover strip)
    const hoverStrip = document.getElementById('hoverStrip');
    const sidebar = document.querySelector('.sidebar');
    if (hoverStrip && sidebar) {
        hoverStrip.addEventListener('click', () => {
            sidebar.classList.toggle('hidden');
        });
    }

    // Files panel
    const filesBtn = document.getElementById('filesBtn');
    if (filesBtn) filesBtn.onclick = showFilesPanel;
    const closeFilesBtn = document.getElementById('closeFilesBtn');
    if (closeFilesBtn) closeFilesBtn.onclick = hideFilesPanel;
    initFilesPanelRefs && initFilesPanelRefs();

    // Projects panel
    const projectsBtn = document.getElementById('projectsBtn');
    if (projectsBtn) projectsBtn.onclick = () => {
        const panel = document.getElementById('projectModal');
        if (panel) {
            panel.classList.remove('hidden');
            renderProjects();
        }
    };
    const closeProjectsBtn = document.getElementById('closeProjectsBtn');
    if (closeProjectsBtn) closeProjectsBtn.onclick = () => {
        const panel = document.getElementById('projectModal');
        if (panel) panel.classList.add('hidden');
    };

    // Settings
    const settingsBtn = document.getElementById('settingsBtn');
    if (settingsBtn) settingsBtn.onclick = toggleSettings;
    if (settingsOverlay) settingsOverlay.onclick = (e) => {
        if (e.target === settingsOverlay) toggleSettings();
    };

    // Chat send button and Enter-to-send
    if (sendBtn) {
        sendBtn.onclick = sendMessage;
        // Ensure touch works on mobile
        sendBtn.addEventListener('touchend', function(e) {
            e.preventDefault();
            sendMessage();
        }, { passive: false });
    }
    if (messageInput) {
        messageInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && (!e.shiftKey)) {
                const settings = loadSettings();
                if (settings.enterToSend !== false) {
                    e.preventDefault();
                    sendMessage();
                }
            }
        });

        // Auto-resize textarea as user types (ChatGPT style)
        messageInput.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = Math.min(this.scrollHeight, 200) + 'px';
        });
    }

    // Model selector change
    if (modelSelect) modelSelect.onchange = onModelChange;

    // Dynamic model discovery: fetch Ollama and llama.cpp models
    window.refreshOllamaModels && window.refreshOllamaModels();
    refreshLlamaCppModels && refreshLlamaCppModels();
    initModelSelector && initModelSelector();

    // Render sidebar and chat
    renderHistory && renderHistory();
    renderProjects && renderProjects();
    // Apply appearance (font/colors) from settings on initial load
    try { applyAppearanceSettings(); } catch (e) { /* ignore */ }
    try { updateSettingsUI(); } catch (e) { /* ignore */ }

    // Show welcome screen if no messages exist
    setTimeout(() => showWelcomeScreen(), 100);
});

// Add dynamic llama.cpp model discovery
async function refreshLlamaCppModels() {
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
        renderModelsList && renderModelsList();
    } catch (e) {
        console.error('Failed to refresh llama.cpp models', e);
    }
}

// getAllModels moved to js/features/models.js (exported to window via main.js)

let isWaiting = false;
let abortController = null;
// Note: window.currentChatId and window.currentProjectId are managed by chat.js and exposed via window.*
// Do NOT declare local versions - use window.currentChatId and window.currentProjectId
let thinkingInterval = null;
let editingMessageId = null;
const STORAGE_KEY = 'parakleon_chats_v1';
const PROJECTS_KEY = 'parakleon_projects_v1';
const MODELS_KEY = 'parakleon_models_v1';
const SETTINGS_KEY = 'parakleon_settings_v1';
const MAX_SHORT_HISTORY = 8;

// Default settings
const DEFAULT_SETTINGS = {
    temperature: 0.7,
    maxTokens: 2048,
    topP: 0.9,
    frequencyPenalty: 0.0,
    presencePenalty: 0.0,
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


// Active model configuration - exposed via window.* for cross-module access
// These are the source of truth, accessed by models.js and settings.js
window.ACTIVE_BASE_URL = window.ACTIVE_BASE_URL || 'https://api.openai.com/v1/chat/completions';
// Set Qwen2.5 as default if available, else fallback to OpenAI
window.ACTIVE_MODEL = window.ACTIVE_MODEL || (window.PARAKLEON_CONFIG.DEFAULT_QWEN_MODEL ? `llamacpp:${window.PARAKLEON_CONFIG.DEFAULT_QWEN_MODEL}` : window.PARAKLEON_CONFIG.OPENAI_MODEL);
window.ACTIVE_API_KEY = window.ACTIVE_API_KEY || window.PARAKLEON_CONFIG.OPENAI_API_KEY;
window.ACTIVE_PROVIDER = window.ACTIVE_PROVIDER || 'openai'; // openai, groq, together, huggingface, ollama, webllm
window.ACTIVE_TEMPERATURE = window.ACTIVE_TEMPERATURE ?? 0.7;
window.ACTIVE_MAX_TOKENS = window.ACTIVE_MAX_TOKENS ?? 2048;
window.ACTIVE_TOP_P = window.ACTIVE_TOP_P ?? 0.9;
window.ACTIVE_FREQUENCY_PENALTY = window.ACTIVE_FREQUENCY_PENALTY ?? 0.0;
window.ACTIVE_PRESENCE_PENALTY = window.ACTIVE_PRESENCE_PENALTY ?? 0.0;

// ========== AI Models Manager ==========

const DEFAULT_MODELS = [
    { provider: 'openai', id: 'openai', name: 'gpt-4o-mini', enabled: true },
    // Local llama.cpp Dolphin Phi-2 (direct, legacy endpoint)
    { provider: 'llamacpp', id: 'llamacpp:local', name: '🦙 Dolphin Phi-2 (Uncensored, llama.cpp)', enabled: true },
    // Local llama-server (OpenAI-compatible, any GGUF model)
    { provider: 'llama-server', id: 'llama-server:local', name: '🦙 Local Llama (llama-server, OpenAI API)', enabled: true }
];

const providerLabels = {
    openai: 'OpenAI',
    llamacpp: '🦙 llama.cpp - Local (Uncensored)',
    groq: '☁️ Groq - Cloud (Free, Fast)',
    together: 'Together AI - Cloud (Free)',
    huggingface: 'Hugging Face - Cloud (Free)',
    ollama: 'Ollama - Local Server',
    custom: 'Custom Models'
};

function loadModelsFromStorage() {
    try {
        const stored = localStorage.getItem(MODELS_KEY);
        if (stored) return JSON.parse(stored);
    } catch (e) {
        console.error('Failed to load models', e);
    }
    return [...DEFAULT_MODELS];
}

function saveModelsToStorage(models) {
    try {
        localStorage.setItem(MODELS_KEY, JSON.stringify(models));
    } catch (e) {
        console.error('Failed to save models', e);
    }
}

function openAIModelsManager() {
    const modal = document.getElementById('aiModelsModal');
    if (modal) {
        modal.classList.remove('hidden');
        renderModelsList();
    }
}

function closeAIModelsManager() {
    const modal = document.getElementById('aiModelsModal');
    if (modal) modal.classList.add('hidden');
}

async function switchBackend(useCloud) {  // Toggle between local Ollama and cloud Groq | ref:pkn.html AI Models modal toggle
    const backend = useCloud ? 'cloud' : 'local';

    // Update UI immediately for responsiveness
    const icon = document.getElementById('backendStatusIcon');
    const text = document.getElementById('backendStatusText');
    const desc = document.getElementById('backendStatusDesc');

    if (useCloud) {
        icon.textContent = '☁️';
        text.textContent = 'Cloud (Groq)';
        desc.textContent = 'Fast ~2s • Free API • Online';
    } else {
        icon.textContent = '🏠';
        text.textContent = 'Local (Ollama)';
        desc.textContent = 'Private • Uncensored • Offline';
    }

    // Call backend API to switch
    try {
        const response = await fetch('/api/multi-agent/backend', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ backend })
        });
        const result = await response.json();

        if (result.success) {
            // Save preference to localStorage
            localStorage.setItem('ai-backend', backend);
            window.AI_BACKEND = backend;

            // Update description with device info
            if (useCloud) {
                desc.textContent = `Fast ~2s • ${result.agents_count} agents • Groq Free`;
            } else {
                desc.textContent = `${result.device === 'mobile' ? 'Mobile' : 'PC'} • ${result.agents_count} agents • Uncensored`;
            }

            console.log(`[Backend] Switched to: ${backend.toUpperCase()} (${result.device})`);
        } else {
            // Revert toggle on error
            const toggle = document.getElementById('backendToggle');
            if (toggle) toggle.checked = !useCloud;
            icon.textContent = useCloud ? '🏠' : '☁️';
            text.textContent = useCloud ? 'Local (Ollama)' : 'Cloud (Groq)';
            console.error('[Backend] Switch failed:', result.error);
            alert(result.error || 'Failed to switch backend');
            return;
        }
    } catch (error) {
        console.error('[Backend] API error:', error);
        // Keep localStorage state for offline compatibility
        localStorage.setItem('ai-backend', backend);
        window.AI_BACKEND = backend;
    }

    // Show notification toast
    const toast = document.createElement('div');
    toast.textContent = `AI Backend: ${useCloud ? 'Cloud ☁️ (Fast)' : 'Local 🏠 (Uncensored)'}`;
    toast.style.cssText = 'position:fixed;top:20px;right:20px;background:var(--theme-primary);color:#000;padding:12px 24px;border-radius:8px;z-index:9999;font-weight:600;box-shadow:0 4px 12px rgba(0,255,255,0.3);';
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
}

async function loadBackendPreference() {  // Load saved backend preference on page load | Called during init
    // First check localStorage for cached preference
    const savedBackend = localStorage.getItem('ai-backend') || 'local';
    const toggle = document.getElementById('backendToggle');

    // Set initial UI state from cache
    if (toggle) {
        toggle.checked = (savedBackend === 'cloud');
    }
    window.AI_BACKEND = savedBackend;

    // Then sync with server to get actual status
    try {
        const response = await fetch('/api/multi-agent/backend');
        const status = await response.json();

        if (status.status === 'success') {
            const icon = document.getElementById('backendStatusIcon');
            const text = document.getElementById('backendStatusText');
            const desc = document.getElementById('backendStatusDesc');

            const isCloud = status.backend === 'cloud';

            if (toggle) toggle.checked = isCloud;
            window.AI_BACKEND = status.backend;
            localStorage.setItem('ai-backend', status.backend);

            if (icon && text && desc) {
                if (isCloud) {
                    icon.textContent = '☁️';
                    text.textContent = 'Cloud (Groq)';
                    desc.textContent = `Fast ~2s • ${status.agents_count} agents • Groq Free`;
                } else {
                    icon.textContent = '🏠';
                    text.textContent = 'Local (Ollama)';
                    desc.textContent = `${status.device === 'mobile' ? 'Mobile' : 'PC'} • ${status.agents_count} agents • Uncensored`;
                }
            }

            console.log(`[Backend] Loaded: ${status.backend.toUpperCase()} (${status.device}, ${status.agents_count} agents)`);
        }
    } catch (error) {
        console.warn('[Backend] Could not sync with server, using cached preference');
        // Use cached value - already set above
        const icon = document.getElementById('backendStatusIcon');
        const text = document.getElementById('backendStatusText');
        const desc = document.getElementById('backendStatusDesc');

        if (icon && text && desc) {
            if (savedBackend === 'cloud') {
                icon.textContent = '☁️';
                text.textContent = 'Cloud (Groq)';
                desc.textContent = 'Fast ~2s • Free API • Online';
            } else {
                icon.textContent = '🏠';
                text.textContent = 'Local (Ollama)';
                desc.textContent = 'Private • Uncensored • Offline';
            }
        }
    }
}

function openCodeAcademy() {  // Open DVN Code Academy in new tab | ref:pkn.html sidebar onclick
    window.open('http://localhost:8011', '_blank');
}

function renderModelsList() {
    const listEl = document.getElementById('aiModelsList');
    if (!listEl) return;
    listEl.innerHTML = '';

    // Combine stored models and dynamically discovered models (detected)
    const stored = loadModelsFromStorage() || [];
    let dynamic = [];
    try { dynamic = window.getAllModels ? window.getAllModels() : []; } catch(e) { dynamic = []; }

    // Create a map of models by id with stored taking precedence
    const map = new Map();
    for (const s of stored) {
        if (!s || !s.id) continue;
        map.set(s.id, { ...s, source: 'stored' });
    }
    for (const d of dynamic) {
        if (!d || !d.id) continue;
        if (!map.has(d.id)) map.set(d.id, { ...d, source: 'detected' });
    }

    const combined = Array.from(map.values());

    // Group by provider
    const providers = {};
    combined.forEach(m => {
        const p = m.provider || (m.id && m.id.includes(':') ? m.id.split(':')[0] : 'custom');
        if (!providers[p]) providers[p] = [];
        providers[p].push(m);
    });

    // Render each provider group and its models
    Object.keys(providers).forEach(provider => {
        const group = document.createElement('div');
        group.style.marginBottom = '12px';

        const header = document.createElement('div');
        header.style.cssText = 'font-size:12px;color:#00FFFF;margin-bottom:6px;font-weight:bold;';
        header.textContent = (providerLabels && providerLabels[provider]) ? providerLabels[provider] : provider;
        group.appendChild(header);

        providers[provider].forEach(model => {
            const item = document.createElement('div');
            item.style.cssText = 'display:flex;align-items:center;gap:8px;padding:6px;border-radius:6px;margin-bottom:4px;background:transparent;';
            
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.checked = model.enabled !== false;
            // disable toggling for detected models (they are auto-discovered)
            if (model.source === 'detected') checkbox.disabled = true;
            checkbox.onchange = () => toggleModelEnabled(model.id);
            checkbox.style.cursor = 'pointer';
            
            const nameSpan = document.createElement('span');
            nameSpan.style.cssText = 'flex: 1; font-size: 12px;';
            nameSpan.textContent = model.name || model.id;
            
            const idSpan = document.createElement('span');
            idSpan.style.cssText = 'font-size: 10px; color: #666; max-width: 150px; overflow: hidden; text-overflow: ellipsis;';
            idSpan.textContent = model.id;
            idSpan.title = model.id;
            
            const editBtn = document.createElement('button');
            editBtn.textContent = '✎';
            editBtn.title = 'Rename';
            editBtn.style.cssText = 'background: transparent; border: none; color: #00FFFF; cursor: pointer; font-size: 14px;';
            // Only allow rename for stored/custom models
            if (model.source !== 'stored') editBtn.disabled = true;
            else editBtn.onclick = () => renameModel(model.id);
            
            const deleteBtn = document.createElement('button');
            deleteBtn.textContent = '×';
            deleteBtn.title = 'Remove';
            deleteBtn.style.cssText = 'background: transparent; border: none; color: #ff4444; cursor: pointer; font-size: 16px;';
            if (model.source !== 'stored') deleteBtn.disabled = true; else deleteBtn.onclick = () => removeModel(model.id);
            
            const detectedBadge = (model.source === 'detected') ? (function() { const b = document.createElement('span'); b.textContent = 'detected'; b.style.cssText = 'font-size:10px;color:#66c2c2;margin-left:6px;'; return b; })() : null;

            item.appendChild(checkbox);
            item.appendChild(nameSpan);
            if (detectedBadge) nameSpan.appendChild(detectedBadge);
            item.appendChild(idSpan);
            item.appendChild(editBtn);
            item.appendChild(deleteBtn);
            group.appendChild(item);
        });

        listEl.appendChild(group);
    });
}

function toggleModelEnabled(modelId) {
    const models = loadModelsFromStorage();
    const model = models.find(m => m.id === modelId);
    if (model) {
        model.enabled = !model.enabled;
        saveModelsToStorage(models);
        updateModelSelectDropdown();
    }
}

function renameModel(modelId) {
    const models = loadModelsFromStorage();
    const model = models.find(m => m.id === modelId);
    if (!model) return;
    
    const newName = prompt('Enter new display name:', model.name);
    if (newName && newName.trim()) {
        model.name = newName.trim();
        saveModelsToStorage(models);
        renderModelsList();
        updateModelSelectDropdown();
    }
}

function removeModel(modelId) {
    if (!confirm('Remove this model from the list?')) return;
    
    let models = loadModelsFromStorage();
    models = models.filter(m => m.id !== modelId);
    saveModelsToStorage(models);
    renderModelsList();
    updateModelSelectDropdown();
}

function addCustomModel() {
    const providerEl = document.getElementById('newModelProvider');
    const idEl = document.getElementById('newModelId');
    const nameEl = document.getElementById('newModelName');
    
    const provider = providerEl.value;
    const modelId = idEl.value.trim();
    const displayName = nameEl.value.trim() || modelId;
    
    if (!modelId) {
        alert('Please enter a model ID');
        return;
    }
    
    // Build the full ID with provider prefix
    let fullId = modelId;
    if (provider !== 'openai' && provider !== 'custom' && !modelId.includes(':')) {
        fullId = provider + ':' + modelId;
    }
    
    const models = loadModelsFromStorage();
    
    // Check if already exists
    if (models.find(m => m.id === fullId)) {
        alert('This model already exists');
        return;
    }
    
    models.push({
        provider: provider,
        id: fullId,
        name: displayName,
        enabled: true,
        custom: true
    });
    
    saveModelsToStorage(models);
    renderModelsList();
    updateModelSelectDropdown();
    
    // Clear inputs
    idEl.value = '';
    nameEl.value = '';
    
    showToast('Model added: ' + displayName);
}

function resetModelsToDefault() {
    if (!confirm('Reset all models to defaults? Custom models will be removed.')) return;
    
    saveModelsToStorage([...DEFAULT_MODELS]);
    renderModelsList();
    updateModelSelectDropdown();
    showToast('Models reset to defaults');
}

function updateModelSelectDropdown() {
    if (!modelSelect) return;

    // Build a combined list of stored + dynamically discovered models (Ollama, llama.cpp, etc.)
    const storedModels = loadModelsFromStorage() || [];
    let dynamicModels = [];
    try {
        dynamicModels = window.getAllModels ? window.getAllModels() : [];
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

// Initialize model selector on load
function initModelSelector() {
    const models = loadModelsFromStorage();
    // If no models in storage, save defaults
    if (!localStorage.getItem(MODELS_KEY)) {
        saveModelsToStorage(DEFAULT_MODELS);
    }
    updateModelSelectDropdown();
}

// Web LLM engine (lazy loaded)
let webLLMEngine = null;
let webLLMInitializing = false;

console.log('Initial window.ACTIVE_MODEL:', window.ACTIVE_MODEL);

function onModelChange() {
    const { value } = modelSelect;
    if (value === 'openai') {
        window.ACTIVE_PROVIDER = 'openai';
        window.ACTIVE_BASE_URL = 'https://api.openai.com/v1/chat/completions';
        window.ACTIVE_MODEL = window.PARAKLEON_CONFIG.OPENAI_MODEL;
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
        window.ACTIVE_BASE_URL = window.PARAKLEON_CONFIG.OLLAMA_BASE_URL + '/chat/completions';
        window.ACTIVE_MODEL = modelName;
        window.ACTIVE_API_KEY = 'ollama';
    } else if (value.startsWith('llamacpp:')) {
        window.ACTIVE_PROVIDER = 'llamacpp';
        window.ACTIVE_BASE_URL = window.PARAKLEON_CONFIG.LLAMACPP_BASE_URL + '/chat/completions';
        window.ACTIVE_MODEL = 'local';
        window.ACTIVE_API_KEY = 'llamacpp';
    }
}

// toggleSettings() - MOVED TO js/features/settings.js
// Function is exposed via window.toggleSettings by main.js module

function toggleAgentSwitcher() {
    const panel = document.getElementById('agentSwitcherPanel');
    if (!panel) return;

    const isHidden = panel.classList.contains('hidden');
    panel.classList.toggle('hidden');

    // Update active state when opening
    if (isHidden && window.multiAgentUI) {
        const currentAgent = window.multiAgentUI.currentAgent;
        document.querySelectorAll('.agent-card').forEach(card => {
            if (card.dataset.agentType === currentAgent) {
                card.classList.add('active');
            } else {
                card.classList.remove('active');
            }
        });
    }
}

function showKeyboardShortcuts() {
    const modal = document.getElementById('keyboardShortcutsModal');
    if (modal) {
        modal.classList.remove('hidden');
    }
}

function hideKeyboardShortcuts() {
    const modal = document.getElementById('keyboardShortcutsModal');
    if (modal) {
        modal.classList.add('hidden');
    }
}

// Chat search functionality
let searchMatches = [];
let currentSearchIndex = -1;

function toggleChatSearch() {
    const searchInput = document.getElementById('chatSearchInput');
    const resultsIndicator = document.getElementById('searchResults');

    if (!searchInput) return;

    const isHidden = searchInput.style.display === 'none';

    if (isHidden) {
        // Show search input
        searchInput.style.display = 'block';
        searchInput.focus();

        // Add search listener
        searchInput.addEventListener('input', performChatSearch);
        searchInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                if (e.shiftKey) {
                    navigateSearchResults('prev');
                } else {
                    navigateSearchResults('next');
                }
            }
        });
    } else {
        // Hide search input and clear highlights
        searchInput.style.display = 'none';
        resultsIndicator.style.display = 'none';
        clearSearchHighlights();
        searchMatches = [];
        currentSearchIndex = -1;
    }
}

function performChatSearch() {
    const searchInput = document.getElementById('chatSearchInput');
    const resultsIndicator = document.getElementById('searchResults');
    const query = searchInput.value.trim().toLowerCase();

    // Clear previous highlights
    clearSearchHighlights();
    searchMatches = [];
    currentSearchIndex = -1;

    if (!query) {
        resultsIndicator.style.display = 'none';
        return;
    }

    // Search in all messages
    const messages = document.querySelectorAll('.message-text');
    messages.forEach((messageEl, index) => {
        const text = messageEl.textContent;
        const lowerText = text.toLowerCase();
        let startIndex = 0;

        while ((startIndex = lowerText.indexOf(query, startIndex)) !== -1) {
            searchMatches.push({ element: messageEl, index: startIndex, length: query.length });
            startIndex += query.length;
        }
    });

    // Show results count
    if (searchMatches.length > 0) {
        currentSearchIndex = 0;
        highlightSearchResults();
        resultsIndicator.textContent = `${currentSearchIndex + 1} of ${searchMatches.length}`;
        resultsIndicator.style.display = 'block';

        // Scroll to first result
        scrollToSearchResult(0);
    } else {
        resultsIndicator.textContent = 'No results';
        resultsIndicator.style.display = 'block';
    }
}

function highlightSearchResults() {
    searchMatches.forEach((match, idx) => {
        const element = match.element;
        const html = element.innerHTML;
        const text = element.textContent;

        // Create highlighted version
        const before = text.substring(0, match.index);
        const highlighted = text.substring(match.index, match.index + match.length);
        const after = text.substring(match.index + match.length);

        const highlightClass = idx === currentSearchIndex ? 'search-highlight-current' : 'search-highlight';
        const newHTML = `${before}<span class="${highlightClass}" data-search-index="${idx}">${highlighted}</span>${after}`;

        // Only update if it's not already highlighted
        if (!element.querySelector('.search-highlight')) {
            element.innerHTML = newHTML;
        }
    });
}

function clearSearchHighlights() {
    document.querySelectorAll('.search-highlight, .search-highlight-current').forEach(el => {
        const parent = el.parentNode;
        parent.textContent = parent.textContent; // Remove all HTML, restore plain text
    });
}

function navigateSearchResults(direction) {
    if (searchMatches.length === 0) return;

    if (direction === 'next') {
        currentSearchIndex = (currentSearchIndex + 1) % searchMatches.length;
    } else {
        currentSearchIndex = (currentSearchIndex - 1 + searchMatches.length) % searchMatches.length;
    }

    // Update highlights
    document.querySelectorAll('.search-highlight-current').forEach(el => {
        el.classList.remove('search-highlight-current');
        el.classList.add('search-highlight');
    });

    const currentHighlight = document.querySelector(`[data-search-index="${currentSearchIndex}"]`);
    if (currentHighlight) {
        currentHighlight.classList.remove('search-highlight');
        currentHighlight.classList.add('search-highlight-current');
    }

    // Update counter
    const resultsIndicator = document.getElementById('searchResults');
    if (resultsIndicator) {
        resultsIndicator.textContent = `${currentSearchIndex + 1} of ${searchMatches.length}`;
    }

    // Scroll to result
    scrollToSearchResult(currentSearchIndex);
}

function scrollToSearchResult(index) {
    if (searchMatches[index]) {
        const element = searchMatches[index].element;
        element.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
}

function scrollToBottom() {
    const messagesContainer = document.getElementById('messagesContainer');
    if (messagesContainer) {
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }
}

// Code block copy functionality
function copyCodeBlock(blockId) {
    const codeBlock = document.getElementById(blockId);
    if (!codeBlock) return;

    const code = codeBlock.querySelector('code');
    if (!code) return;

    const text = code.textContent;

    navigator.clipboard.writeText(text).then(() => {
        // Show success feedback
        const btn = codeBlock.parentElement.querySelector('.code-copy-btn');
        if (btn) {
            const originalHTML = btn.innerHTML;
            btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <path d="M13.5 4.5L6 12L2.5 8.5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            </svg> Copied!`;
            btn.style.color = '#10b981';

            setTimeout(() => {
                btn.innerHTML = originalHTML;
                btn.style.color = '';
            }, 2000);
        }
    }).catch(err => {
        console.error('Failed to copy code:', err);
        showToast('Failed to copy code', 2000, 'error');
    });
}

// Initialize syntax highlighting for code blocks
function initSyntaxHighlighting() {
    if (typeof hljs !== 'undefined') {
        document.querySelectorAll('pre code').forEach((block) => {
            hljs.highlightElement(block);
        });
    }
}

// Message action functions
function copyMessageText(btn) {
    console.log('copyMessageText called', btn);
    const messageDiv = btn.closest('.message');
    console.log('messageDiv:', messageDiv);
    if (!messageDiv) return;

    const textEl = messageDiv.querySelector('.message-content');
    console.log('textEl:', textEl);
    if (!textEl) return;

    const text = textEl.textContent;
    console.log('text to copy:', text);

    navigator.clipboard.writeText(text).then(() => {
        // Show success feedback
        const originalText = btn.innerHTML;
        btn.innerHTML = '✅';
        btn.style.color = '#10b981';

        setTimeout(() => {
            btn.innerHTML = originalText;
            btn.style.color = '';
        }, 2000);

        showToast('Message copied!', 2000, 'success');
    }).catch(err => {
        console.error('Failed to copy message:', err);
        showToast('Failed to copy', 2000, 'error');
    });
}

// Expose to window for onclick handlers
window.copyMessageText = copyMessageText;

function editMessage(btn) {
    console.log('editMessage called', btn);
    const messageDiv = btn.closest('.message');
    if (!messageDiv) {
        console.log('No messageDiv found');
        return;
    }

    const textEl = messageDiv.querySelector('.message-content');
    if (!textEl) {
        console.log('No message-content found');
        return;
    }

    const currentText = messageDiv.dataset.content || textEl.textContent;

    // Create edit textarea
    const originalHTML = textEl.innerHTML;
    textEl.innerHTML = `
        <textarea class="message-edit-input" style="width: 100%; min-height: 60px; padding: 8px;
                  background: rgba(0,0,0,0.3); border: 1px solid var(--theme-primary);
                  border-radius: 4px; color: #fff; font-size: 14px; resize: vertical;">${currentText}</textarea>
        <div style="margin-top: 8px; display: flex; gap: 8px;">
            <button onclick="saveEditedMessage(this)" style="padding: 6px 12px; background: var(--theme-primary);
                    color: #000; border: none; border-radius: 4px; cursor: pointer;">Save</button>
            <button onclick="cancelEditMessage(this, \`${originalHTML.replace(/`/g, '\\`')}\`)"
                    style="padding: 6px 12px; background: rgba(255,255,255,0.1); color: #fff;
                    border: 1px solid rgba(255,255,255,0.2); border-radius: 4px; cursor: pointer;">Cancel</button>
        </div>
    `;

    textEl.querySelector('textarea').focus();
}

window.editMessage = editMessage;

function saveEditedMessage(btn) {
    const messageDiv = btn.closest('.message');
    if (!messageDiv) return;

    const textarea = messageDiv.querySelector('.message-edit-input');
    if (!textarea) return;

    const newText = textarea.value.trim();
    if (!newText) {
        showToast('Message cannot be empty', 2000, 'error');
        return;
    }

    // Update the message content
    messageDiv.dataset.content = newText;
    const textEl = messageDiv.querySelector('.message-content');
    if (textEl) {
        textEl.textContent = newText;
    }

    showToast('Message updated!', 2000, 'success');
}

window.saveEditedMessage = saveEditedMessage;

function cancelEditMessage(btn, originalHTML) {
    const messageDiv = btn.closest('.message');
    if (!messageDiv) return;

    const textEl = messageDiv.querySelector('.message-content');
    if (textEl) {
        textEl.innerHTML = originalHTML;
    }
}

window.cancelEditMessage = cancelEditMessage;

function deleteMessage(btn) {
    console.log('deleteMessage called', btn);
    const messageDiv = btn.closest('.message');
    if (!messageDiv) {
        console.log('No messageDiv found');
        return;
    }

    if (confirm('Delete this message?')) {
        messageDiv.style.opacity = '0';
        messageDiv.style.transform = 'translateX(-20px)';
        messageDiv.style.transition = 'all 0.3s ease';

        setTimeout(() => {
            messageDiv.remove();
            showToast('Message deleted', 2000, 'info');
        }, 300);
    }
}

window.deleteMessage = deleteMessage;

function regenerateResponse(btn) {
    const messageDiv = btn.closest('.message');
    if (!messageDiv) return;

    // Find the previous user message
    let prevMessage = messageDiv.previousElementSibling;
    while (prevMessage && !prevMessage.classList.contains('user-message')) {
        prevMessage = prevMessage.previousElementSibling;
    }

    if (!prevMessage) {
        showToast('No user message found to regenerate from', 2000, 'error');
        return;
    }

    const userText = prevMessage.dataset.content || prevMessage.querySelector('.message-text')?.textContent;
    if (!userText) return;

    // Delete current AI message
    messageDiv.remove();

    // Resend the user message
    const messageInput = document.getElementById('messageInput');
    if (messageInput) {
        messageInput.value = userText;
        if (window.sendMessage) {
            window.sendMessage();
        }
    }
}

window.regenerateResponse = regenerateResponse;

// Theme mode switching (dark/light)
function setThemeMode(mode) {
    const html = document.documentElement;

    if (mode === 'light') {
        html.classList.add('light-mode');
    } else {
        html.classList.remove('light-mode');
    }

    // Update button states
    document.querySelectorAll('.theme-mode-btn').forEach(btn => {
        if (btn.dataset.mode === mode) {
            btn.classList.add('active');
            btn.style.background = 'var(--theme-primary)';
            btn.style.color = mode === 'light' ? '#000' : '#000';
        } else {
            btn.classList.remove('active');
            btn.style.background = 'transparent';
            btn.style.color = '#888';
        }
    });

    // Save preference
    localStorage.setItem('themeMode', mode);

    showToast(`${mode === 'light' ? '☀️ Light' : '🌙 Dark'} mode activated`, 2000, 'success');
}

// Load saved theme mode on page load
function loadThemeMode() {
    const savedMode = localStorage.getItem('themeMode') || 'dark';
    setThemeMode(savedMode);
}

// File upload and analysis functionality
function initFileUpload() {
    const fileInput = document.getElementById('fileInput');
    if (!fileInput) return;

    fileInput.addEventListener('change', async (e) => {
        const files = Array.from(e.target.files);
        if (files.length === 0) return;

        for (const file of files) {
            await analyzeUploadedFile(file);
        }

        // Clear the input so the same file can be selected again
        fileInput.value = '';
    });
}

async function analyzeUploadedFile(file) {
    const maxSize = 10 * 1024 * 1024; // 10MB limit
    if (file.size > maxSize) {
        showToast('File too large (max 10MB)', 3000, 'error');
        return;
    }

    // Show upload progress
    showToast(`📎 Analyzing ${file.name}...`, 3000, 'info');

    try {
        // Read file content
        const content = await readFileContent(file);

        // Determine file type and extract text
        let extractedText = '';
        let fileInfo = `**File:** ${file.name}\n**Type:** ${file.type || 'unknown'}\n**Size:** ${(file.size / 1024).toFixed(2)} KB\n\n`;

        if (file.type.startsWith('text/') || file.name.endsWith('.txt') ||
            file.name.endsWith('.md') || file.name.endsWith('.json') ||
            file.name.endsWith('.js') || file.name.endsWith('.py') ||
            file.name.endsWith('.html') || file.name.endsWith('.css')) {
            // Text file - use content directly
            extractedText = content;
        } else if (file.type.startsWith('image/')) {
            // Image file - create data URL for display
            const dataUrl = await fileToDataURL(file);
            fileInfo += `\n![${file.name}](${dataUrl})\n\n`;
            extractedText = "Please analyze this image.";
        } else {
            extractedText = "Binary file uploaded. Unable to extract text content.";
        }

        // Create analysis prompt
        const analysisPrompt = `${fileInfo}**Content:**\n\`\`\`\n${extractedText.substring(0, 5000)}\n\`\`\`\n\nPlease analyze this file and provide insights.`;

        // Add file info to chat
        if (window.multiAgentUI) {
            window.multiAgentUI.addMessageToUI('user', `Uploaded file: ${file.name}`, {});
        }

        // Send to AI for analysis
        const messageInput = document.getElementById('messageInput');
        if (messageInput) {
            messageInput.value = analysisPrompt;
            if (window.sendMessage) {
                window.sendMessage();
            }
        }

        showToast(`✅ ${file.name} analyzed!`, 2000, 'success');
    } catch (error) {
        console.error('Error analyzing file:', error);
        showToast(`Failed to analyze ${file.name}`, 3000, 'error');
    }
}

function readFileContent(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (e) => resolve(e.target.result);
        reader.onerror = (e) => reject(e);
        reader.readAsText(file);
    });
}

function fileToDataURL(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (e) => resolve(e.target.result);
        reader.onerror = (e) => reject(e);
        reader.readAsDataURL(file);
    });
}

// Export chat functionality
function exportChat() {
    // Show export options modal
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.innerHTML = `
        <div class="modal-content" style="max-width: 400px;">
            <div class="modal-header">
                <h3>📥 Export Chat</h3>
                <button onclick="this.closest('.modal-overlay').remove()" class="modal-close">×</button>
            </div>
            <div class="modal-body" style="padding: 20px;">
                <p style="color: #aaa; margin-bottom: 16px;">Choose export format:</p>
                <button onclick="exportChatAs('markdown')" style="width: 100%; margin-bottom: 8px; padding: 12px;">
                    📝 Markdown (.md)
                </button>
                <button onclick="exportChatAs('text')" style="width: 100%; margin-bottom: 8px; padding: 12px;">
                    📄 Plain Text (.txt)
                </button>
                <button onclick="exportChatAs('json')" style="width: 100%; padding: 12px;">
                    📋 JSON (.json)
                </button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
}

function exportChatAs(format) {
    // Get all messages
    const messages = [];
    document.querySelectorAll('.message').forEach(msg => {
        const isUser = msg.classList.contains('user-message');
        const isAI = msg.classList.contains('assistant-message');

        if (isUser || isAI) {
            const role = isUser ? 'user' : 'assistant';
            const textEl = msg.querySelector('.message-text');
            const text = textEl ? textEl.textContent : '';

            messages.push({ role, content: text });
        }
    });

    if (messages.length === 0) {
        showToast('No messages to export', 2000, 'warning');
        return;
    }

    let content = '';
    let filename = '';
    let mimeType = '';

    if (format === 'markdown') {
        content = messages.map(m => `**${m.role === 'user' ? 'You' : 'AI'}:**\n\n${m.content}\n\n---\n`).join('\n');
        filename = `chat-${Date.now()}.md`;
        mimeType = 'text/markdown';
    } else if (format === 'text') {
        content = messages.map(m => `${m.role === 'user' ? 'You' : 'AI'}: ${m.content}\n\n`).join('');
        filename = `chat-${Date.now()}.txt`;
        mimeType = 'text/plain';
    } else if (format === 'json') {
        content = JSON.stringify(messages, null, 2);
        filename = `chat-${Date.now()}.json`;
        mimeType = 'application/json';
    }

    // Create download link
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);

    // Close modal
    document.querySelector('.modal-overlay')?.remove();

    showToast(`Exported as ${format.toUpperCase()}`, 2000, 'success');
}

function toggleFullHistory() {
    if (window.currentProjectId) {
        const projects = loadProjectsFromStorage();
        const project = projects.find(p => p.id === window.currentProjectId);
        const chat = project && project.chats ? project.chats.find(c => c.id === window.currentChatId) : null;
        if (chat) {
            chat.useFullHistory = !!fullHistoryToggle.checked;
            chat.updatedAt = Date.now();
            saveProjectsToStorage(projects);
            renderProjects();
        }
    } else {
        let chats = loadChatsFromStorage();
        const chat = getCurrentChat(chats);
        if (chat) {
            chat.useFullHistory = !!fullHistoryToggle.checked;
            chat.updatedAt = Date.now();
            saveChatsToStorage(chats);
            renderHistory();
        }
    }
}

function confirmDeleteAllChats() {
    if (confirm('Are you sure you want to delete all chats? This cannot be undone.')) {
        localStorage.removeItem('parakleon_chats_v1');
        localStorage.removeItem('window.currentChatId');
        window.currentChatId = null;
        clearMessages();
        toggleSettings();
        renderHistory(); // Re-render to show the "+ New chat" button
        // Show system message without saving to chat
        const systemDiv = document.createElement('div');
        systemDiv.className = 'message system-message';
        systemDiv.textContent = 'All chats deleted.';
        messagesContainer.appendChild(systemDiv);
    }
}

function confirmDeleteAllProjects() {
    if (confirm('Are you sure you want to delete all projects? This will delete all project chats and cannot be undone.')) {
        localStorage.removeItem('parakleon_projects_v1');
        if (window.currentProjectId) {
            window.currentProjectId = null;
            window.currentChatId = null;
            clearMessages();
        }
        toggleSettings();
        renderProjects();
        renderHistory();
        // Show system message without saving to chat
        const systemDiv = document.createElement('div');
        systemDiv.className = 'message system-message';
        systemDiv.textContent = 'All projects deleted.';
        messagesContainer.appendChild(systemDiv);
    }
}

// CLI Access Functions
function copyCliCommands() {
    const commands = `# Control services:
./pkn_control.sh start-all
./pkn_control.sh status
./pkn_control.sh stop-all

# View logs:
tail -f divinenode.log

# Test agents:
python3 test_free_agents.py`;

    navigator.clipboard.writeText(commands).then(() => {
        showToast('CLI commands copied to clipboard!', 2000, 'success');
    }).catch(err => {
        console.error('Failed to copy:', err);
        showToast('Failed to copy commands', 2000, 'error');
    });
}

// Service status checker
async function checkServicesStatus() {
    const statusModal = document.createElement('div');
    statusModal.className = 'settings-overlay';
    statusModal.style.display = 'flex';
    statusModal.innerHTML = `
        <div style="background: rgba(0, 0, 0, 0.95); border: 2px solid var(--theme-primary); border-radius: 8px; padding: 24px; max-width: 500px;">
            <h2 style="color: var(--theme-primary); margin-top: 0; font-size: 18px; margin-bottom: 20px;">Service Status</h2>

            <div id="serviceStatusContent" style="color: #fff; font-size: 13px;">
                <div style="text-align: center; padding: 20px;">
                    <div style="color: var(--theme-primary);">Checking services...</div>
                </div>
            </div>

            <div style="text-align: center; margin-top: 20px;">
                <button onclick="this.closest('.settings-overlay').remove()" style="background: var(--theme-primary); color: #000; border: none; padding: 10px 24px; border-radius: 6px; cursor: pointer; font-weight: 700;">Close</button>
            </div>
        </div>
    `;
    document.body.appendChild(statusModal);

    // Check services
    const content = document.getElementById('serviceStatusContent');
    let html = '';

    // Check Flask server (divinenode)
    try {
        const response = await fetch('http://localhost:8010/health', { timeout: 2000 });
        if (response.ok) {
            html += '<div style="margin-bottom: 12px;"><span style="color: #10b981;">🟢 Flask Server</span> - Running on port 8010</div>';
        } else {
            html += '<div style="margin-bottom: 12px;"><span style="color: #f59e0b;">🟡 Flask Server</span> - Responding but unhealthy</div>';
        }
    } catch (e) {
        html += '<div style="margin-bottom: 12px;"><span style="color: #ef4444;">🔴 Flask Server</span> - Not running</div>';
        html += '<div style="margin-left: 20px; font-size: 11px; color: #666; margin-bottom: 12px;">Start with: ./pkn_control.sh start-divinenode</div>';
    }

    // Check llama.cpp server
    try {
        const response = await fetch('http://localhost:8000/v1/models', { timeout: 2000 });
        if (response.ok) {
            html += '<div style="margin-bottom: 12px;"><span style="color: #10b981;">🟢 LLM Server (llama.cpp)</span> - Running on port 8000</div>';
        } else {
            html += '<div style="margin-bottom: 12px;"><span style="color: #f59e0b;">🟡 LLM Server</span> - Responding but unhealthy</div>';
        }
    } catch (e) {
        html += '<div style="margin-bottom: 12px;"><span style="color: #ef4444;">🔴 LLM Server (llama.cpp)</span> - Not running</div>';
        html += '<div style="margin-left: 20px; font-size: 11px; color: #666; margin-bottom: 12px;">Start with: ./pkn_control.sh start-llama</div>';
    }

    // Overall status
    if (html.includes('🔴')) {
        html += '<div style="margin-top: 20px; padding: 12px; background: rgba(239, 68, 68, 0.1); border: 1px solid #ef4444; border-radius: 6px;">';
        html += '<div style="color: #ef4444; font-weight: 700; margin-bottom: 6px;">⚠️ Some services are down</div>';
        html += '<div style="font-size: 11px; color: #999;">Run: ./pkn_control.sh start-all</div>';
        html += '</div>';
    } else {
        html += '<div style="margin-top: 20px; padding: 12px; background: rgba(16, 185, 129, 0.1); border: 1px solid #10b981; border-radius: 6px;">';
        html += '<div style="color: #10b981; font-weight: 700;">✓ All services running</div>';
        html += '</div>';
    }

    content.innerHTML = html;
}

function showCliHelp() {
    const helpContent = `
        <div style="background: rgba(0, 0, 0, 0.95); border: 2px solid var(--theme-primary); border-radius: 8px; padding: 24px; max-width: 600px; max-height: 80vh; overflow-y: auto; color: #fff;">
            <h2 style="color: var(--theme-primary); margin-top: 0; font-size: 20px; margin-bottom: 16px;">⌨️ Divine Node CLI Guide</h2>

            <div style="margin-bottom: 20px;">
                <h3 style="color: var(--theme-primary); font-size: 14px; margin-bottom: 8px;">Service Management</h3>
                <code style="display: block; background: #000; padding: 8px; border-radius: 4px; font-size: 12px; margin-bottom: 4px;">./pkn_control.sh start-all</code>
                <p style="color: #999; font-size: 12px; margin: 4px 0 12px 0;">Start all Divine Node services (Flask + llama.cpp)</p>

                <code style="display: block; background: #000; padding: 8px; border-radius: 4px; font-size: 12px; margin-bottom: 4px;">./pkn_control.sh stop-all</code>
                <p style="color: #999; font-size: 12px; margin: 4px 0 12px 0;">Stop all running services</p>

                <code style="display: block; background: #000; padding: 8px; border-radius: 4px; font-size: 12px; margin-bottom: 4px;">./pkn_control.sh status</code>
                <p style="color: #999; font-size: 12px; margin: 4px 0 12px 0;">Check service status and port usage</p>

                <code style="display: block; background: #000; padding: 8px; border-radius: 4px; font-size: 12px; margin-bottom: 4px;">./pkn_control.sh restart-llama</code>
                <p style="color: #999; font-size: 12px; margin: 4px 0;">Restart the LLM inference server</p>
            </div>

            <div style="margin-bottom: 20px;">
                <h3 style="color: var(--theme-primary); font-size: 14px; margin-bottom: 8px;">Debugging & Logs</h3>
                <code style="display: block; background: #000; padding: 8px; border-radius: 4px; font-size: 12px; margin-bottom: 4px;">tail -f divinenode.log</code>
                <p style="color: #999; font-size: 12px; margin: 4px 0 12px 0;">View Flask server logs in real-time</p>

                <code style="display: block; background: #000; padding: 8px; border-radius: 4px; font-size: 12px; margin-bottom: 4px;">tail -f llama.log</code>
                <p style="color: #999; font-size: 12px; margin: 4px 0 12px 0;">View llama.cpp inference logs</p>

                <code style="display: block; background: #000; padding: 8px; border-radius: 4px; font-size: 12px; margin-bottom: 4px;">./pkn_control.sh debug-qwen</code>
                <p style="color: #999; font-size: 12px; margin: 4px 0;">Test LLM connection and health</p>
            </div>

            <div style="margin-bottom: 20px;">
                <h3 style="color: var(--theme-primary); font-size: 14px; margin-bottom: 8px;">Testing</h3>
                <code style="display: block; background: #000; padding: 8px; border-radius: 4px; font-size: 12px; margin-bottom: 4px;">python3 test_free_agents.py</code>
                <p style="color: #999; font-size: 12px; margin: 4px 0 12px 0;">Test multi-agent system</p>

                <code style="display: block; background: #000; padding: 8px; border-radius: 4px; font-size: 12px; margin-bottom: 4px;">./test_streaming.sh</code>
                <p style="color: #999; font-size: 12px; margin: 4px 0;">Test streaming responses</p>
            </div>

            <div style="margin-bottom: 20px;">
                <h3 style="color: var(--theme-primary); font-size: 14px; margin-bottom: 8px;">API Endpoints</h3>
                <code style="display: block; background: #000; padding: 8px; border-radius: 4px; font-size: 12px; margin-bottom: 4px;">curl http://localhost:8010/health</code>
                <p style="color: #999; font-size: 12px; margin: 4px 0 12px 0;">Check server health</p>

                <code style="display: block; background: #000; padding: 8px; border-radius: 4px; font-size: 12px; margin-bottom: 4px;">curl http://localhost:8000/v1/models</code>
                <p style="color: #999; font-size: 12px; margin: 4px 0;">List available LLM models</p>
            </div>

            <div style="text-align: center; margin-top: 24px;">
                <button onclick="this.closest('.settings-overlay').remove()" style="background: var(--theme-primary); color: #000; border: none; padding: 10px 24px; border-radius: 6px; cursor: pointer; font-weight: 700;">Got it!</button>
            </div>
        </div>
    `;

    const overlay = document.createElement('div');
    overlay.className = 'settings-overlay';
    overlay.style.display = 'flex';
    overlay.innerHTML = helpContent;
    overlay.onclick = (e) => {
        if (e.target === overlay) overlay.remove();
    };
    document.body.appendChild(overlay);
}

// Storage functions moved to ../utils/storage.js (loaded via main.js module)

// renderHistory moved to ../features/history.js (loaded via main.js module)

// History menu functions moved to ../features/history.js (loaded via main.js module)
// closeHistoryMenu, openHistoryMenu, toggleFavoriteChat, toggleArchiveChat

// toggleArchiveChat, getCurrentChat, ensureCurrentChat moved to ../features/history.js and ../ui/chat.js

// appendMessageToCurrentChat moved to ../ui/chat.js

// loadChat moved to ../features/history.js

// reloadCurrentChat, deleteChat, renameChatPrompt, renameChat, newChat, backupChat, importBackup
// All moved to ../features/history.js (loaded via main.js module)

// ===== SETTINGS MANAGEMENT =====
function loadSettings() {
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

function saveSettings(settings) {
    try {
        localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
    } catch (e) {
        console.error('Failed to save settings', e);
    }
}

function getApiKeyForProvider(provider) {
    const settings = loadSettings();
    const storedKey = settings.apiKeys[provider];
    if (storedKey) return storedKey;
    
    // Fall back to config.js keys
    switch (provider) {
        case 'openai': return window.PARAKLEON_CONFIG.OPENAI_API_KEY || '';
        case 'groq': return window.PARAKLEON_CONFIG.GROQ_API_KEY || '';
        case 'together': return window.PARAKLEON_CONFIG.TOGETHER_API_KEY || '';
        case 'huggingface': return window.PARAKLEON_CONFIG.HUGGINGFACE_API_KEY || '';
        default: return '';
    }
}

function updateSettingsUI() {
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

    // Top P
    const topPSlider = document.getElementById('topPSlider');
    const topPValue = document.getElementById('topPValue');
    if (topPSlider) {
        topPSlider.value = settings.topP || 0.9;
        if (topPValue) topPValue.textContent = settings.topP || 0.9;
    }

    // Frequency Penalty
    const freqSlider = document.getElementById('frequencyPenaltySlider');
    const freqValue = document.getElementById('frequencyPenaltyValue');
    if (freqSlider) {
        freqSlider.value = settings.frequencyPenalty || 0.0;
        if (freqValue) freqValue.textContent = settings.frequencyPenalty || 0.0;
    }

    // Presence Penalty
    const presSlider = document.getElementById('presencePenaltySlider');
    const presValue = document.getElementById('presencePenaltyValue');
    if (presSlider) {
        presSlider.value = settings.presencePenalty || 0.0;
        if (presValue) presValue.textContent = settings.presencePenalty || 0.0;
    }

    // Enter to Send
    const enterToggle = document.getElementById('enterToSendToggle');
    if (enterToggle) enterToggle.checked = settings.enterToSend;
    
    // Timestamps
    const timestampsToggle = document.getElementById('showTimestampsToggle');
    if (timestampsToggle) timestampsToggle.checked = settings.showTimestamps;
    
    // API Keys (show masked)
    ['openai', 'groq', 'together', 'huggingface'].forEach(provider => {
        const input = document.getElementById(`apiKey_${provider}`);
        if (input) {
            const key = settings.apiKeys[provider] || '';
            input.value = key;
            input.placeholder = getApiKeyForProvider(provider) ? '••••••••' : 'Not configured';
        }
    });
    
    // Appearance UI (chat + UI font, colors)
    const chatFontSelect = document.getElementById('chatFontSelect');
    if (chatFontSelect) chatFontSelect.value = settings.chatFontFamily || DEFAULT_SETTINGS.chatFontFamily;

    const uiFontSelect = document.getElementById('uiFontSelect');
    if (uiFontSelect) uiFontSelect.value = settings.uiFontFamily || DEFAULT_SETTINGS.uiFontFamily;

    const inputColor = document.getElementById('inputTextColor');
    if (inputColor) inputColor.value = settings.inputTextColor || DEFAULT_SETTINGS.inputTextColor;

    const outputColor = document.getElementById('outputTextColor');
    if (outputColor) outputColor.value = settings.outputTextColor || DEFAULT_SETTINGS.outputTextColor;

    // Chat font size slider
    const chatFontSizeSlider = document.getElementById('chatFontSizeSlider');
    const chatFontSizeValue = document.getElementById('chatFontSizeValue');
    if (chatFontSizeSlider) {
        chatFontSizeSlider.value = settings.chatFontSize || DEFAULT_SETTINGS.chatFontSize;
        if (chatFontSizeValue) chatFontSizeValue.textContent = (settings.chatFontSize || DEFAULT_SETTINGS.chatFontSize) + 'px';
    }

    // Apply appearance settings immediately so preview and UI reflect them
    try { applyAppearanceSettings(); } catch (e) { /* ignore if not yet defined */ }

    // Update active settings
    window.ACTIVE_TEMPERATURE = settings.temperature;
    window.ACTIVE_MAX_TOKENS = settings.maxTokens;
    window.ACTIVE_TOP_P = settings.topP || 0.9;
    window.ACTIVE_FREQUENCY_PENALTY = settings.frequencyPenalty || 0.0;
    window.ACTIVE_PRESENCE_PENALTY = settings.presencePenalty || 0.0;
}

// ===== SETTINGS SAVE FUNCTIONS - MOVED TO js/features/settings.js =====
// The following functions are now in settings.js and exposed via window.* by main.js:
// - saveTemperature, saveMaxTokens, saveTopP
// - saveFrequencyPenalty, savePresencePenalty
// - saveEnterToSend, saveShowTimestamps, saveApiKey

// ===== APPEARANCE FUNCTIONS - MOVED TO js/features/settings.js =====
// The following functions are now in settings.js and exposed via window.* by main.js:
// - applyAppearanceSettings, saveChatFontFamily, saveUIFontFamily
// - saveInputTextColor, saveOutputTextColor, saveChatFontSize
// - getStorageUsage, formatFileSize
// - toggleFullHistory, confirmDeleteAllChats, confirmDeleteAllProjects

// ===== IMAGE FUNCTIONS - MOVED TO js/features/images.js =====
// The following functions are now in images.js and exposed via window.* by main.js:
// - openImageGenerator, closeImageGenerator, generateImage
// - openImagesGallery, closeImagesGallery, clearGeneratedImages
// - renderImages, saveGeneratedImages, renderImagesGallery
// - openImageModal, deleteImage, deleteImageFromGallery

// ===== GLOBAL FILES PANEL MANAGEMENT =====
let filesPanel, filesListEl;

function initFilesPanelRefs() {
    filesPanel = document.getElementById('filesPanel');
    filesListEl = document.getElementById('filesList');
}
function showFilesPanel() {
    console.log('showFilesPanel called'); // Debugging line
    if (filesPanel) {
        filesPanel.classList.remove('hidden');
        renderGlobalFilesList();
    }
}

function hideFilesPanel() {
    console.log('hideFilesPanel called'); // Debugging line
    if (filesPanel) {
        filesPanel.classList.add('hidden');
    }
}

async function renderGlobalFilesList() {
    if (!filesListEl) return;
    filesListEl.innerHTML = '<p style="color: #666; text-align: center; padding: 20px;">Loading files...</p>';

    try {
        const response = await fetch('/api/files/list');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        const files = data.files || [];

        filesListEl.innerHTML = ''; // Clear loading message

        if (files.length === 0) {
            filesListEl.innerHTML = '<p style="color: #999; text-align: center; padding: 20px;">No files uploaded yet.</p>';
            return;
        }

        files.forEach(file => {
            const item = document.createElement('div');
            item.className = 'file-item'; // Use existing file-item style
            item.style.display = 'flex';
            item.style.justifyContent = 'space-between';
            item.style.alignItems = 'center';
            item.style.padding = '8px';
            item.style.marginBottom = '4px';
            item.style.background = 'rgba(0,255,255,0.05)';
            item.style.borderRadius = '4px';

            const isImage = file.filename.match(/\.(jpeg|jpg|gif|png|webp|svg)$/i);
            const icon = isImage ? '🖼️' : '📄';
            const size = formatFileSize(file.size);

            item.innerHTML = `
                <span>${icon} ${escapeHtml(file.filename)} <small style="color:#666">(${size})</small></span>
                <button onclick="deleteGlobalFile('${file.id}')" style="background:transparent;border:none;color:#ff4444;cursor:pointer;font-size:16px;">×</button>
            `;
            filesListEl.appendChild(item);
        });

    } catch (error) {
        console.error('Failed to load global files:', error);
        filesListEl.innerHTML = `<p style="color: #ff6b6b; text-align: center; padding: 20px;">Error loading files: ${error.message}</p>`;
    }
}

async function deleteGlobalFile(fileId) {
    if (!confirm('Are you sure you want to delete this file permanently? This cannot be undone.')) {
        return;
    }

    try {
        const response = await fetch(`/api/files/${fileId}`, {
            method: 'DELETE'
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
            throw new Error(errorData.error || `Server error: ${response.status}`);
        }
        
        showToast('File deleted successfully.');
        renderGlobalFilesList(); // Refresh the list

    } catch (error) {
        console.error('Failed to delete file:', error);
        alert(`Failed to delete file: ${error.message}`);
    }
}

// ===== PROJECTS MANAGEMENT =====
function loadProjectsFromStorage() {
    try {
        const raw = localStorage.getItem(PROJECTS_KEY);
        if (!raw) return [];
        return JSON.parse(raw);
    } catch (e) {
        console.error('Failed to load projects', e);
        return [];
    }
}

function saveProjectsToStorage(projects) {
    try {
        localStorage.setItem(PROJECTS_KEY, JSON.stringify(projects));
    } catch (e) {
        console.error('Failed to save projects', e);
    }
}

function createNewProject() {
    const modal = document.getElementById('projectModal');
    if (modal) {
        modal.classList.remove('hidden');
        document.getElementById('projectName').value = '';
        document.getElementById('projectPrompt').value = '';
        document.getElementById('projectFilesList').innerHTML = '';
        window.projectModalFiles = [];
    }
}

function closeProjectModal() {
    const modal = document.getElementById('projectModal');
    if (modal) modal.classList.add('hidden');
}

function showMoveToProjectModal(chatId) {
    const modal = document.getElementById('moveToProjectModal');
    const list = document.getElementById('moveToProjectList');
    
    if (!modal || !list) return;
    
    const projects = loadProjectsFromStorage();
    list.innerHTML = '';
    
    if (projects.length === 0) {
        list.innerHTML = '<p style="color: #999; text-align: center; padding: 20px;">No projects available. Create a project first.</p>';
    } else {
        projects.forEach(project => {
            const item = document.createElement('div');
            item.className = 'project-file-item';
            item.style.cursor = 'pointer';
            item.style.padding = '12px';
            item.style.marginBottom = '8px';
            item.style.border = '1px solid #333';
            item.style.borderRadius = '4px';
            item.style.transition = 'background 0.2s';
            item.innerHTML = `<strong>${escapeHtml(project.name)}</strong>`;
            if (project.description) {
                item.innerHTML += `<br><small style="color: #999;">${escapeHtml(project.description)}</small>`;
            }
            item.onmouseover = () => item.style.background = '#222';
            item.onmouseout = () => item.style.background = '';
            item.onclick = () => {
                moveChatToProject(chatId, project.id);
                closeMoveToProjectModal();
            };
            list.appendChild(item);
        });
    }

    modal.classList.remove('hidden');
}

function closeMoveToProjectModal() {
    const modal = document.getElementById('moveToProjectModal');
    if (modal) modal.classList.add('hidden');
}

function moveChatToProject(chatId, projectId) {
    // Get the chat from global storage
    let chats = loadChatsFromStorage();
    const chatIndex = chats.findIndex(c => c.id === chatId);
    
    if (chatIndex === -1) {
        alert('Chat not found.');
        return;
    }
    
    const chat = chats[chatIndex];
    
    // Get the project
    const projects = loadProjectsFromStorage();
    const project = projects.find(p => p.id === projectId);
    
    if (!project) {
        alert('Project not found.');
        return;
    }
    
    // Move chat to project
    if (!project.chats) project.chats = [];
    project.chats.unshift(chat);
    
    // Remove from global chats
    chats.splice(chatIndex, 1);
    
    // Save both
    saveChatsToStorage(chats);
    saveProjectsToStorage(projects);
    
    // Update UI
    if (window.currentChatId === chatId) {
        window.currentChatId = null;
        clearMessages();
    }
    renderHistory();
    
    // Show confirmation
    const systemDiv = document.createElement('div');
    systemDiv.className = 'message system-message';
    systemDiv.textContent = `Chat moved to project "${project.name}".`;
    messagesContainer.appendChild(systemDiv);
}

function handleProjectFiles() {
    const input = document.getElementById('projectFilesInput');
    const filesList = document.getElementById('projectFilesList');
    if (!input.files || !input.files.length) return;
    
    window.projectModalFiles = window.projectModalFiles || [];
    
    Array.from(input.files).forEach(file => {
        window.projectModalFiles.push(file);
        const fileItem = document.createElement('div');
        fileItem.className = 'project-file-item';
        fileItem.innerHTML = `<span>${escapeHtml(file.name)}</span><button onclick="removeProjectFile('${escapeHtml(file.name)}')">×</button>`;
        filesList.appendChild(fileItem);
    });
    
    input.value = '';
}

function removeProjectFile(fileName) {
    window.projectModalFiles = (window.projectModalFiles || []).filter(f => f.name !== fileName);
    const filesList = document.getElementById('projectFilesList');
    Array.from(filesList.children).forEach(item => {
        if (item.textContent.includes(fileName)) item.remove();
    });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

async function saveNewProject() {
    const name = document.getElementById('projectName').value.trim();
    const systemPrompt = document.getElementById('projectPrompt').value.trim();
    const files = window.projectModalFiles || [];
    
    if (!name) {
        alert('Please enter a project name.');
        return;
    }
    
    const projects = loadProjectsFromStorage();
    const projectId = 'project_' + Date.now();
    const chatId = 'chat_' + Date.now();
    
    // Upload project files to server
    const uploadedFiles = [];
    for (const file of files) {
        try {
            const fd = new FormData();
            fd.append('file', file);
            const resp = await fetch('/api/files/upload', { method: 'POST', body: fd });
            const j = await resp.json();
            if (resp.ok) {
                uploadedFiles.push({
                    id: j.id,
                    filename: j.filename,
                    storedName: j.stored_name,
                    size: file.size,
                    uploadedAt: Date.now()
                });
            }
        } catch (e) {
            console.error('File upload failed:', e);
        }
    }
    
    // Create first chat for the project
    const firstChat = {
        id: chatId,
        title: 'Project Chat',
        messages: [],
        starred: false,
        archived: false,
        useFullHistory: true,
        updatedAt: Date.now()
    };
    
    // Add system prompt as first message if provided
    if (systemPrompt) {
        firstChat.messages.push({
            id: 'msg_' + Date.now(),
            sender: 'system',
            text: 'System Prompt: ' + systemPrompt,
            timestamp: Date.now()
        });
    }
    
    projects.push({
        id: projectId,
        name: name,
        systemPrompt: systemPrompt,
        description: '',
        chats: [firstChat],
        files: uploadedFiles,
        images: [],
        createdAt: Date.now(),
        updatedAt: Date.now()
    });
    
    saveProjectsToStorage(projects);
    window.currentProjectId = projectId;
    window.currentChatId = chatId;
    renderProjects();
    closeProjectModal();
    
    // Load the project's first chat
    clearMessages();
    if (systemPrompt) {
        addMessage('System Prompt: ' + systemPrompt, 'system', false);
    }
    
    let msg = `Project "${name}" created`;
    if (uploadedFiles.length > 0) {
        msg += ` with ${uploadedFiles.length} file${uploadedFiles.length > 1 ? 's' : ''}`;
    }
    addMessage(msg + '.', 'system', false);
}

function renderProjects() {
    const projects = loadProjectsFromStorage();
    
    if (!projectsList) return;
    projectsList.innerHTML = '';
    
    projects.forEach(project => {
        const item = document.createElement('div');
        item.className = 'project-item' + (project.id === window.currentProjectId ? ' active' : '');
        item.dataset.projectId = project.id;
        
        const nameDiv = document.createElement('div');
        nameDiv.className = 'project-name';
        nameDiv.textContent = project.name;
        nameDiv.onclick = (e) => {
            e.stopPropagation();
            switchProject(project.id);
        };
        item.appendChild(nameDiv);
        
        const menuBtn = document.createElement('button');
        menuBtn.className = 'history-menu-btn';
        menuBtn.style.padding = '2px 4px';
        menuBtn.textContent = '⋮';
        menuBtn.onclick = (e) => {
            e.stopPropagation();
            openProjectMenu(project.id, menuBtn);
        };
        item.appendChild(menuBtn);
        
        projectsList.appendChild(item);
    });
}

// Project menu and switching helpers
function switchProject(projectId) {
    const projects = loadProjectsFromStorage();
    const project = projects.find(p => p.id === projectId);
    if (!project) return;
    window.currentProjectId = projectId;
    if (project.chats && project.chats.length > 0) {
        window.currentChatId = project.chats[0].id;
    } else {
        window.currentChatId = null;
    }
    clearMessages();
    if (window.currentChatId) {
        reloadCurrentChat();
    } else if (project.systemPrompt) {
        addMessage('System Prompt: ' + project.systemPrompt, 'system', false);
    }
    renderProjects();
    renderHistory();
}

function openProjectMenu(projectId, anchorButton) {
    closeHistoryMenu();

    const rect = anchorButton.getBoundingClientRect();
    const containerRect = document.body.getBoundingClientRect();

    const menu = document.createElement('div');
    menu.className = 'history-menu';

    const openItem = document.createElement('div');
    openItem.className = 'history-menu-item';
    openItem.textContent = 'Open project';
    openItem.onclick = () => {
        switchProject(projectId);
        closeHistoryMenu();
    };
    menu.appendChild(openItem);

    const renameItem = document.createElement('div');
    renameItem.className = 'history-menu-item';
    renameItem.textContent = 'Rename project';
    renameItem.onclick = () => {
        const newName = prompt('Enter new project name:');
        if (newName && newName.trim()) {
            const projects = loadProjectsFromStorage();
            const project = projects.find(p => p.id === projectId);
            if (project) {
                project.name = newName.trim();
                saveProjectsToStorage(projects);
                renderProjects();
            }
        }
        closeHistoryMenu();
    };
    menu.appendChild(renameItem);

    const deleteItem = document.createElement('div');
    deleteItem.className = 'history-menu-item';
    deleteItem.textContent = 'Delete project';
    deleteItem.onclick = () => {
        if (confirm('Delete this project and all its chats?')) {
            let projects = loadProjectsFromStorage();
            projects = projects.filter(p => p.id !== projectId);
            saveProjectsToStorage(projects);
            if (window.currentProjectId === projectId) {
                window.currentProjectId = null;
                window.currentChatId = null;
                clearMessages();
            }
            renderProjects();
            renderHistory();
        }
        closeHistoryMenu();
    };
    menu.appendChild(deleteItem);

    const top = rect.top - containerRect.top + window.scrollY;
    const left = rect.left - containerRect.left + window.scrollX;
    menu.style.top = top + 'px';
    menu.style.left = left + 'px';

    document.body.appendChild(menu);
    openMenuElement = menu;
}

// Add backend health check + UI banner (shows when a simple static server is running)
async function checkBackend(showToastOnFail = true) {
	const tryFetch = async (url) => {
		try {
			const r = await fetch(url, { cache: 'no-store' });
			return r && r.ok;
		} catch (e) {
			return false;
		}
	};

	try {
		let ok = await tryFetch('/api/health');
		if (!ok) ok = await tryFetch('/health');

		if (!ok) {
			showBackendBanner('Backend API not reachable. It looks like you are serving static files (python -m http.server). Start the Flask backend: <code>python divinenode_server.py --host 0.0.0.0 --port 8010</code> or run <code>./start_parakleon.sh</code>.');
			if (typeof showToast === 'function' && showToastOnFail) showToast('Backend not detected - APIs disabled');
			return false;
		} else {
			hideBackendBanner();
			// Re-fetch models when backend comes online
			window.refreshOllamaModels && window.refreshOllamaModels();
			if (typeof showToast === 'function' && showToastOnFail) showToast('Backend online', 1200);
			return true;
		}
	} catch (e) {
		console.error('Backend check failed', e);
		showBackendBanner('Failed to check backend: ' + (e && e.message ? e.message : e));
		if (typeof showToast === 'function' && showToastOnFail) showToast('Backend check failed');
		return false;
	}
}

function showBackendBanner(htmlMessage) {
	let banner = document.getElementById('backendBanner');
	if (!banner) {
		banner = document.createElement('div');
		banner.id = 'backendBanner';
		banner.style.cssText = 'position:fixed;top:8px;left:36px;right:8px;z-index:9999;padding:10px;border-radius:6px;background:#ff5a5a;color:#fff;display:flex;align-items:center;justify-content:space-between;gap:12px;box-shadow:0 6px 18px rgba(0,0,0,0.6);font-size:13px;';
		document.body.appendChild(banner);
	}
	banner.innerHTML = `<div style="flex:1;">${htmlMessage}</div>`;
	const actions = document.createElement('div');
	actions.style.cssText = 'display:flex;gap:8px;margin-left:8px;';
	const retry = document.createElement('button');
	retry.className = 'settings-action-btn';
	retry.textContent = 'Retry';
	retry.onclick = () => checkBackend(true);
	const guide = document.createElement('button');
	guide.className = 'settings-action-btn';
	guide.textContent = 'How to fix';
	guide.onclick = () => window.open('/SETUP_GUIDE.md', '_blank');
	actions.appendChild(retry);
	actions.appendChild(guide);
	// replace any old actions
	const oldActions = banner.querySelector('div:last-child');
	if (oldActions) oldActions.remove();
	banner.appendChild(actions);
	banner.style.display = 'flex';
}

function hideBackendBanner() {
	const b = document.getElementById('backendBanner');
	if (b) b.style.display = 'none';
}

// --- Application Initialization ---
function init() {
	if (init._ran) return; // idempotent guard in case init is called twice
	init._ran = true;

	initModelSelector();
	renderProjects();
	renderHistory();
	// Initially hide the global files panel
	hideFilesPanel();

	// --- Make sure UI handlers that might not be registered elsewhere are attached ---
	// Ensure send button calls sendMessage (in case inline handlers missed)
	if (sendBtn) sendBtn.onclick = sendMessage;

	// Sidebar hover/toggle is now handled by main.js module

	// Check backend availability (shows banner if only a static file server is running)
	checkBackend(false);

	// Load saved theme mode
	loadThemeMode();

	// Load saved backend preference (Local llama.cpp vs Cloud OpenAI)
	loadBackendPreference();

	// Initialize file upload handling
	initFileUpload();

	console.log('[Parakleon] Initialized successfully');
}

// Ensure init runs on load
window.addEventListener('DOMContentLoaded', init);
