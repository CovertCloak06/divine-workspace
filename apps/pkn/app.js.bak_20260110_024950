// Parakleon Main Chat Application

// --- Utility Functions ---
// Toast notification system for user feedback
function showToast(message, duration = 3000, type = 'info') {
    const container = document.getElementById('toastContainer') || document.body;
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    toast.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        background: ${type === 'error' ? '#ef4444' : type === 'success' ? '#10b981' : '#3b82f6'};
        color: white;
        padding: 12px 20px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        z-index: 10000;
        animation: slideIn 0.3s ease-out;
        max-width: 350px;
        word-wrap: break-word;
    `;
    container.appendChild(toast);

    // Auto-remove after duration
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

// Add CSS animations for toast if not already present
if (!document.getElementById('toast-animations')) {
    const style = document.createElement('style');
    style.id = 'toast-animations';
    style.textContent = `
        @keyframes slideIn {
            from { transform: translateX(400px); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOut {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(400px); opacity: 0; }
        }
    `;
    document.head.appendChild(style);
}

// --- Error Message Handling System ---
// Maps technical errors to user-friendly messages with actionable recovery steps
const ERROR_MESSAGES = {
    // Network & Connection Errors
    'ECONNREFUSED': {
        title: '🔌 Service Not Running',
        message: 'The AI service isn\'t responding.',
        actions: [
            'Start services: Open Settings → CLI Access → Copy Commands',
            'Or run: ./pkn_control.sh start-all',
            'Check status: ./pkn_control.sh status'
        ],
        severity: 'error',
        docs: '#service-not-running'
    },
    'Failed to fetch': {
        title: '🌐 Connection Failed',
        message: 'Cannot reach the server.',
        actions: [
            'Check if server is running: curl http://localhost:8010/health',
            'Restart services: ./pkn_control.sh restart-divinenode',
            'Check browser console (F12) for details'
        ],
        severity: 'error',
        docs: '#connection-failed'
    },
    'NetworkError': {
        title: '🌐 Network Error',
        message: 'Network request failed.',
        actions: [
            'Check your internet connection',
            'Verify server is running on port 8010',
            'Try refreshing the page'
        ],
        severity: 'error'
    },

    // Port & Service Errors
    'port 8010': {
        title: '⚠️ Port Conflict',
        message: 'Port 8010 is already in use by another application.',
        actions: [
            'Stop conflicting service: lsof -i :8010',
            'Or change Divine Node port in divinenode_server.py',
            'Then restart: ./pkn_control.sh restart-divinenode'
        ],
        severity: 'warning',
        docs: '#port-conflict'
    },
    'port 8000': {
        title: '⚠️ LLM Port Conflict',
        message: 'Port 8000 (llama.cpp) is already in use.',
        actions: [
            'Stop conflicting service: lsof -i :8000',
            'Or restart llama.cpp: ./pkn_control.sh restart-llama'
        ],
        severity: 'warning'
    },

    // Image Generation Errors
    'IndexError': {
        title: '🎨 Image Generation Failed',
        message: 'The image generator encountered a configuration error.',
        actions: [
            'Restart services: ./pkn_control.sh restart-divinenode',
            'Check logs: tail -20 divinenode.log',
            'Try a simpler prompt'
        ],
        severity: 'error',
        docs: '#image-generation'
    },
    'timed out': {
        title: '⏱️ Generation Timeout',
        message: 'The operation took too long to complete.',
        actions: [
            'CPU mode takes ~3 minutes - this is normal',
            'If using GPU and still timing out, check GPU availability',
            'Try reducing image complexity or step count'
        ],
        severity: 'warning'
    },

    // Model & AI Errors
    'Model not found': {
        title: '🤖 Model Not Available',
        message: 'The requested AI model isn\'t loaded.',
        actions: [
            'Check available models: curl http://localhost:8000/v1/models',
            'Verify model path in pkn_control.sh',
            'Download model if missing'
        ],
        severity: 'error',
        docs: '#model-not-found'
    },
    'CUDA': {
        title: 'ℹ️ GPU Not Available',
        message: 'CUDA not available - using CPU mode.',
        actions: [
            'This is expected on systems without NVIDIA GPU',
            'CPU mode works fine, just slower (~3-5x)',
            'No action needed unless you expected GPU acceleration'
        ],
        severity: 'info'
    },

    // File & Storage Errors
    'QuotaExceededError': {
        title: '💾 Storage Full',
        message: 'Browser storage limit exceeded.',
        actions: [
            'Clear old chats: Settings → Delete Chats',
            'Clear images: Settings → Clear Images',
            'Export important chats first: Settings → Export Chats'
        ],
        severity: 'warning',
        docs: '#storage-full'
    },
    'File too large': {
        title: '📁 File Too Large',
        message: 'The uploaded file exceeds size limits.',
        actions: [
            'Maximum file size: 10MB',
            'Try compressing the file',
            'Or split into smaller chunks'
        ],
        severity: 'warning'
    },

    // HTTP Status Errors
    '404': {
        title: '🔍 Not Found',
        message: 'The requested resource doesn\'t exist.',
        actions: [
            'Check the URL or endpoint',
            'Verify server is running latest version',
            'Try restarting services'
        ],
        severity: 'error'
    },
    '500': {
        title: '🔥 Server Error',
        message: 'Internal server error occurred.',
        actions: [
            'Check server logs: tail -20 divinenode.log',
            'Restart services: ./pkn_control.sh restart-all',
            'Report issue if error persists'
        ],
        severity: 'error',
        docs: '#server-errors'
    },
    '503': {
        title: '⚠️ Service Unavailable',
        message: 'Server is temporarily unavailable.',
        actions: [
            'Server might be starting up (wait 10-15 seconds)',
            'Check status: ./pkn_control.sh status',
            'Restart if needed: ./pkn_control.sh restart-all'
        ],
        severity: 'warning'
    }
};

/**
 * Format error into user-friendly message with recovery actions
 * @param {Error|string} error - Error object or message
 * @param {string} context - Optional context (e.g., "image_generation", "chat")
 * @returns {Object} Formatted error with title, message, actions, severity
 */
function formatError(error, context = '') {
    const errorMsg = typeof error === 'string' ? error : (error.message || String(error));

    // Try to match error patterns
    for (const [pattern, errorInfo] of Object.entries(ERROR_MESSAGES)) {
        if (errorMsg.includes(pattern) || errorMsg.toLowerCase().includes(pattern.toLowerCase())) {
            return {
                title: errorInfo.title,
                message: errorInfo.message,
                actions: errorInfo.actions || [],
                severity: errorInfo.severity || 'error',
                docs: errorInfo.docs || null,
                originalError: errorMsg
            };
        }
    }

    // Fallback for unknown errors
    return {
        title: '❌ Error',
        message: errorMsg,
        actions: [
            'Check browser console (F12) for details',
            'View server logs: tail -20 divinenode.log',
            'Try restarting services if issue persists'
        ],
        severity: 'error',
        originalError: errorMsg
    };
}

/**
 * Display formatted error to user with recovery options
 * @param {Error|string} error - Error object or message
 * @param {string} context - Optional context
 * @param {HTMLElement} targetElement - Optional element to show error in
 */
function showFormattedError(error, context = '', targetElement = null) {
    const formatted = formatError(error, context);

    // Create error card HTML
    const errorHTML = `
        <div class="error-card" style="
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid ${formatted.severity === 'error' ? '#ef4444' : formatted.severity === 'warning' ? '#f59e0b' : '#3b82f6'};
            border-radius: 8px;
            padding: 16px;
            margin: 12px 0;
            font-size: 13px;
        ">
            <div class="error-title" style="
                color: ${formatted.severity === 'error' ? '#ef4444' : formatted.severity === 'warning' ? '#f59e0b' : '#3b82f6'};
                font-weight: 700;
                font-size: 14px;
                margin-bottom: 8px;
            ">${formatted.title}</div>

            <div class="error-message" style="color: #ccc; margin-bottom: 12px;">
                ${formatted.message}
            </div>

            ${formatted.actions.length > 0 ? `
                <div class="error-actions" style="margin-top: 12px;">
                    <div style="color: #999; font-size: 12px; margin-bottom: 6px; font-weight: 600;">💡 Try these fixes:</div>
                    <ul style="margin: 0; padding-left: 20px; color: #aaa; font-size: 12px; line-height: 1.6;">
                        ${formatted.actions.map(action => `<li>${action}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}

            ${formatted.docs ? `
                <div style="margin-top: 12px; padding-top: 12px; border-top: 1px solid rgba(255,255,255,0.1);">
                    <a href="/docs${formatted.docs}" style="color: var(--theme-primary); font-size: 12px; text-decoration: none;">
                        📖 Learn more →
                    </a>
                </div>
            ` : ''}

            <details style="margin-top: 12px; font-size: 11px;">
                <summary style="cursor: pointer; color: #666;">Technical details</summary>
                <pre style="margin-top: 6px; padding: 8px; background: #000; border-radius: 4px; overflow-x: auto; color: #999;">${formatted.originalError}</pre>
            </details>
        </div>
    `;

    if (targetElement) {
        targetElement.innerHTML = errorHTML;
        targetElement.style.display = 'block';
    } else {
        // Add to chat as system message
        const container = document.getElementById('messagesContainer');
        if (container) {
            const errorDiv = document.createElement('div');
            errorDiv.className = 'message system-message';
            errorDiv.innerHTML = errorHTML;
            container.appendChild(errorDiv);
            container.scrollTop = container.scrollHeight;
        }
    }

    // Also show toast for immediate feedback
    showToast(formatted.title, 4000, formatted.severity);
}

// --- Send Message Handler ---
// Global abort controller for stopping AI responses
let currentAbortController = null;
let userInitiatedStop = false;

// Send example prompt from welcome screen
function sendExample(exampleText) {
    const messageInput = document.getElementById('messageInput');
    if (messageInput) {
        messageInput.value = exampleText;
        hideWelcomeScreen(); // Hide welcome screen before sending
        sendMessage();
    }
}

// Export to window for onclick handlers
window.sendExample = sendExample;

// Hide welcome screen when messages exist
function hideWelcomeScreen() {
    const welcomeScreen = document.getElementById('welcomeScreen');
    if (welcomeScreen) {
        welcomeScreen.style.display = 'none';
        console.log('Welcome screen hidden');
    }
}

// Show welcome screen (can be called to recall it)
function showWelcomeScreen() {
    console.log('showWelcomeScreen called');
    const messagesContainer = document.getElementById('messagesContainer');
    const welcomeScreen = document.getElementById('welcomeScreen');

    console.log('messagesContainer:', messagesContainer);
    console.log('welcomeScreen:', welcomeScreen);

    if (!messagesContainer) {
        console.error('No messages container found');
        return;
    }

    const hasMessages = messagesContainer.querySelectorAll('.message').length > 0;
    console.log('hasMessages:', hasMessages);

    if (!hasMessages && welcomeScreen) {
        // Show welcome screen only if no messages
        welcomeScreen.style.display = 'flex';
        console.log('Welcome screen shown');
    } else if (hasMessages) {
        // Can't show welcome screen with messages - clear chat first
        console.log('Has messages, asking to clear');
        if (confirm('Clear current chat to show welcome screen?')) {
            console.log('User confirmed, clearing messages');
            messagesContainer.innerHTML = '';
            if (welcomeScreen) {
                welcomeScreen.style.display = 'flex';
            } else {
                location.reload();
            }
        }
    } else if (!welcomeScreen) {
        // Welcome screen was removed - reload page
        console.log('Welcome screen missing, reloading');
        location.reload();
    }
}

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
        sendBtn.textContent = 'STOP';
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
    const timeoutId = setTimeout(() => currentAbortController.abort(), 120000);

    // Always use multi-agent endpoint
    fetch('/api/multi-agent/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            message: input,
            mode: agentType,
            history: messages
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
        if (err.name === 'AbortError' && userInitiatedStop) {
            // User clicked stop - just show simple toast, no error card
            showToast('Request stopped by user', 2000, 'info');
        } else {
            // Show formatted error with recovery suggestions
            showFormattedError(err, 'chat');
        }
    })
    .finally(() => {
        // Clear abort controller and reset flag
        currentAbortController = null;
        userInitiatedStop = false;

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

        // Message action buttons (edit, delete, copy)
        const actionsHtml = `
            <div class="message-actions">
                <button class="message-action-btn" onclick="copyMessageText(this)" title="Copy message">
                    <span>📋</span>
                </button>
                <button class="message-action-btn" onclick="editMessage(this)" title="Edit message">
                    <span>✏️</span>
                </button>
                <button class="message-action-btn" onclick="deleteMessage(this)" title="Delete message">
                    <span>🗑️</span>
                </button>
            </div>`;

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

// Simple helper to toggle sidebar sections by id (used by inline onclick handlers in HTML)
function toggleSection(sectionId) {
    const section = document.getElementById(sectionId);
    if (!section) return;
    section.classList.toggle('collapsed');
    const chevronId = sectionId.replace(/Section$/, 'Chevron');
    const chevron = document.getElementById(chevronId);
    if (chevron) chevron.textContent = section.classList.contains('collapsed') ? '►' : '▼';
}

// Network action menu helper (invoked by Network button)
function networkAction(e) {
    try {
        e.stopPropagation();
        closeHistoryMenu();
        const menu = document.createElement('div');
        menu.className = 'history-menu';

        const items = [
            { label: 'Port Scan', action: () => window.ParakleonTools.portScan && window.ParakleonTools.portScan() },
            { label: 'Ping', action: () => window.ParakleonTools.ping && window.ParakleonTools.ping() },
            { label: 'DNS Lookup', action: () => window.ParakleonTools.dnsLookup && window.ParakleonTools.dnsLookup() },
            { label: 'IP Info', action: () => window.ParakleonTools.ipInfo && window.ParakleonTools.ipInfo() },
        ];

        items.forEach(itm => {
            const it = document.createElement('div');
            it.className = 'history-menu-item';
            it.textContent = itm.label;
            it.onclick = () => { itm.action(); closeHistoryMenu(); };
            menu.appendChild(it);
        });

        const rect = e && e.currentTarget && e.currentTarget.getBoundingClientRect ? e.currentTarget.getBoundingClientRect() : { top: 0, left: 0, bottom: 0 };
        const containerRect = document.body.getBoundingClientRect();
        const top = rect.bottom - containerRect.top + window.scrollY;
        const left = rect.left - containerRect.left + window.scrollX;
        menu.style.top = top + 'px';
        menu.style.left = left + 'px';

        document.body.appendChild(menu);
        openMenuElement = menu;
    } catch (err) {
        console.error('networkAction error', err);
    }
}

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

// 2) fetch models from Flask/Ollama
async function refreshOllamaModels() {
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
        renderModelsList && renderModelsList();
  } catch (e) {
    console.error('Failed to refresh Ollama models', e);
  }
}

// 3) helper to return all models (temporary local helper - a canonical merged version appears later)
function getAllModels() {
    return window.dynamicOllamaModels || [];
}

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
    if (sendBtn) sendBtn.onclick = sendMessage;
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
    refreshOllamaModels();
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

// Patch getAllModels to merge all dynamic models
function getAllModels() {
    return [
        ...(window.dynamicOllamaModels || []),
        ...(window.dynamicLlamaCppModels || []),
        ...loadModelsFromStorage().filter(m => m.enabled !== false)
    ];
}

let isWaiting = false;
let abortController = null;
let currentChatId = null;
let currentProjectId = null;
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


let ACTIVE_BASE_URL = 'https://api.openai.com/v1/chat/completions';
// Set Qwen2.5 as default if available, else fallback to OpenAI
let ACTIVE_MODEL = window.PARAKLEON_CONFIG.DEFAULT_QWEN_MODEL ? `llamacpp:${window.PARAKLEON_CONFIG.DEFAULT_QWEN_MODEL}` : window.PARAKLEON_CONFIG.OPENAI_MODEL;
let ACTIVE_API_KEY = window.PARAKLEON_CONFIG.OPENAI_API_KEY;
let ACTIVE_PROVIDER = 'openai'; // openai, groq, together, huggingface, ollama, webllm
let ACTIVE_TEMPERATURE = 0.7;
let ACTIVE_MAX_TOKENS = 2048;
let ACTIVE_TOP_P = 0.9;
let ACTIVE_FREQUENCY_PENALTY = 0.0;
let ACTIVE_PRESENCE_PENALTY = 0.0;

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

function renderModelsList() {
    const listEl = document.getElementById('aiModelsList');
    if (!listEl) return;
    listEl.innerHTML = '';

    // Combine stored models and dynamically discovered models (detected)
    const stored = loadModelsFromStorage() || [];
    let dynamic = [];
    try { dynamic = (typeof getAllModels === 'function') ? getAllModels() : []; } catch(e) { dynamic = []; }

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
        dynamicModels = (typeof getAllModels === 'function') ? getAllModels() : [];
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

console.log('Initial ACTIVE_MODEL:', ACTIVE_MODEL);

function onModelChange() {
    const { value } = modelSelect;
    if (value === 'openai') {
        ACTIVE_PROVIDER = 'openai';
        ACTIVE_BASE_URL = 'https://api.openai.com/v1/chat/completions';
        ACTIVE_MODEL = window.PARAKLEON_CONFIG.OPENAI_MODEL;
        ACTIVE_API_KEY = getApiKeyForProvider('openai');
    } else if (value.startsWith('groq:')) {
        ACTIVE_PROVIDER = 'groq';
        const modelName = value.replace('groq:', '');
        ACTIVE_BASE_URL = 'https://api.groq.com/openai/v1/chat/completions';
        ACTIVE_MODEL = modelName;
        ACTIVE_API_KEY = getApiKeyForProvider('groq');
    } else if (value.startsWith('together:')) {
        ACTIVE_PROVIDER = 'together';
        const modelName = value.replace('together:', '');
        ACTIVE_BASE_URL = 'https://api.together.xyz/v1/chat/completions';
        ACTIVE_MODEL = modelName;
        ACTIVE_API_KEY = getApiKeyForProvider('together');
    } else if (value.startsWith('huggingface:')) {
        ACTIVE_PROVIDER = 'huggingface';
        const modelName = value.replace('huggingface:', '');
        ACTIVE_BASE_URL = 'https://api-inference.huggingface.co/models/' + modelName + '/v1/chat/completions';
        ACTIVE_MODEL = modelName;
        ACTIVE_API_KEY = getApiKeyForProvider('huggingface');
    } else if (value.startsWith('ollama:')) {
        ACTIVE_PROVIDER = 'ollama';
        const modelName = value.replace('ollama:', '');
        ACTIVE_BASE_URL = window.PARAKLEON_CONFIG.OLLAMA_BASE_URL + '/chat/completions';
        ACTIVE_MODEL = modelName;
        ACTIVE_API_KEY = 'ollama';
    } else if (value.startsWith('llamacpp:')) {
        ACTIVE_PROVIDER = 'llamacpp';
        ACTIVE_BASE_URL = window.PARAKLEON_CONFIG.LLAMACPP_BASE_URL + '/chat/completions';
        ACTIVE_MODEL = 'local';
        ACTIVE_API_KEY = 'llamacpp';
    }
}

function toggleSettings() {
    const visible = !settingsOverlay.classList.contains('hidden');
    if (!visible) {
        let chat = null;
        if (currentProjectId) {
            const projects = loadProjectsFromStorage();
            const project = projects.find(p => p.id === currentProjectId);
            chat = project && project.chats ? project.chats.find(c => c.id === currentChatId) : null;
        } else {
            const chats = loadChatsFromStorage();
            chat = getCurrentChat(chats);
        }
        fullHistoryToggle.checked = chat ? !!chat.useFullHistory : true;
        updateSettingsUI();
        // Update storage usage display
        const storageEl = document.getElementById('storageUsage');
        if (storageEl) storageEl.textContent = getStorageUsage() + ' MB';
    }
    settingsOverlay.classList.toggle('hidden');
}

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
    if (currentProjectId) {
        const projects = loadProjectsFromStorage();
        const project = projects.find(p => p.id === currentProjectId);
        const chat = project && project.chats ? project.chats.find(c => c.id === currentChatId) : null;
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
        localStorage.removeItem('currentChatId');
        currentChatId = null;
        messagesContainer.innerHTML = '';
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
        if (currentProjectId) {
            currentProjectId = null;
            currentChatId = null;
            messagesContainer.innerHTML = '';
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

function loadChatsFromStorage() {
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (!raw) return [];
        return JSON.parse(raw);
    } catch (e) {
        console.error('Failed to load history', e);
        return [];
    }
}

function saveChatsToStorage(chats) {
    try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(chats));
    } catch (e) {
        console.error('Failed to save history', e);
    }
}

function sortChats(chats) {
    return chats.sort((a, b) => {
        const aTime = a.updatedAt || 0;
        const bTime = b.updatedAt || 0;
        return bTime - aTime;
    });
}

function renderHistory() {
    historyList.innerHTML = '';
    favoritesList.innerHTML = '';
    archiveList.innerHTML = '';

    let chats = loadChatsFromStorage();
    chats = sortChats(chats);

    // Add "+ New chat" button at the top of chats list
    const newChatBtn = document.createElement('div');
    newChatBtn.className = 'history-item new-chat-btn';
    newChatBtn.innerHTML = '<span class="history-title">+ New chat</span>';
    newChatBtn.onclick = () => {
        newChat();
    };
    historyList.appendChild(newChatBtn);

    chats.forEach(chat => {
        const item = document.createElement('div');
        item.className = 'history-item' + (chat.id === currentChatId ? ' active' : '');
        item.dataset.chatId = chat.id;

        const title = document.createElement('span');
        title.className = 'history-title';
        title.textContent = chat.title || 'Untitled chat';
        title.onclick = (e) => {
            e.stopPropagation();
            loadChat(chat.id);
        };
        item.appendChild(title);

        const menuBtn = document.createElement('button');
        menuBtn.className = 'history-menu-btn';
        menuBtn.textContent = '⋮';
        menuBtn.onclick = (e) => {
            e.stopPropagation();
            openHistoryMenu(chat.id, menuBtn, !!chat.starred, !!chat.archived);
        };
        item.appendChild(menuBtn);

        if (chat.archived) {
            archiveList.appendChild(item);
        } else if (chat.starred) {
            favoritesList.appendChild(item);
        } else {
            historyList.appendChild(item);
        }
    });

    // Add empty state messages
    if (favoritesList.children.length === 0) {
        const emptyState = document.createElement('div');
        emptyState.className = 'empty-state';
        emptyState.innerHTML = `
            <div class="empty-state-icon">⭐</div>
            <div class="empty-state-text">No favorites yet</div>
            <div class="empty-state-hint">Star chats to see them here</div>
        `;
        favoritesList.appendChild(emptyState);
    }

    if (archiveList.children.length === 0) {
        const emptyState = document.createElement('div');
        emptyState.className = 'empty-state';
        emptyState.innerHTML = `
            <div class="empty-state-icon">📦</div>
            <div class="empty-state-text">No archived chats</div>
            <div class="empty-state-hint">Archive old chats to keep them organized</div>
        `;
        archiveList.appendChild(emptyState);
    }

    if (historyList.children.length === 1) { // Only "+ New chat" button
        const emptyState = document.createElement('div');
        emptyState.className = 'empty-state';
        emptyState.innerHTML = `
            <div class="empty-state-icon">💬</div>
            <div class="empty-state-text">No chats yet</div>
            <div class="empty-state-hint">Start a new conversation</div>
        `;
        historyList.appendChild(emptyState);
    }
}

    let openMenuElement = null;

function closeHistoryMenu() {
    if (openMenuElement && openMenuElement.parentNode) {
        openMenuElement.parentNode.removeChild(openMenuElement);
    }
    openMenuElement = null;
}

function openHistoryMenu(chatId, anchorButton, isStarred, isArchived) {
    closeHistoryMenu();

    const rect = anchorButton.getBoundingClientRect();
    const containerRect = document.body.getBoundingClientRect();

    const menu = document.createElement('div');
    menu.className = 'history-menu';

    const favItem = document.createElement('div');
    favItem.className = 'history-menu-item';
    favItem.textContent = isStarred ? 'Unfavorite' : 'Add to favorites';
    favItem.onclick = () => {
        toggleFavoriteChat(chatId);
        closeHistoryMenu();
    };
    menu.appendChild(favItem);

    const archItem = document.createElement('div');
    archItem.className = 'history-menu-item';
    archItem.textContent = isArchived ? 'Unarchive' : 'Archive chat';
    archItem.onclick = () => {
        toggleArchiveChat(chatId);
        closeHistoryMenu();
    };
    menu.appendChild(archItem);

    const renameItem = document.createElement('div');
    renameItem.className = 'history-menu-item';
    renameItem.textContent = 'Rename chat';
    renameItem.onclick = () => {
        renameChatPrompt(chatId);
        closeHistoryMenu();
    };
    menu.appendChild(renameItem);

    const moveItem = document.createElement('div');
    moveItem.className = 'history-menu-item';
    moveItem.textContent = 'Move to Project';
    moveItem.onclick = () => {
        showMoveToProjectModal(chatId);
        closeHistoryMenu();
    };
    menu.appendChild(moveItem);

    const deleteItem = document.createElement('div');
    deleteItem.className = 'history-menu-item';
    deleteItem.textContent = 'Delete chat';
    deleteItem.onclick = () => {
        deleteChat(chatId);
        closeHistoryMenu();
    };
    menu.appendChild(deleteItem);

    const top = rect.bottom - containerRect.top + window.scrollY;
    const left = rect.left - containerRect.left + window.scrollX;
    menu.style.top = top + 'px';
    menu.style.left = left + 'px';

    document.body.appendChild(menu);
    openMenuElement = menu;
}

document.addEventListener('click', (e) => {
    if (openMenuElement && !openMenuElement.contains(e.target) && !e.target.classList.contains('history-menu-btn')) {
        closeHistoryMenu();
    }
});

function toggleFavoriteChat(id) {
    // Global
    let chats = loadChatsFromStorage();
    let chat = chats.find(c => c.id === id);
    if (chat) {
        chat.starred = !chat.starred;
        chat.updatedAt = Date.now();
        saveChatsToStorage(chats);
        renderHistory();
        return;
    }

    // Projects
    let projects = loadProjectsFromStorage();
    for (const project of projects) {
        if (project.chats && project.chats.find(c => c.id === id)) {
            const projChat = project.chats.find(c => c.id === id);
            projChat.starred = !projChat.starred;
            projChat.updatedAt = Date.now();
            saveProjectsToStorage(projects);
            renderProjects();
            return;
        }
    }
}

function toggleArchiveChat(id) {
    // Global
    let chats = loadChatsFromStorage();
    let chat = chats.find(c => c.id === id);
    if (chat) {
        chat.archived = !chat.archived;
        chat.updatedAt = Date.now();
        saveChatsToStorage(chats);
        renderHistory();
        return;
    }

    // Projects
    let projects = loadProjectsFromStorage();
    for (const project of projects) {
        if (project.chats && project.chats.find(c => c.id === id)) {
            const projChat = project.chats.find(c => c.id === id);
            projChat.archived = !projChat.archived;
            projChat.updatedAt = Date.now();
            saveProjectsToStorage(projects);
            renderProjects();
            return;
        }
    }
}

function getCurrentChat(chats) {
    return chats.find(c => c.id === currentChatId);
}

function ensureCurrentChat() {
    if (currentProjectId) {
        // Project mode: use project chats
        const projects = loadProjectsFromStorage();
        const project = projects.find(p => p.id === currentProjectId);
        
        if (project) {
            if (!project.chats) project.chats = [];
            
            // If we have a current chat ID and it exists in project, we're good
            if (currentChatId && project.chats.find(c => c.id === currentChatId)) {
                return;
            }
            
            // Don't auto-create chat - let user explicitly create one
            currentChatId = null;
        }
    } else {
        // Global mode: use global chats
        let chats = loadChatsFromStorage();
        
        // If we have a current chat ID and it exists, we're good
        if (currentChatId && getCurrentChat(chats)) {
            return;
        }
        
        // Don't auto-create chat - let user explicitly create one
        currentChatId = null;
    }
}

function appendMessageToCurrentChat(sender, text, attachments = [], messageId = null, model = null) {
    ensureCurrentChat();
    
    let chat = null;
    if (currentProjectId) {
        // Get chat from project
        const projects = loadProjectsFromStorage();
        const project = projects.find(p => p.id === currentProjectId);
        if (project && project.chats) {
            chat = project.chats.find(c => c.id === currentChatId);
        }
        
        if (chat) {
            const now = Date.now();
            if (editingMessageId && sender === 'user' && messageId) {
                const idx = chat.messages.findIndex(m => m.id === messageId);
                if (idx !== -1) {
                    chat.messages[idx].text = text;
                    chat.messages[idx].attachments = attachments;
                    // Remove all messages after this edited message
                    chat.messages = chat.messages.slice(0, idx + 1);
                }
                editingMessageId = null;
                saveProjectsToStorage(projects);
                // Reload chat to show changes
                setTimeout(() => reloadCurrentChat(), 100);
                return;
            } else {
                const id = 'msg_' + now + '_' + Math.floor(Math.random() * 10000);
                const message = {id, sender, text, attachments, timestamp: now};
                if (model) message.model = model;
                chat.messages.push(message);
            }
            if (chat.title === 'Project Chat' && sender === 'user') {
                chat.title = text.slice(0, 30);
            }
            if (chat.useFullHistory === undefined) chat.useFullHistory = true;
            chat.updatedAt = now;
            saveProjectsToStorage(projects);
        }
    } else {
        // Get chat from global storage
        let chats = loadChatsFromStorage();
        chat = getCurrentChat(chats);
        
        if (chat) {
            const now = Date.now();
            if (editingMessageId && sender === 'user' && messageId) {
                const idx = chat.messages.findIndex(m => m.id === messageId);
                if (idx !== -1) {
                    chat.messages[idx].text = text;
                    chat.messages[idx].attachments = attachments;
                    // Remove all messages after this edited message
                    chat.messages = chat.messages.slice(0, idx + 1);
                }
                editingMessageId = null;
                saveChatsToStorage(chats);
                renderHistory();
                // Reload chat to show changes
                setTimeout(() => reloadCurrentChat(), 100);
                return;
            } else {
                const id = 'msg_' + now + '_' + Math.floor(Math.random() * 10000);
                const message = {id, sender, text, attachments, timestamp: now};
                if (model) message.model = model;
                chat.messages.push(message);
            }
            if (chat.title === 'New chat' && sender === 'user') {
                chat.title = text.slice(0, 30);
            }
            if (chat.useFullHistory === undefined) chat.useFullHistory = true;
            chat.updatedAt = now;
            saveChatsToStorage(chats);
            renderHistory();
        }
    }
}

function loadChat(id) {
    // Try global chats first
    let chats = loadChatsFromStorage();
    let chat = chats.find(c => c.id === id);
    if (chat) {
        currentProjectId = null;
        currentChatId = id;
        messagesContainer.innerHTML = '';
        chat.messages.forEach(m => addMessage(m.text, m.sender, false, m.attachments, m.id, m.model, m.timestamp));
        fullHistoryToggle.checked = chat.useFullHistory !== false;
        renderProjects();
        renderHistory();
        // Show welcome screen if chat is empty
        setTimeout(() => showWelcomeScreen(), 50);
        return;
    }

    // Search project chats
    const projects = loadProjectsFromStorage();
    for (const project of projects) {
        const projChat = (project.chats || []).find(c => c.id === id);
        if (projChat) {
            currentProjectId = project.id;
            currentChatId = id;
            messagesContainer.innerHTML = '';
            projChat.messages.forEach(m => addMessage(m.text, m.sender, false, m.attachments || [], m.id, m.model, m.timestamp));
            fullHistoryToggle.checked = projChat.useFullHistory !== false;
            renderProjects();
            renderHistory();
            // Show welcome screen if chat is empty
            setTimeout(() => showWelcomeScreen(), 50);
            return;
        }
    }

    console.warn('Chat not found:', id);
}

function reloadCurrentChat() {
    if (!currentChatId) return;

    messagesContainer.innerHTML = '';

    if (currentProjectId) {
        // Reload project chat
        const projects = loadProjectsFromStorage();
        const project = projects.find(p => p.id === currentProjectId);
        if (project && project.chats) {
            const chat = project.chats.find(c => c.id === currentChatId);
            if (chat && chat.messages) {
                chat.messages.forEach(m => addMessage(m.text, m.sender, false, m.attachments || [], m.id, m.model, m.timestamp));
            }
        }
    } else {
        // Reload global chat
        const chats = loadChatsFromStorage();
        const chat = chats.find(c => c.id === currentChatId);
        if (chat && chat.messages) {
            chat.messages.forEach(m => addMessage(m.text, m.sender, false, m.attachments, m.id, m.model, m.timestamp));
        }
    }

    // Show welcome screen if chat is empty
    setTimeout(() => showWelcomeScreen(), 50);
}

function deleteChat(id) {
    // Try global chats first
    let chats = loadChatsFromStorage();
    if (chats.find(c => c.id === id)) {
        chats = chats.filter(c => c.id !== id);
        saveChatsToStorage(chats);
        if (currentChatId === id) {
            currentChatId = null;
            messagesContainer.innerHTML = '';
        }
        renderHistory();
        return;
    }

    // Otherwise, search projects
    let projects = loadProjectsFromStorage();
    for (const project of projects) {
        if (project.chats && project.chats.find(c => c.id === id)) {
            project.chats = project.chats.filter(c => c.id !== id);
            saveProjectsToStorage(projects);
            if (currentChatId === id) {
                currentChatId = null;
                messagesContainer.innerHTML = '';
            }
            renderProjects();
            return;
        }
    }
}

function renameChatPrompt(chatId) {
    // Try global first
    let chats = loadChatsFromStorage();
    let chat = chats.find(c => c.id === chatId);

    // If not found, search project chats
    if (!chat) {
        const projects = loadProjectsFromStorage();
        for (const project of projects) {
            if (project.chats && project.chats.find(c => c.id === chatId)) {
                chat = project.chats.find(c => c.id === chatId);
                break;
            }
        }
    }

    if (!chat) return;
    
    const newTitle = prompt('Enter new chat name:', chat.title);
    if (newTitle !== null && newTitle.trim() !== '') {
        renameChat(chatId, newTitle.trim());
    }
}

function renameChat(chatId, newTitle) {
    // Try rename in global chats first
    let chats = loadChatsFromStorage();
    let chat = chats.find(c => c.id === chatId);
    if (chat) {
        chat.title = newTitle;
        chat.updatedAt = Date.now();
        saveChatsToStorage(chats);
        renderHistory();
        return;
    }

    // Otherwise search projects
    const projects = loadProjectsFromStorage();
    for (const project of projects) {
        if (project.chats && project.chats.find(c => c.id === chatId)) {
            const projChat = project.chats.find(c => c.id === chatId);
            projChat.title = newTitle;
            projChat.updatedAt = Date.now();
            saveProjectsToStorage(projects);
            renderProjects();
            return;
        }
    }
}

function newChat() {
    const id = 'chat_' + Date.now();

    // If in project mode, create a project-local chat
    if (currentProjectId) {
        const projects = loadProjectsFromStorage();
        const project = projects.find(p => p.id === currentProjectId);
        if (project) {
            project.chats = project.chats || [];
            project.chats.unshift({
                id,
                title: 'Project Chat',
                messages: [],
                starred: false,
                archived: false,
                useFullHistory: true,
                updatedAt: Date.now()
            });
            saveProjectsToStorage(projects);
            currentChatId = id;
            messagesContainer.innerHTML = '';
            renderProjects();
            renderHistory();
            // Show welcome screen for new empty chat
            setTimeout(() => showWelcomeScreen(), 50);
            return;
        }
    }

    // Global chat fallback
    const chats = loadChatsFromStorage();
    chats.unshift({
        id,
        title: 'New chat',
        messages: [],
        starred: false,
        archived: false,
        useFullHistory: true,
        updatedAt: Date.now()
    });
    saveChatsToStorage(chats);
    currentChatId = id;
    currentProjectId = null;
    messagesContainer.innerHTML = '';
    renderProjects();
    renderHistory();
    // Show welcome screen for new empty chat
    setTimeout(() => showWelcomeScreen(), 50);
}

// Export to window for onclick handlers
window.newChat = newChat;

function backupChat() {
    const chats = loadChatsFromStorage();
    const blob = new Blob([JSON.stringify(chats, null, 2)], {type: 'application/json'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'parakleon_chat_backup.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    alert('Backup downloaded.');
}

function importBackup() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        
        try {
            const text = await file.text();
            const imported = JSON.parse(text);
            
            if (!Array.isArray(imported)) {
                alert('Invalid backup file format.');
                return;
            }
            
            // Validate structure
            const isValid = imported.every(chat => 
                chat.id && chat.title && Array.isArray(chat.messages)
            );
            
            if (!isValid) {
                alert('Invalid chat backup structure.');
                return;
            }
            
            const existingChats = loadChatsFromStorage();
            const existingIds = new Set(existingChats.map(c => c.id));
            
            let importedCount = 0;
            let skippedCount = 0;
            
            imported.forEach(chat => {
                if (existingIds.has(chat.id)) {
                    skippedCount++;
                } else {
                    existingChats.push(chat);
                    importedCount++;
                }
            });
            
            saveChatsToStorage(existingChats);
            renderHistory();
            
            alert(`Imported ${importedCount} chats. Skipped ${skippedCount} duplicates.`);
        } catch (err) {
            console.error('Import failed:', err);
            alert('Failed to import backup: ' + err.message);
        }
    };
    input.click();
}

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
    ACTIVE_TEMPERATURE = settings.temperature;
    ACTIVE_MAX_TOKENS = settings.maxTokens;
    ACTIVE_TOP_P = settings.topP || 0.9;
    ACTIVE_FREQUENCY_PENALTY = settings.frequencyPenalty || 0.0;
    ACTIVE_PRESENCE_PENALTY = settings.presencePenalty || 0.0;
}

function saveTemperature(value) {
    const settings = loadSettings();
    settings.temperature = parseFloat(value);
    saveSettings(settings);
    ACTIVE_TEMPERATURE = settings.temperature;
    document.getElementById('temperatureValue').textContent = value;
}

function saveMaxTokens(value) {
    const settings = loadSettings();
    settings.maxTokens = parseInt(value);
    saveSettings(settings);
    ACTIVE_MAX_TOKENS = settings.maxTokens;
    document.getElementById('maxTokensValue').textContent = value;
}

function saveTopP(value) {
    const settings = loadSettings();
    settings.topP = parseFloat(value);
    saveSettings(settings);
    ACTIVE_TOP_P = settings.topP;
    document.getElementById('topPValue').textContent = value;
}

function saveFrequencyPenalty(value) {
    const settings = loadSettings();
    settings.frequencyPenalty = parseFloat(value);
    saveSettings(settings);
    ACTIVE_FREQUENCY_PENALTY = settings.frequencyPenalty;
    document.getElementById('frequencyPenaltyValue').textContent = value;
}

function savePresencePenalty(value) {
    const settings = loadSettings();
    settings.presencePenalty = parseFloat(value);
    saveSettings(settings);
    ACTIVE_PRESENCE_PENALTY = settings.presencePenalty;
    document.getElementById('presencePenaltyValue').textContent = value;
}

function saveEnterToSend(checked) {
    const settings = loadSettings();
    settings.enterToSend = checked;
    saveSettings(settings);
}

function saveShowTimestamps(checked) {
    const settings = loadSettings();
    settings.showTimestamps = checked;
    saveSettings(settings);
    // Re-render messages to apply timestamp visibility
    if (currentChatId) {
        const chats = loadChatsFromStorage();
        const chat = chats.find(c => c.id === currentChatId);
        if (chat) {
            messagesContainer.innerHTML = '';
            chat.messages.forEach(m => {
                addMessage(m.sender, m.text, false, m.id, m.attachments, m.model, m.timestamp);
            });
        }
    }
}

function saveApiKey(provider, value) {
    const settings = loadSettings();
    settings.apiKeys[provider] = value.trim();
    saveSettings(settings);
    
    // Update placeholder to show key is configured
    const input = document.getElementById(`apiKey_${provider}`);
    if (input && value.trim()) {
        input.placeholder = '••••••••';
    }
}

// ===== Appearance / Font Settings =====
function applyAppearanceSettings() {
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

function saveChatFontFamily(value) {
    const settings = loadSettings();
    settings.chatFontFamily = value;
    saveSettings(settings);
    applyAppearanceSettings();
}

function saveUIFontFamily(value) {
    const settings = loadSettings();
    settings.uiFontFamily = value;
    saveSettings(settings);
    applyAppearanceSettings();
}

function saveInputTextColor(value) {
    const settings = loadSettings();
    settings.inputTextColor = value;
    saveSettings(settings);
    applyAppearanceSettings();
}

function saveOutputTextColor(value) {
    const settings = loadSettings();
    settings.outputTextColor = value;
    saveSettings(settings);
    applyAppearanceSettings();
}

function saveChatFontSize(value) {
    const settings = loadSettings();
    settings.chatFontSize = parseInt(value, 10) || DEFAULT_SETTINGS.chatFontSize;
    saveSettings(settings);
    applyAppearanceSettings();
    const lbl = document.getElementById('chatFontSizeValue');
    if (lbl) lbl.textContent = settings.chatFontSize + 'px';
}

function getStorageUsage() {
    let total = 0;
    for (let key in localStorage) {
        if (localStorage.hasOwnProperty(key)) {
            total += localStorage[key].length * 2; // UTF-16 = 2 bytes per char
        }
    }
    return (total / 1024 / 1024).toFixed(2); // MB
}

// Format bytes into human-readable string (e.g., 1.23 MB)
function formatFileSize(bytes) {
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

function clearGeneratedImages() {
    if (confirm('Delete all generated images from storage?')) {
        localStorage.removeItem('parakleon_images_v1');
        renderImages();
        alert('All generated images cleared.');
    }
}

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
    if (currentChatId === chatId) {
        currentChatId = null;
        messagesContainer.innerHTML = '';
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
    currentProjectId = projectId;
    currentChatId = chatId;
    renderProjects();
    closeProjectModal();
    
    // Load the project's first chat
    messagesContainer.innerHTML = '';
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
        item.className = 'project-item' + (project.id === currentProjectId ? ' active' : '');
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
    currentProjectId = projectId;
    if (project.chats && project.chats.length > 0) {
        currentChatId = project.chats[0].id;
    } else {
        currentChatId = null;
    }
    messagesContainer.innerHTML = '';
    if (currentChatId) {
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
            if (currentProjectId === projectId) {
                currentProjectId = null;
                currentChatId = null;
                messagesContainer.innerHTML = '';
            }
            renderProjects();
            renderHistory();
        }
        closeHistoryMenu();
    };
    menu.appendChild(deleteItem);

    const top = rect.bottom - containerRect.top + window.scrollY;
    const left = rect.left - containerRect.left + window.scrollX;
    menu.style.top = top + 'px';
    menu.style.left = left + 'px';

    document.body.appendChild(menu);
    openMenuElement = menu;
}

function saveGeneratedImages(imageAttachments, prompt) {
    const STORAGE_KEY = 'parakleon_images_v1';
    let images = [];
    
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (raw) images = JSON.parse(raw);
    } catch (e) {
        console.error('Failed to load images', e);
    }
    
    imageAttachments.forEach(img => {
        images.unshift({
            id: 'img_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9),
            url: img.url,
            name: img.name,
            prompt: prompt,
            projectId: currentProjectId || null,
            chatId: currentChatId || null,
            createdAt: Date.now()
        });
    });
    
    try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(images));
        renderImages();
    } catch (e) {
        console.error('Failed to save images', e);
    }
}

// ========== Images Gallery Modal ==========
function openImagesGallery() {
    const modal = document.getElementById('imagesGalleryModal');
    if (modal) {
        modal.classList.remove('hidden');
        renderImagesGallery();
    }
}

function closeImagesGallery() {
    const modal = document.getElementById('imagesGalleryModal');
    if (modal) modal.classList.add('hidden');
}

function renderImagesGallery() {
    const STORAGE_KEY = 'parakleon_images_v1';
    const grid = document.getElementById('imagesGalleryGrid');
    
    if (!grid) return;
    
    let images = [];
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (raw) images = JSON.parse(raw);
    } catch (e) {
        console.error('Failed to load images', e);
    }
    
    grid.innerHTML = '';
    
    if (images.length === 0) {
        grid.innerHTML = '<div style="grid-column: 1/-1; padding: 40px; text-align: center; color: #666; font-size: 13px;">No images yet. Click "Generate New" to create one!</div>';
        return;
    }
    
    images.forEach(img => {
        const item = document.createElement('div');
        item.style.cssText = 'position: relative; border: 1px solid #00FFFF; border-radius: 6px; overflow: hidden; cursor: pointer; transition: all 0.2s ease;';
        
        const thumb = document.createElement('img');
        thumb.src = img.url;
        thumb.style.cssText = 'width: 100%; height: 100px; object-fit: cover;';
        thumb.alt = img.name;
        
        const info = document.createElement('div');
        info.style.cssText = 'padding: 6px; background: rgba(0,0,0,0.8); font-size: 10px; color: #999; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;';
        info.textContent = img.name;
        
        const deleteBtn = document.createElement('button');
        deleteBtn.textContent = '×';
        deleteBtn.style.cssText = 'position: absolute; top: 4px; right: 4px; background: rgba(255,0,0,0.8); border: none; color: #fff; width: 20px; height: 20px; border-radius: 50%; cursor: pointer; font-size: 14px; line-height: 1; opacity: 0; transition: opacity 0.2s;';
        deleteBtn.onclick = (e) => {
            e.stopPropagation();
            deleteImageFromGallery(img.id);
        };
        
        item.appendChild(thumb);
        item.appendChild(info);
        item.appendChild(deleteBtn);
        
        item.onmouseover = () => {
            item.style.boxShadow = '0 0 8px rgba(0, 255, 255, 0.4)';
            deleteBtn.style.opacity = '1';
        };
        item.onmouseout = () => {
            item.style.boxShadow = '';
            deleteBtn.style.opacity = '0';
        };
        
        item.onclick = () => {
            closeImagesGallery();
            openImageModal(img);
        };
        
        grid.appendChild(item);
    });
}

function deleteImageFromGallery(imageId) {
    if (!confirm('Delete this image?')) return;
    
    const STORAGE_KEY = 'parakleon_images_v1';
    let images = [];
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (raw) images = JSON.parse(raw);
        images = images.filter(img => img.id !== imageId);
        localStorage.setItem(STORAGE_KEY, JSON.stringify(images));
        renderImagesGallery();
    } catch (e) {
        console.error('Failed to delete image', e);
    }
}

function renderImages() {
    const STORAGE_KEY = 'parakleon_images_v1';
    const imagesList = document.getElementById('imagesList');
    
    if (!imagesList) return;
    
    let images = [];
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (raw) images = JSON.parse(raw);
    } catch (e) {
        console.error('Failed to load images', e);
    }
    
    imagesList.innerHTML = '';
    
    if (images.length === 0) {
        imagesList.innerHTML = '<div style="padding: 12px; text-align: center; color: #666; font-size: 11px;">No images yet</div>';
        return;
    }
    
    images.forEach(img => {
        const item = document.createElement('div');
        item.className = 'image-item';
        item.style.cssText = 'padding: 8px; border-bottom: 1px solid #222; cursor: pointer; transition: background 0.2s;';
        
        const thumb = document.createElement('img');
        thumb.src = img.url;
        thumb.style.cssText = 'width: 100%; height: 80px; object-fit: cover; border-radius: 4px; border: 1px solid #00FFFF; margin-bottom: 4px;';
        thumb.alt = img.name;
        
        const info = document.createElement('div');
        info.style.cssText = 'font-size: 10px; color: #999; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;';
        info.textContent = img.name;
        
        item.appendChild(thumb);
        item.appendChild(info);
        
        item.onmouseover = () => item.style.background = '#1a1a1a';
        item.onmouseout = () => item.style.background = '';
        
        item.onclick = () => openImageModal(img);
        
        imagesList.appendChild(item);
    });
}

function openImageModal(img) {
    const modal = document.createElement('div');
    modal.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.9); display: flex; flex-direction: column; align-items: center; justify-content: center; z-index: 10000; padding: 20px;';
    
    const closeBtn = document.createElement('button');
    closeBtn.textContent = '×';
    closeBtn.style.cssText = 'position: absolute; top: 20px; right: 30px; background: transparent; border: 2px solid #00FFFF; color: #00FFFF; font-size: 32px; cursor: pointer; padding: 5px 15px; border-radius: 4px;';
    closeBtn.onclick = () => document.body.removeChild(modal);
    
    const image = document.createElement('img');
    image.src = img.url;
    image.style.cssText = 'max-width: 90%; max-height: 70%; border: 2px solid #00FFFF; border-radius: 8px; object-fit: contain;';
    
    const info = document.createElement('div');
    info.style.cssText = 'margin-top: 20px; color: #00FFFF; text-align: center; max-width: 600px;';
    info.innerHTML = `
        <div style="font-size: 14px; margin-bottom: 8px;"><strong>${escapeHtml(img.name)}</strong></div>
        <div style="font-size: 12px; color: #999; margin-bottom: 12px;">Generated: ${new Date(img.createdAt).toLocaleString()}</div>
        ${img.prompt ? `<div style="font-size: 11px; color: #666; font-style: italic;">"${escapeHtml(img.prompt.substring(0, 100))}${img.prompt.length > 100 ? '...' : ''}"</div>` : ''}
    `;
    
    const actions = document.createElement('div');
    actions.style.cssText = 'margin-top: 12px; display: flex; gap: 12px; justify-content: center;';
    
    const downloadBtn = document.createElement('a');
    downloadBtn.href = img.url;
    downloadBtn.download = img.name;
    downloadBtn.textContent = '⬇ Download';
    downloadBtn.style.cssText = 'padding: 8px 16px; background: #00FFFF; color: #000; text-decoration: none; border-radius: 4px; font-size: 12px;';
    
    const deleteBtn = document.createElement('button');
    deleteBtn.textContent = '🗑 Delete';
    deleteBtn.style.cssText = 'padding: 8px 16px; background: transparent; border: 1px solid #ff0000; color: #ff0000; border-radius: 4px; font-size: 12px; cursor: pointer;';
    deleteBtn.onclick = () => {
        if (confirm('Delete this image?')) {
            deleteImage(img.id);
            document.body.removeChild(modal);
        }
    };
    
    actions.appendChild(downloadBtn);
    actions.appendChild(deleteBtn);
    
    modal.appendChild(closeBtn);
    modal.appendChild(image);
    modal.appendChild(info);
    modal.appendChild(actions);
    
    document.body.appendChild(modal);
}

function deleteImage(imageId) {
    const STORAGE_KEY = 'parakleon_images_v1';
    let images = [];
    
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (raw) images = JSON.parse(raw);
    } catch (e) {
        console.error('Failed to load images', e);
        return;
    }
    
    images = images.filter(img => img.id !== imageId);
    
    try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(images));
        renderImages();
    } catch (e) {
        console.error('Failed to save images', e);
    }
}

// Duplicate renderProjects removed. Only one canonical implementation remains.

function saveGeneratedImages(imageAttachments, prompt) {
    const STORAGE_KEY = 'parakleon_images_v1';
    let images = [];
    
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (raw) images = JSON.parse(raw);
    } catch (e) {
        console.error('Failed to load images', e);
    }
    
    imageAttachments.forEach(img => {
        images.unshift({
            id: 'img_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9),
            url: img.url,
            name: img.name,
            prompt: prompt,
            projectId: currentProjectId || null,
            chatId: currentChatId || null,
            createdAt: Date.now()
        });
    });
    
    try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(images));
        renderImages();
    } catch (e) {
        console.error('Failed to save images', e);
    }
}

// ========== Image Generation ==========

function openImageGenerator() {
    const modal = document.getElementById('imageGenModal');
    const prompt = document.getElementById('imagePrompt');
    const status = document.getElementById('imageGenStatus');

    modal.classList.remove('hidden');
    prompt.value = '';
    status.style.display = 'none';
    prompt.focus();
}

function closeImageGenerator() {
    const modal = document.getElementById('imageGenModal');
    if (modal) modal.classList.add('hidden');
}

async function generateImage() {
    const prompt = document.getElementById('imagePrompt').value.trim();
    const status = document.getElementById('imageGenStatus');
    const generateBtn = document.querySelector('#imageGeneratorModal button[onclick="generateImage()"]');

    if (!prompt) {
        status.textContent = '⚠ Please enter a description';
        status.style.display = 'block';
        status.style.color = '#ff6b6b';
        showToast('Please enter an image description', 3000, 'error');
        return;
    }

    // Disable button during generation
    if (generateBtn) {
        generateBtn.disabled = true;
        generateBtn.textContent = 'Generating...';
    }

    const themeColor = getComputedStyle(document.documentElement).getPropertyValue('--theme-primary').trim() || '#00ffff';

    // Create progress bar
    const progressContainer = document.createElement('div');
    progressContainer.id = 'imageGenProgress';
    progressContainer.style.cssText = 'margin-top: 12px; width: 100%;';
    progressContainer.innerHTML = `
        <div style="margin-bottom: 6px;">
            <span id="progressText" style="color: ${themeColor}; font-size: 12px;">🎨 Starting...</span>
        </div>
        <div style="width: 100%; height: 8px; background: #222; border-radius: 4px; overflow: hidden;">
            <div id="progressBar" style="width: 0%; height: 100%; background: ${themeColor}; transition: width 0.3s;"></div>
        </div>
        <div style="margin-top: 4px; font-size: 11px; color: #666;" id="progressDetails">Estimated time: ~3 minutes</div>
    `;

    // Insert progress bar after status
    status.parentNode.insertBefore(progressContainer, status.nextSibling);
    status.style.display = 'none';

    try {
        // Use SSE endpoint for real-time progress
        const streamUrl = window.PARAKLEON_CONFIG.LOCAL_IMAGE_GEN_URL.replace('/api/generate-image', '/api/generate-image-stream');

        // Create SSE connection
        const response = await fetch(streamUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                prompt: prompt
            })
        });

        if (!response.ok) {
            throw new Error(`Server error: ${response.status}`);
        }

        // Read SSE stream
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        let base64Image = null;

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            buffer = lines.pop() || '';

            for (const line of lines) {
                if (line.startsWith('data: ')) {
                    const data = JSON.parse(line.slice(6));
                    const progressBar = document.getElementById('progressBar');
                    const progressText = document.getElementById('progressText');
                    const progressDetails = document.getElementById('progressDetails');

                    if (data.status === 'starting') {
                        progressText.textContent = data.message;
                    } else if (data.status === 'progress') {
                        const percent = Math.round(data.progress * 100);
                        progressBar.style.width = `${percent}%`;
                        progressText.textContent = `🎨 ${data.message}`;

                        // Calculate estimated time remaining
                        const elapsed = (data.step / data.total_steps);
                        const avgTimePerStep = 6; // ~6 seconds per step on CPU
                        const remaining = Math.round(avgTimePerStep * (data.total_steps - data.step));
                        progressDetails.textContent = `Step ${data.step}/${data.total_steps} • ~${remaining}s remaining`;
                    } else if (data.status === 'complete') {
                        progressBar.style.width = '100%';
                        progressText.textContent = '✓ ' + data.message;
                        progressDetails.textContent = 'Done!';
                        base64Image = data.image;
                    } else if (data.status === 'error') {
                        throw new Error(data.error);
                    }
                }
            }
        }

        if (!base64Image) {
            throw new Error('No image data received from server.');
        }

        // Create an attachment object for the new image
        const imageAttachment = {
            type: 'image/png',
            url: base64Image,
            previewUrl: base64Image,
            name: `${prompt.slice(0, 20).replace(/\s/g, '_')}.png`
        };

        // Add to chat as an assistant message with the image
        addMessage(`Generated image for: "${prompt}"`, 'ai', true, [imageAttachment]);

        // Auto-save to Images gallery
        saveGeneratedImages([imageAttachment], prompt);

        showToast('Image generated successfully!', 3000, 'success');

        // Close modal after a brief delay to show completion
        setTimeout(() => closeImageGenerator(), 1000);

    } catch (error) {
        console.error('Image generation error:', error);

        // Remove progress bar
        const progressContainer = document.getElementById('imageGenProgress');
        if (progressContainer) {
            progressContainer.remove();
        }

        // Use formatted error with recovery suggestions
        const formatted = formatError(error, 'image_generation');

        // Update modal status
        if (status) {
            status.textContent = `❌ ${formatted.title}`;
            status.style.color = formatted.severity === 'error' ? '#ff6b6b' : '#f59e0b';
            status.style.display = 'block';
        }

        // Show toast with actionable error
        showToast(formatted.title, 5000, formatted.severity);

        // For severe errors, also show formatted error card
        if (formatted.severity === 'error') {
            showFormattedError(error, 'image_generation');
        }
    } finally {
        // Re-enable button
        if (generateBtn) {
            generateBtn.disabled = false;
            generateBtn.textContent = 'Generate Image';
        }

        // Clean up progress bar if still present
        setTimeout(() => {
            const progressContainer = document.getElementById('imageGenProgress');
            if (progressContainer) {
                progressContainer.remove();
            }
        }, 2000);
    }
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
			refreshOllamaModels();
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

	// Initialize sidebar hover/toggle behavior
	if (typeof setupSidebarHover === 'function') setupSidebarHover();

	// Check backend availability (shows banner if only a static file server is running)
	checkBackend(false);

	// Load saved theme mode
	loadThemeMode();

	// Initialize file upload handling
	initFileUpload();

	console.log('[Parakleon] Initialized successfully');
}

// Ensure init runs on load
window.addEventListener('DOMContentLoaded', init);

// Replace the IIFE with a named, re-entrant initializer for sidebar hover behavior
function setupSidebarHover() {
    if (setupSidebarHover._attached) return; // prevent double-attach
    setupSidebarHover._attached = true;

    if (typeof window === 'undefined') return;

    const HOVER_ZONE = 50; // px from left edge to open (slightly larger for reliability)
    const CLOSE_DELAY = 1200; // ms delay before closing
    const isTouchDevice = 'ontouchstart' in window;
    let closeTimer = null;

    const sidebar = document.querySelector('.sidebar');
    const hoverStrip = document.getElementById('hoverStrip');
    if (!sidebar) return;

    const clearCloseTimer = () => { if (closeTimer) { clearTimeout(closeTimer); closeTimer = null; } };

    function openSidebar() {
        clearCloseTimer();
        if (sidebar.classList.contains('hidden')) {
            sidebar.classList.remove('hidden');
            if (hoverStrip) hoverStrip.classList.add('hidden');
        }
    }
    function closeSidebar() {
        clearCloseTimer();
        if (!sidebar.classList.contains('hidden')) {
            sidebar.classList.add('hidden');
            if (hoverStrip) hoverStrip.classList.remove('hidden');
        }
    }

    if (!isTouchDevice) {
        // Sidebar hover logic (see main.css for .sidebar and .hover-strip)
        document.addEventListener('mousemove', (e) => {
            const x = e.clientX;
            if (x <= HOVER_ZONE) {
                openSidebar();
            } else if (!sidebar.matches(':hover') && !(hoverStrip && hoverStrip.matches(':hover')) && !sidebar.classList.contains('hidden') && !closeTimer) {
                closeTimer = setTimeout(closeSidebar, CLOSE_DELAY);
            }
        });

        sidebar.addEventListener('mouseenter', () => { clearCloseTimer(); });
        sidebar.addEventListener('mouseleave', () => { clearCloseTimer(); closeTimer = setTimeout(closeSidebar, CLOSE_DELAY); });

        if (hoverStrip) {
            hoverStrip.addEventListener('mouseenter', () => { openSidebar(); });
        }
    } else {
        // Touch: click to toggle and click outside to close
        if (hoverStrip) {
            hoverStrip.addEventListener('click', (e) => {
                e.preventDefault(); e.stopPropagation();
                if (sidebar.classList.contains('hidden')) openSidebar(); else closeSidebar();
            });
        }

        document.addEventListener('click', (e) => {
            if (!sidebar.contains(e.target) && !(hoverStrip && hoverStrip.contains(e.target))) {
                if (!sidebar.classList.contains('hidden')) closeSidebar();
            }
        });
    }

    if (hoverStrip) {
        hoverStrip.addEventListener('keydown', (ev) => {
            if (ev.key === 'Enter' || ev.key === ' ' || ev.key === 'Spacebar') {
                ev.preventDefault(); openSidebar();
            } else if (ev.key === 'Escape') {
                ev.preventDefault(); closeSidebar();
            }
        });
        if (!sidebar.classList.contains('hidden')) hoverStrip.classList.add('hidden');
    }

    // Global keyboard: Escape closes open panels
    document.addEventListener('keydown', (ev) => {
        // Ctrl+` shortcut to show CLI commands
        if (ev.ctrlKey && ev.key === '`') {
            ev.preventDefault();
            showCliHelp();
            return;
        }

        if (ev.key === 'Escape') {
            const filesPanel = document.getElementById('filesPanel');
            if (filesPanel && !filesPanel.classList.contains('hidden')) {
                hideFilesPanel();
                ev.stopPropagation();
                return;
            }
            if (sidebar && !sidebar.classList.contains('hidden')) {
                closeSidebar();
                ev.stopPropagation();
            }
        }
    });
}
