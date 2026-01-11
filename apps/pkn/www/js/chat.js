/**
 * Chat Module
 * Handles chat messaging and conversation management
 */

import { showToast, escapeHtml } from './utils.js';
import { loadChatsFromStorage, saveChatsToStorage, loadProjectsFromStorage, saveProjectsFromStorage, loadSettings } from './storage.js';

// Global variables that need to be accessed/modified
let currentChatId = null;
let currentProjectId = null;
let editingMessageId = null;

// DOM references
let messagesContainer = null;
let messageInput = null;

/**
 * Initialize chat module with DOM references
 */
export function initChat() {
    messagesContainer = document.getElementById('messagesContainer');
    messageInput = document.getElementById('messageInput');

    // Expose globals for backward compatibility
    window.currentChatId = currentChatId;
    window.currentProjectId = currentProjectId;
}

/**
 * Set current chat ID
 * @param {string} chatId - The chat ID to set
 */
export function setCurrentChatId(chatId) {
    currentChatId = chatId;
    window.currentChatId = chatId;
}

/**
 * Get current chat ID
 * @returns {string} Current chat ID
 */
export function getCurrentChatId() {
    return currentChatId;
}

/**
 * Set current project ID
 * @param {string} projectId - The project ID to set
 */
export function setCurrentProjectId(projectId) {
    currentProjectId = projectId;
    window.currentProjectId = projectId;
}

/**
 * Get current project ID
 * @returns {string} Current project ID
 */
export function getCurrentProjectId() {
    return currentProjectId;
}

/**
 * Get the current chat object
 * @param {Array} chats - Array of chat objects
 * @returns {Object|undefined} Current chat object
 */
export function getCurrentChat(chats) {
    return chats.find(c => c.id === currentChatId);
}

/**
 * Ensure current chat exists (create if needed)
 */
export function ensureCurrentChat() {
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
            window.currentChatId = null;
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
        window.currentChatId = null;
    }
}

/**
 * Append a message to the current chat in storage
 * @param {string} sender - Message sender ('user', 'ai', 'system')
 * @param {string} text - Message text
 * @param {Array} attachments - Optional attachments
 * @param {string} messageId - Optional message ID
 * @param {string} model - Optional model name
 */
export function appendMessageToCurrentChat(sender, text, attachments = [], messageId = null, model = null) {
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
                setTimeout(() => window.reloadCurrentChat && window.reloadCurrentChat(), 100);
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
                window.renderHistory && window.renderHistory();
                // Reload chat to show changes
                setTimeout(() => window.reloadCurrentChat && window.reloadCurrentChat(), 100);
                return;
            } else {
                const id = 'msg_' + now + '_' + Math.floor(Math.random() * 10000);
                const message = {id, sender, text, attachments, timestamp: now};
                if (model) message.model = model;
                chat.messages.push(message);
            }
            if (chat.title === 'Untitled chat' && sender === 'user') {
                chat.title = text.slice(0, 30);
            }
            if (chat.useFullHistory === undefined) chat.useFullHistory = true;
            chat.updatedAt = now;
            saveChatsToStorage(chats);
        }
    }
}

/**
 * Add a message to the DOM and optionally save to storage
 * @param {string} text - Message text
 * @param {string} sender - Message sender ('user', 'ai', 'system')
 * @param {boolean} saveToChat - Whether to save to storage
 * @param {Array} attachments - Optional attachments
 * @param {string} id - Optional message ID
 * @param {string} model - Optional model name
 * @param {number} timestamp - Optional timestamp
 */
export function addMessage(text, sender = 'user', saveToChat = true, attachments = [], id = null, model = null, timestamp = null) {
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

        el.innerHTML = `
            <div class="message-row">
                ${avatarHtml}
                <div class="message-body">
                    <div class="message-content">${contentHtml}</div>
                    ${tsHtml}
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

/**
 * Send a message to the AI
 */
export function sendMessage() {
    const input = messageInput.value.trim();
    if (!input) return;

    // Disable input and button during request
    const sendBtn = document.getElementById('sendBtn');
    const messageInput = document.getElementById('messageInput');
    if (messageInput) messageInput.disabled = true;
    if (sendBtn) {
        sendBtn.disabled = true;
        sendBtn.dataset.originalText = sendBtn.textContent;
        sendBtn.textContent = 'Sending...';
    }

    // Add user message to chat and storage immediately
    addMessage(input, 'user', false);
    appendMessageToCurrentChat('user', input);
    messageInput.value = '';

    // Show thinking/typing animation (AI is responding)
    const thinkingId = 'thinking_' + Date.now();
    addMessage('<span class="thinking-dots"><span class="dot active"></span><span class="dot"></span><span class="dot"></span></span>', 'ai', false, [], thinkingId);

    // Prepare chat history for backend (send all messages in current chat)
    let chats = loadChatsFromStorage();
    let chat = getCurrentChat(chats);
    let messages = chat && chat.messages ? chat.messages.map(m => ({ role: m.sender === 'user' ? 'user' : 'assistant', content: m.text })) : [{ role: 'user', content: input }];

    // Build provider-prefixed modelId for server compatibility (e.g., "llamacpp:local", "ollama:xyz")
    const ACTIVE_MODEL = window.ACTIVE_MODEL || 'openai';
    const ACTIVE_PROVIDER = window.ACTIVE_PROVIDER || 'openai';
    const modelIdToSend = (typeof ACTIVE_MODEL === 'string' && ACTIVE_MODEL.includes(':')) ? ACTIVE_MODEL : (ACTIVE_PROVIDER ? `${ACTIVE_PROVIDER}:${ACTIVE_MODEL}` : ACTIVE_MODEL);

    // Add timeout handling (30 seconds)
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000);

    fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ messages, modelId: modelIdToSend }),
        signal: controller.signal
    })
    .then(async res => {
        clearTimeout(timeoutId);
        const json = await res.json().catch(()=>({}));
        if (!res.ok) {
            const thinkingElem = document.getElementById(thinkingId);
            if (thinkingElem) thinkingElem.remove();

            // Provide more specific error messages
            let errorMsg = 'Unknown error';
            if (res.status === 502) {
                errorMsg = 'Backend service unavailable. Please check if llama.cpp/Ollama is running.';
            } else if (res.status === 500) {
                errorMsg = json.error || 'Server error. Check server logs for details.';
            } else if (res.status === 404) {
                errorMsg = 'API endpoint not found. Please check server configuration.';
            } else {
                errorMsg = json.error || `HTTP ${res.status}`;
            }

            addMessage('Error: ' + errorMsg, 'system', false);
            showToast(errorMsg, 5000, 'error');
            throw new Error(errorMsg);
        }
        return json;
    })
    .then(data => {
        // Remove thinking animation
        const thinkingElem = document.getElementById(thinkingId);
        if (thinkingElem) thinkingElem.remove();

        // Add AI response to chat
        let aiText = '';
        if (data.choices && data.choices[0] && data.choices[0].message) {
            aiText = data.choices[0].message.content;
        } else if (data.output) {
            aiText = data.output;
        } else if (data.text) {
            aiText = data.text;
        } else {
            aiText = '[No response]';
            showToast('Received empty response from AI', 3000, 'error');
        }
        addMessage(aiText, 'ai', false);
        appendMessageToCurrentChat('ai', aiText);
    })
    .catch(err => {
        clearTimeout(timeoutId);
        const thinkingElem = document.getElementById(thinkingId);
        if (thinkingElem) thinkingElem.remove();

        // Handle different error types
        let errorMsg = err.message || 'Request failed';
        if (err.name === 'AbortError') {
            errorMsg = 'Request timed out after 30 seconds. Please try again or check your connection.';
            showToast(errorMsg, 5000, 'error');
        } else if (errorMsg.includes('Failed to fetch') || errorMsg.includes('NetworkError')) {
            errorMsg = 'Network error. Please check your connection and ensure the server is running.';
            showToast(errorMsg, 5000, 'error');
        }

        addMessage('Error: ' + errorMsg, 'system', false);
    })
    .finally(() => {
        // Re-enable input and button
        if (messageInput) messageInput.disabled = false;
        if (sendBtn) {
            sendBtn.disabled = false;
            sendBtn.textContent = sendBtn.dataset.originalText || 'Send';
        }
        if (messageInput) messageInput.focus();
    });
}

// Export for backward compatibility
export { currentChatId, currentProjectId, editingMessageId };
