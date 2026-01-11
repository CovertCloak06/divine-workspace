/**
 * Multi-Agent UI Integration
 * Handles agent selection, status display, and session management
 */

class MultiAgentUI {
    constructor() {
        this.currentSession = null;
        this.availableAgents = [];
        this.currentAgent = null;
        this.agentMode = 'auto'; // 'auto' or 'manual'
        this.currentStreamController = null; // For aborting streams

        this.init();
    }

    async init() {
        // Load available agents
        await this.loadAgents();

        // Create UI elements
        this.createHeaderControls();
        this.createSessionDisplay();
        this.createSessionPanel();
        this.createAgentSwitcherPanel();

        // Set up event listeners
        this.setupEventListeners();
        this.setupKeyboardShortcuts();

        console.log('[MultiAgent] Initialized successfully');
    }

    async loadAgents() {
        try {
            const response = await fetch('/api/multi-agent/agents');
            const data = await response.json();

            if (data.status === 'success') {
                this.availableAgents = data.agents;
                console.log(`[MultiAgent] Loaded ${data.count} agents`);
            }
        } catch (error) {
            console.error('[MultiAgent] Failed to load agents:', error);
        }
    }

    createHeaderControls() {
        // Add agent controls to header (replace model select)
        const headerModelSelect = document.querySelector('.header-model-select');
        if (!headerModelSelect) return;

        // Create container for all header controls
        headerModelSelect.innerHTML = `
            <div class="header-agent-controls">
                <!-- Current agent display (above dropdown) -->
                <div class="header-agent-display">
                    <span class="agent-label">Agent:</span>
                    <span class="agent-name" id="currentAgentName">Auto-Select</span>
                    <span class="agent-badge" id="currentAgentBadge">⚙️</span>
                </div>

                <!-- Row with thinking, Auto/Manual toggle and agent dropdown -->
                <div class="header-controls-row">
                    <!-- Thinking indicator (left of toggle) -->
                    <div class="agent-thinking-header" id="agentThinking" style="display: none;">
                        <div class="thinking-spinner"></div>
                    </div>

                    <!-- Auto/Manual toggle -->
                    <div class="agent-mode-toggle-header">
                        <button class="mode-btn-header active" data-mode="auto" onclick="window.multiAgentUI.setMode('auto')" title="Auto">
                            <span class="mode-icon">⚡</span>
                        </button>
                        <button class="mode-btn-header" data-mode="manual" onclick="window.multiAgentUI.setMode('manual')" title="Manual">
                            <span class="mode-icon">👤</span>
                        </button>
                    </div>

                    <!-- Agent selector dropdown -->
                    <select id="agentSelect" class="model-select-header" onchange="window.multiAgentUI.onAgentSelectChange()">
                        <option value="auto">Auto-Select Agent</option>
                    </select>
                </div>
            </div>
        `;

        // Populate agent selector
        this.populateAgentSelector();
    }

    createSessionDisplay() {
        // Add session info to bottom left of header, under logo
        const header = document.querySelector('.header');
        if (!header) return;

        const sessionDisplay = document.createElement('div');
        sessionDisplay.id = 'sessionDisplay';
        sessionDisplay.className = 'session-display-header';
        sessionDisplay.innerHTML = `
            <div class="session-info-header">
                <span class="session-label-header">Session:</span>
                <span class="session-id-header" id="currentSessionId">New</span>
                <button class="session-save-btn-header" onclick="window.multiAgentUI.saveCurrentSession()" title="Save session">
                    💾
                </button>
            </div>
        `;

        header.appendChild(sessionDisplay);
    }

    populateAgentSelector() {
        const select = document.getElementById('agentSelect');
        if (!select) return;

        select.innerHTML = '<option value="auto">Auto-Select Agent</option>';

        this.availableAgents.forEach(agent => {
            const option = document.createElement('option');
            option.value = agent.type;
            option.textContent = `${agent.name}`;
            option.dataset.capabilities = agent.capabilities.join(', ');
            select.appendChild(option);
        });
    }

    onAgentSelectChange() {
        const select = document.getElementById('agentSelect');
        if (!select) return;

        const value = select.value;

        if (value === 'auto') {
            this.setMode('auto');
        } else {
            this.setMode('manual');
            this.currentAgent = value;
            const selectedOption = select.options[select.selectedIndex];
            this.updateAgentDisplay(value, selectedOption.textContent);
        }
    }

    createSessionPanel() {
        // Add session management to sidebar
        const sidebarContent = document.querySelector('.sidebar-content');
        if (!sidebarContent) return;

        const sessionSection = document.createElement('div');
        sessionSection.innerHTML = `
            <div class="sidebar-section-header" onclick="toggleSection('sessionsSection')">
                <span>Sessions</span>
                <span class="chevron" id="sessionsChevron">►</span>
            </div>
            <div class="sidebar-section collapsed" id="sessionsSection">
                <div class="sessions-list" id="sessionsList">
                    <div class="session-item-empty">No saved sessions</div>
                </div>
                <div class="sessions-footer">
                    <button class="action-btn" onclick="window.multiAgentUI.loadSessions()" style="width: 100%; font-size: 11px;">
                        Refresh Sessions
                    </button>
                </div>
            </div>
        `;

        // Insert before AI Models section
        const aiModelsHeader = Array.from(sidebarContent.querySelectorAll('.sidebar-section-header'))
            .find(h => h.textContent.includes('AI Models'));

        if (aiModelsHeader) {
            sidebarContent.insertBefore(sessionSection, aiModelsHeader);
        } else {
            sidebarContent.appendChild(sessionSection);
        }
    }

    setupEventListeners() {
        // Intercept send button to use multi-agent endpoint
        const originalSendMessage = window.sendMessage;

        window.sendMessage = async () => {
            if (this.agentMode === 'auto' || this.currentAgent) {
                await this.sendMultiAgentMessage();
            } else {
                // Fallback to original
                if (originalSendMessage) originalSendMessage();
            }
        };
    }

    async sendMultiAgentMessage() {
        // Use streaming by default (can be disabled via settings)
        const useStreaming = true; // TODO: Make this a user setting

        if (useStreaming) {
            return await this.sendMultiAgentMessageStreaming();
        } else {
            return await this.sendMultiAgentMessageNonStreaming();
        }
    }

    async sendMultiAgentMessageStreaming() {
        const messageInput = document.getElementById('messageInput');
        if (!messageInput) return;

        const message = messageInput.value.trim();
        if (!message) return;

        // Create abort controller for this request
        this.currentStreamController = new AbortController();

        // Disable input
        messageInput.disabled = true;

        // Change send button to stop button
        const sendBtn = document.getElementById('sendBtn');
        if (sendBtn) {
            sendBtn.disabled = false; // Keep enabled so user can click to stop
            sendBtn.dataset.originalText = sendBtn.textContent;
            sendBtn.textContent = '⏹ Stop';
            sendBtn.onclick = () => this.stopStreaming();
        }

        // Show thinking indicator
        this.showThinking(true);

        // Add user message to UI
        this.addMessageToUI('user', message);

        // Track performance
        const startTime = Date.now();
        let selectedAgent = this.currentAgent || 'auto';
        let currentMessageDiv = null;

        try {
            const payload = {
                message: message,
                session_id: this.currentSession
            };

            // If manual mode, specify agent
            if (this.agentMode === 'manual' && this.currentAgent) {
                payload.agent_type = this.currentAgent;
            }

            // Create response container for streaming
            const response = await fetch('/api/multi-agent/chat/stream', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload),
                signal: this.currentStreamController.signal
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            // Handle SSE stream
            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let buffer = '';
            let fullResponse = '';
            let eventData = {
                agent: null,
                routing: null,
                toolsUsed: [],
                executionTime: 0
            };

            while (true) {
                const { value, done } = await reader.read();
                if (done) break;

                buffer += decoder.decode(value, { stream: true });
                const lines = buffer.split('\n');
                buffer = lines.pop(); // Keep incomplete line in buffer

                for (const line of lines) {
                    if (line.startsWith('event: ')) {
                        const eventType = line.substring(7).trim();
                        continue;
                    }

                    if (line.startsWith('data: ')) {
                        const data = JSON.parse(line.substring(6));

                        if (data.type === 'start' || eventData.agent === null) {
                            selectedAgent = data.agent || selectedAgent;
                            eventData.agent = data.agent_name || data.agent;
                            eventData.routing = data.routing;
                            this.currentSession = data.session_id;
                            this.updateSessionDisplay(data.session_id);
                            this.updateAgentDisplay(data.agent, data.agent_name);
                        }

                        if (data.type === 'chunk' || data.content) {
                            const chunk = data.content || '';
                            fullResponse += chunk;

                            // Update or create message div
                            if (!currentMessageDiv) {
                                currentMessageDiv = this.addStreamingMessage('assistant', '', {
                                    agent: eventData.agent
                                });
                            }

                            // Update with new content
                            this.updateStreamingMessage(currentMessageDiv, fullResponse);
                        }

                        if (data.type === 'done') {
                            eventData.executionTime = data.execution_time;
                            eventData.toolsUsed = data.tools_used || [];

                            // Track success metrics
                            if (window.agentQualityMonitor) {
                                const perfRating = window.agentQualityMonitor.trackRequest(selectedAgent, startTime);
                                window.agentQualityMonitor.trackSuccess(selectedAgent);
                                eventData.perfRating = perfRating;
                            }

                            // Finalize message with metadata
                            if (currentMessageDiv) {
                                this.finalizeStreamingMessage(currentMessageDiv, eventData);
                            }
                        }

                        if (data.type === 'error' || data.error) {
                            throw new Error(data.content || data.error || 'Unknown streaming error');
                        }
                    }
                }
            }

            // Clear input
            messageInput.value = '';

        } catch (error) {
            console.error('[MultiAgent] Streaming error:', error);

            // Don't show error if user aborted
            if (error.name !== 'AbortError') {
                // Track error metrics
                if (window.agentQualityMonitor) {
                    window.agentQualityMonitor.trackError(selectedAgent, error, { message });
                }

                // Show error with retry button
                this.addErrorMessage(error, message);
            } else {
                // User stopped the stream
                console.log('[MultiAgent] Stream aborted by user');
            }
        } finally {
            // Re-enable input
            messageInput.disabled = false;

            // Restore send button
            if (sendBtn) {
                sendBtn.disabled = false;
                sendBtn.textContent = sendBtn.dataset.originalText || 'Send';
                sendBtn.onclick = null; // Remove stop handler
            }

            messageInput.focus();
            this.showThinking(false);
            this.currentStreamController = null;
        }
    }

    stopStreaming() {
        if (this.currentStreamController) {
            console.log('[MultiAgent] Stopping stream...');
            this.currentStreamController.abort();
            this.currentStreamController = null;

            // Show toast notification
            if (window.showToast) {
                window.showToast('Stream stopped', 2000, 'info');
            }
        }
    }

    async sendMultiAgentMessageNonStreaming() {
        const messageInput = document.getElementById('messageInput');
        if (!messageInput) return;

        const message = messageInput.value.trim();
        if (!message) return;

        // Disable input
        messageInput.disabled = true;
        const sendBtn = document.getElementById('sendBtn');
        if (sendBtn) sendBtn.disabled = true;

        // Show thinking indicator
        this.showThinking(true);

        // Add user message to UI
        this.addMessageToUI('user', message);

        // Track performance
        const startTime = Date.now();
        let selectedAgent = this.currentAgent || 'auto';

        try {
            const payload = {
                message: message,
                session_id: this.currentSession
            };

            // If manual mode, specify agent
            if (this.agentMode === 'manual' && this.currentAgent) {
                payload.agent_type = this.currentAgent;
            }

            // Use retry logic for better reliability
            const makeRequest = async () => {
                const response = await fetch('/api/multi-agent/chat', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(payload),
                    timeout: 180000 // 3 minute timeout
                });

                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }

                return response.json();
            };

            const data = window.agentQualityMonitor
                ? await window.agentQualityMonitor.retryRequest(makeRequest, 1, 3000)
                : await makeRequest();

            if (data.status === 'success') {
                selectedAgent = data.agent_used;

                // Track success metrics
                if (window.agentQualityMonitor) {
                    const perfRating = window.agentQualityMonitor.trackRequest(selectedAgent, startTime);
                    window.agentQualityMonitor.trackSuccess(selectedAgent);

                    // Add performance badge to metadata
                    data.perfRating = perfRating;
                }

                // Update session
                this.currentSession = data.session_id;
                this.updateSessionDisplay(data.session_id);

                // Update agent display
                this.updateAgentDisplay(data.agent_used, data.agent_name);

                // Add assistant response with quality metrics
                this.addMessageToUI('assistant', data.response, {
                    agent: data.agent_name || data.agent_used,
                    executionTime: data.execution_time,
                    toolsUsed: data.tools_used || [],
                    perfRating: data.perfRating,
                    routing: data.routing
                });

                // Clear input
                messageInput.value = '';
            } else {
                throw new Error(data.error || 'Unknown error');
            }
        } catch (error) {
            console.error('[MultiAgent] Error:', error);

            // Track error metrics
            if (window.agentQualityMonitor) {
                window.agentQualityMonitor.trackError(selectedAgent, error, { message });
            }

            // Show error with retry button
            this.addErrorMessage(error, message);
        } finally {
            // Re-enable input
            messageInput.disabled = false;
            if (sendBtn) sendBtn.disabled = false;
            messageInput.focus();
            this.showThinking(false);
        }
    }

    addErrorMessage(error, originalMessage) {
        const messagesContainer = document.getElementById('messagesContainer');
        if (!messagesContainer) return;

        const errorDiv = document.createElement('div');
        errorDiv.className = 'agent-error';
        errorDiv.innerHTML = `
            <div class="agent-error-title">⚠️ Request Failed</div>
            <div class="agent-error-detail">${this.escapeHtml(error.message)}</div>
            <button class="retry-btn" onclick="window.multiAgentUI.retryMessage('${this.escapeHtml(originalMessage)}')">
                🔄 Retry
            </button>
        `;

        messagesContainer.appendChild(errorDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    async retryMessage(message) {
        const messageInput = document.getElementById('messageInput');
        if (messageInput) {
            messageInput.value = message;
            await this.sendMultiAgentMessage();
        }
    }

    addMessageToUI(role, content, metadata = {}) {
        const messagesContainer = document.getElementById('messagesContainer');
        if (!messagesContainer) return;

        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${role}-message`;
        messageDiv.dataset.messageId = Date.now() + Math.random(); // Unique ID
        messageDiv.dataset.content = content; // Store original content

        if (role === 'user') {
            messageDiv.innerHTML = `
                <div class="message-header">
                    <span class="user-label">You:</span>
                    <span class="message-timestamp">${this.getRelativeTime(Date.now())}</span>
                </div>
                <div class="message-content">
                    <div class="message-text">${this.escapeHtml(content)}</div>
                </div>
                <div class="message-actions">
                    <button class="message-action-btn" onclick="copyMessageText(this)" title="Copy message">
                        📋
                    </button>
                    <button class="message-action-btn" onclick="editMessage(this)" title="Edit message">
                        ✏️
                    </button>
                    <button class="message-action-btn" onclick="deleteMessage(this)" title="Delete message">
                        🗑️
                    </button>
                </div>
            `;
        } else if (role === 'assistant') {
            const toolsInfo = metadata.toolsUsed && metadata.toolsUsed.length > 0
                ? `<div class="message-tools">🔧 Used: ${metadata.toolsUsed.join(', ')}</div>`
                : '';

            // Performance badge
            let perfBadge = '';
            if (metadata.perfRating) {
                const r = metadata.perfRating;
                perfBadge = `<span class="perf-badge perf-badge-${r.rating}">${r.emoji} ${r.label}</span>`;
            }

            // Routing info (confidence)
            let confidenceBadge = '';
            if (metadata.routing && metadata.routing.classification) {
                const conf = metadata.routing.classification.confidence;
                let confClass = 'low';
                if (conf >= 0.7) confClass = 'high';
                else if (conf >= 0.4) confClass = 'medium';

                confidenceBadge = `<span class="agent-confidence confidence-${confClass}">
                    ${(conf * 100).toFixed(0)}% confident
                </span>`;
            }

            const timeInfo = metadata.executionTime
                ? `<div class="message-time">⏱️ ${metadata.executionTime.toFixed(2)}s${perfBadge}</div>`
                : '';

            messageDiv.innerHTML = `
                <div class="message-header">
                    <img src="img/icchat.png" alt="AI" class="ai-avatar" />
                    <span class="agent-name-label">${metadata.agent || 'AI'}</span>
                    ${confidenceBadge}
                    <span class="message-timestamp">${this.getRelativeTime(Date.now())}</span>
                </div>
                <div class="message-content">
                    <div class="message-text">${this.formatMarkdown(content)}</div>
                    ${toolsInfo}
                    ${timeInfo}
                </div>
                <div class="message-actions">
                    <button class="message-action-btn" onclick="copyMessageText(this)" title="Copy message">
                        📋
                    </button>
                    <button class="message-action-btn" onclick="regenerateResponse(this)" title="Regenerate response">
                        🔄
                    </button>
                    <button class="message-action-btn" onclick="deleteMessage(this)" title="Delete message">
                        🗑️
                    </button>
                </div>
            `;
        } else if (role === 'system') {
            messageDiv.className = 'message system-message';
            messageDiv.innerHTML = `
                <div class="message-content">
                    <div class="message-text">⚠️ ${this.escapeHtml(content)}</div>
                </div>
            `;
        }

        messagesContainer.appendChild(messageDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;

        // Apply syntax highlighting to code blocks
        if (typeof initSyntaxHighlighting === 'function') {
            setTimeout(() => initSyntaxHighlighting(), 100);
        }
    }

    addStreamingMessage(role, content, metadata = {}) {
        const messagesContainer = document.getElementById('messagesContainer');
        if (!messagesContainer) return null;

        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${role}-message streaming`;
        messageDiv.dataset.streaming = 'true';

        if (role === 'assistant') {
            messageDiv.innerHTML = `
                <div class="message-header">
                    <img src="img/icchat.png" alt="AI" class="ai-avatar" />
                    <span class="agent-name-label">${metadata.agent || 'AI'}</span>
                    <span class="streaming-indicator">●</span>
                </div>
                <div class="message-content">
                    <div class="message-text streaming-text"></div>
                </div>
            `;
        }

        messagesContainer.appendChild(messageDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;

        return messageDiv;
    }

    updateStreamingMessage(messageDiv, content) {
        if (!messageDiv) return;

        const textDiv = messageDiv.querySelector('.message-text');
        if (textDiv) {
            textDiv.innerHTML = this.formatMarkdown(content);

            // Apply syntax highlighting
            if (typeof initSyntaxHighlighting === 'function') {
                setTimeout(() => initSyntaxHighlighting(), 50);
            }
        }

        // Auto-scroll to bottom
        const messagesContainer = document.getElementById('messagesContainer');
        if (messagesContainer) {
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
        }
    }

    finalizeStreamingMessage(messageDiv, metadata) {
        if (!messageDiv) return;

        // Remove streaming indicator
        const streamingIndicator = messageDiv.querySelector('.streaming-indicator');
        if (streamingIndicator) {
            streamingIndicator.remove();
        }

        // Remove streaming class
        messageDiv.classList.remove('streaming');
        delete messageDiv.dataset.streaming;

        // Add metadata (tools, time, performance badges)
        const contentDiv = messageDiv.querySelector('.message-content');
        if (!contentDiv) return;

        // Add tools info
        if (metadata.toolsUsed && metadata.toolsUsed.length > 0) {
            const toolsDiv = document.createElement('div');
            toolsDiv.className = 'message-tools';
            toolsDiv.innerHTML = `🔧 Used: ${metadata.toolsUsed.join(', ')}`;
            contentDiv.appendChild(toolsDiv);
        }

        // Add performance info
        if (metadata.executionTime) {
            let perfBadge = '';
            if (metadata.perfRating) {
                const r = metadata.perfRating;
                perfBadge = `<span class="perf-badge perf-badge-${r.rating}">${r.emoji} ${r.label}</span>`;
            }

            const timeDiv = document.createElement('div');
            timeDiv.className = 'message-time';
            timeDiv.innerHTML = `⏱️ ${metadata.executionTime.toFixed(2)}s${perfBadge}`;
            contentDiv.appendChild(timeDiv);
        }

        // Add confidence badge to header
        if (metadata.routing && metadata.routing.classification) {
            const conf = metadata.routing.classification.confidence;
            let confClass = 'low';
            if (conf >= 0.7) confClass = 'high';
            else if (conf >= 0.4) confClass = 'medium';

            const headerDiv = messageDiv.querySelector('.message-header');
            if (headerDiv) {
                const confidenceBadge = document.createElement('span');
                confidenceBadge.className = `agent-confidence confidence-${confClass}`;
                confidenceBadge.textContent = `${(conf * 100).toFixed(0)}% confident`;
                headerDiv.appendChild(confidenceBadge);
            }
        }
    }

    setMode(mode) {
        this.agentMode = mode;

        // Update button states (header buttons)
        document.querySelectorAll('.mode-btn-header').forEach(btn => {
            if (btn.dataset.mode === mode) {
                btn.classList.add('active');
            } else {
                btn.classList.remove('active');
            }
        });

        // Update dropdown
        const select = document.getElementById('agentSelect');
        if (mode === 'auto' && select) {
            select.value = 'auto';
            this.currentAgent = null;
            this.updateAgentDisplay(null, 'Auto-Select');
        }
    }

    updateAgentDisplay(agentType, agentName) {
        const nameEl = document.getElementById('currentAgentName');
        const badgeEl = document.getElementById('currentAgentBadge');

        if (nameEl) nameEl.textContent = agentName || 'Auto-Select';
        if (badgeEl) badgeEl.textContent = this.getAgentBadge(agentType);
    }

    updateSessionDisplay(sessionId) {
        const sessionEl = document.getElementById('currentSessionId');
        if (sessionEl && sessionId) {
            sessionEl.textContent = sessionId.substring(0, 8) + '...';
            sessionEl.title = sessionId;
        }
    }

    showThinking(show) {
        const thinkingEl = document.getElementById('agentThinking');
        if (thinkingEl) {
            thinkingEl.style.display = show ? 'flex' : 'none';
        }
    }

    getAgentBadge(agentType) {
        const badges = {
            'coder': '💻',
            'reasoner': '🧠',
            'researcher': '🔍',
            'executor': '⚡',
            'general': '💬',
            'consultant': '🎓',
            'security': '🔒',
            'vision': '👁️',
            'auto': '⚙️'
        };
        return badges[agentType] || badges['auto'];
    }

    async saveCurrentSession() {
        if (!this.currentSession) {
            alert('No active session to save');
            return;
        }

        const name = prompt('Enter session name:', `Session ${new Date().toLocaleString()}`);
        if (!name) return;

        // TODO: Implement session saving API
        console.log('[MultiAgent] Saving session:', this.currentSession, name);
        alert('Session saved! (Feature in development)');
    }

    async loadSessions() {
        // TODO: Implement session loading
        console.log('[MultiAgent] Loading sessions...');
        const sessionsList = document.getElementById('sessionsList');
        if (sessionsList) {
            sessionsList.innerHTML = '<div class="session-item-empty">Loading sessions...</div>';
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    getRelativeTime(timestamp) {
        const now = Date.now();
        const diff = now - timestamp;
        const seconds = Math.floor(diff / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);
        const days = Math.floor(hours / 24);

        if (seconds < 10) return 'just now';
        if (seconds < 60) return `${seconds}s ago`;
        if (minutes < 60) return `${minutes}m ago`;
        if (hours < 24) return `${hours}h ago`;
        if (days < 7) return `${days}d ago`;

        // For older messages, show date
        const date = new Date(timestamp);
        return date.toLocaleDateString();
    }

    formatMarkdown(text) {
        // Simple markdown formatting
        let formatted = this.escapeHtml(text);

        // Code blocks with copy button
        let codeBlockIndex = 0;
        formatted = formatted.replace(/```(\w+)?\n([\s\S]*?)```/g, (match, lang, code) => {
            const blockId = `code-block-${Date.now()}-${codeBlockIndex++}`;
            const language = lang || 'text';
            const displayLang = language.charAt(0).toUpperCase() + language.slice(1);

            return `<div class="code-block-wrapper">
                <div class="code-block-header">
                    <span class="code-block-language">${displayLang}</span>
                    <button class="code-copy-btn" onclick="copyCodeBlock('${blockId}')" title="Copy code">
                        <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                            <rect x="5" y="5" width="9" height="9" rx="1" stroke="currentColor" stroke-width="1.5" fill="none"/>
                            <path d="M3 11V3C3 2.44772 3.44772 2 4 2H10" stroke="currentColor" stroke-width="1.5"/>
                        </svg>
                        Copy
                    </button>
                </div>
                <pre id="${blockId}"><code class="language-${language}">${code}</code></pre>
            </div>`;
        });

        // Inline code
        formatted = formatted.replace(/`([^`]+)`/g, '<code class="inline-code">$1</code>');

        // Bold
        formatted = formatted.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');

        // Line breaks
        formatted = formatted.replace(/\n/g, '<br>');

        return formatted;
    }

    createAgentSwitcherPanel() {
        // Populate agent cards in the switcher panel
        const cardsContainer = document.getElementById('agentSwitcherCards');
        if (!cardsContainer) return;

        // Agent descriptions for better UX
        const agentDescriptions = {
            'coder': {
                description: 'Expert at writing, debugging, and refactoring code across multiple languages.',
                capabilities: 'Python, JavaScript, Java, C++, debugging, code review'
            },
            'reasoner': {
                description: 'Handles complex reasoning, planning, and problem-solving tasks.',
                capabilities: 'Logic, planning, analysis, decision-making'
            },
            'researcher': {
                description: 'Searches the web and documentation to find information and answer questions.',
                capabilities: 'Web research, documentation lookup, fact-finding'
            },
            'executor': {
                description: 'Executes system commands and performs file operations.',
                capabilities: 'Shell commands, file management, system tasks'
            },
            'general': {
                description: 'Quick responses for simple questions and general conversation.',
                capabilities: 'Q&A, chat, quick tasks'
            },
            'consultant': {
                description: 'Uses external AI APIs (Claude, GPT) for advanced tasks.',
                capabilities: 'External LLMs, advanced reasoning, cloud AI'
            }
        };

        // Create agent cards
        cardsContainer.innerHTML = '';
        this.availableAgents.forEach(agent => {
            const desc = agentDescriptions[agent.type] || {};
            const card = document.createElement('div');
            card.className = 'agent-card';
            card.dataset.agentType = agent.type;
            card.onclick = () => this.selectAgentFromSwitcher(agent.type, agent.name);

            card.innerHTML = `
                <div class="agent-card-header">
                    <div class="agent-card-icon">${this.getAgentBadge(agent.type)}</div>
                    <div class="agent-card-title">${agent.name}</div>
                </div>
                <div class="agent-card-description">${desc.description || 'No description available'}</div>
                <div class="agent-card-capabilities">💡 ${desc.capabilities || agent.capabilities?.join(', ') || ''}</div>
            `;

            cardsContainer.appendChild(card);
        });

        console.log('[MultiAgent] Agent switcher panel populated');
    }

    selectAgentFromSwitcher(agentType, agentName) {
        // Switch to manual mode and select this agent
        this.setMode('manual');
        this.currentAgent = agentType;
        this.updateAgentDisplay(agentType, agentName);

        // Update dropdown to match
        const select = document.getElementById('agentSelect');
        if (select) {
            select.value = agentType;
        }

        // Update active state on cards
        document.querySelectorAll('.agent-card').forEach(card => {
            if (card.dataset.agentType === agentType) {
                card.classList.add('active');
            } else {
                card.classList.remove('active');
            }
        });

        // Close the panel
        const panel = document.getElementById('agentSwitcherPanel');
        if (panel) {
            panel.classList.add('hidden');
        }

        // Show success toast
        if (window.showToast) {
            window.showToast(`Switched to ${agentName}`, 2000, 'success');
        }

        console.log('[MultiAgent] Selected agent from switcher:', agentType);
    }

    setupKeyboardShortcuts() {
        // Global keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            // Don't trigger shortcuts when typing in input fields (except Ctrl+Enter for send)
            const isInputField = e.target.tagName === 'INPUT' ||
                                e.target.tagName === 'TEXTAREA' ||
                                e.target.isContentEditable;

            // Ctrl+A - Toggle agent switcher
            if (e.ctrlKey && e.key === 'a' && !e.shiftKey && !e.altKey && !isInputField) {
                e.preventDefault();
                if (window.toggleAgentSwitcher) {
                    window.toggleAgentSwitcher();
                }
                return;
            }

            // Ctrl+S - Open settings
            if (e.ctrlKey && e.key === 's' && !e.shiftKey && !e.altKey) {
                e.preventDefault();
                if (window.toggleSettings) {
                    window.toggleSettings();
                }
                return;
            }

            // Ctrl+N - New chat
            if (e.ctrlKey && e.key === 'n' && !e.shiftKey && !e.altKey) {
                e.preventDefault();
                if (window.newChat) {
                    window.newChat();
                }
                return;
            }

            // Ctrl+/ - Show keyboard shortcuts help
            if (e.ctrlKey && e.key === '/' && !e.shiftKey && !e.altKey) {
                e.preventDefault();
                if (window.showKeyboardShortcuts) {
                    window.showKeyboardShortcuts();
                }
                return;
            }

            // Ctrl+Enter - Send message
            if (e.ctrlKey && e.key === 'Enter' && isInputField) {
                e.preventDefault();
                if (window.sendMessage) {
                    window.sendMessage();
                }
                return;
            }

            // Ctrl+K - Clear input
            if (e.ctrlKey && e.key === 'k' && !e.shiftKey && !e.altKey && isInputField) {
                e.preventDefault();
                const messageInput = document.getElementById('messageInput');
                if (messageInput) {
                    messageInput.value = '';
                    messageInput.focus();
                }
                return;
            }

            // Ctrl+L - Clear chat
            if (e.ctrlKey && e.key === 'l' && !e.shiftKey && !e.altKey && !isInputField) {
                e.preventDefault();
                if (window.clearChat) {
                    window.clearChat();
                }
                return;
            }

            // Ctrl+I - Generate image
            if (e.ctrlKey && e.key === 'i' && !e.shiftKey && !e.altKey && !isInputField) {
                e.preventDefault();
                if (window.showImageModal) {
                    window.showImageModal();
                }
                return;
            }

            // Ctrl+F - File explorer
            if (e.ctrlKey && e.key === 'f' && !e.shiftKey && !e.altKey && !isInputField) {
                e.preventDefault();
                if (window.showFilesPanel) {
                    window.showFilesPanel();
                }
                return;
            }

            // Esc - Close modals/panels
            if (e.key === 'Escape') {
                // Close agent switcher
                const agentPanel = document.getElementById('agentSwitcherPanel');
                if (agentPanel && !agentPanel.classList.contains('hidden')) {
                    agentPanel.classList.add('hidden');
                    return;
                }

                // Close keyboard shortcuts modal
                const shortcutsModal = document.getElementById('keyboardShortcutsModal');
                if (shortcutsModal && !shortcutsModal.classList.contains('hidden')) {
                    if (window.hideKeyboardShortcuts) {
                        window.hideKeyboardShortcuts();
                    }
                    return;
                }

                // Close settings
                const settings = document.getElementById('settingsOverlay');
                if (settings && !settings.classList.contains('hidden')) {
                    if (window.toggleSettings) {
                        window.toggleSettings();
                    }
                    return;
                }
            }
        });

        console.log('[MultiAgent] Keyboard shortcuts registered');
    }
}

// Initialize on DOM ready
let multiAgentUI;
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        multiAgentUI = new MultiAgentUI();
        window.multiAgentUI = multiAgentUI;
    });
} else {
    multiAgentUI = new MultiAgentUI();
    window.multiAgentUI = multiAgentUI;
}
