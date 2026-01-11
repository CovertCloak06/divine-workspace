/**
 * Agent Collaboration Theater Plugin
 * Visualize agents working together in real-time
 */

import { PluginBase } from '../../js/plugin-base.js';

export class CollaborationTheaterPlugin extends PluginBase {
    constructor(manifest) {
        super(manifest);
        this.activeAgents = new Map();
        this.collaborationLog = [];
        this.isTheaterOpen = false;
    }

    async init() {
        await super.init();

        const defaults = {
            autoShow: true,
            showThoughts: true,
            animationSpeed: 'normal'
        };
        this.loadSettings({ ...defaults, ...this.getSettings() });

        this.injectCSS(this.getCSS());
    }

    async enable() {
        await super.enable();

        // Add theater button to sidebar
        this.addTheaterButton();

        // Subscribe to agent events
        this.subscribe('agent:thinking', (data) => this.onAgentThinking(data));
        this.subscribe('agent:response', (data) => this.onAgentResponse(data));
        this.subscribe('agent:collaboration', (data) => this.onAgentCollaboration(data));

        // Auto-show for multi-agent tasks
        this.subscribe('message:sent', (data) => this.checkMultiAgent(data));

        // Make globally available
        window.collaborationTheater = this;

        console.log(`[${this.name}] Collaboration Theater active`);
    }

    async disable() {
        await super.disable();
        this.removeTheaterButton();
        this.hideTheater();
    }

    /**
     * Add theater button to sidebar
     */
    addTheaterButton() {
        const sidebar = document.querySelector('.sidebar');
        if (!sidebar) return;

        const button = document.createElement('div');
        button.className = 'sidebar-section-header clickable';
        button.id = 'theaterBtn';
        button.innerHTML = '<span>🎭 Collaboration Theater</span>';
        button.onclick = () => this.showTheater();

        // Insert after Multi-Agent section
        const multiAgentSection = document.querySelector('.sidebar-section-header[onclick*="openMultiAgent"]');
        if (multiAgentSection) {
            multiAgentSection.parentNode.insertBefore(button, multiAgentSection.nextSibling);
        }
    }

    /**
     * Remove theater button
     */
    removeTheaterButton() {
        const button = document.getElementById('theaterBtn');
        if (button) button.remove();
    }

    /**
     * Show theater
     */
    showTheater() {
        if (this.isTheaterOpen) return;

        this.hideTheater(); // Clean up existing

        const theater = document.createElement('div');
        theater.id = 'collaborationTheater';
        theater.className = 'collaboration-theater';

        let html = `
            <div class="theater-header">
                <div class="theater-title">🎭 Agent Collaboration Theater</div>
                <button class="theater-close" onclick="window.collaborationTheater.hideTheater()">×</button>
            </div>
            <div class="theater-stage">
                <div class="stage-floor"></div>
                <div class="stage-agents" id="theaterAgents">
        `;

        // Add agent avatars
        const agents = ['coder', 'reasoner', 'researcher', 'executor', 'general', 'security'];
        agents.forEach(agentName => {
            const isActive = this.activeAgents.has(agentName);
            html += this.renderAgent(agentName, isActive);
        });

        html += `
                </div>
                <div class="stage-thoughts" id="theaterThoughts"></div>
            </div>
            <div class="theater-log" id="theaterLog">
                <div class="log-header">Collaboration Log</div>
                <div class="log-content" id="theaterLogContent">
                    ${this.renderLog()}
                </div>
            </div>
        `;

        theater.innerHTML = html;
        document.body.appendChild(theater);

        this.isTheaterOpen = true;
        setTimeout(() => theater.classList.add('visible'), 10);
    }

    /**
     * Hide theater
     */
    hideTheater() {
        const theater = document.getElementById('collaborationTheater');
        if (theater) {
            theater.classList.remove('visible');
            setTimeout(() => {
                theater.remove();
                this.isTheaterOpen = false;
            }, 300);
        }
    }

    /**
     * Render agent avatar
     */
    renderAgent(agentName, isActive = false) {
        const icons = {
            coder: '💻',
            reasoner: '🧠',
            researcher: '🔍',
            executor: '⚙️',
            general: '🤖',
            security: '🔒'
        };

        const colors = {
            coder: '#00ff00',
            reasoner: '#00ffff',
            researcher: '#ffff00',
            executor: '#ff00ff',
            general: '#ffffff',
            security: '#ff0000'
        };

        const activeClass = isActive ? 'active' : '';

        return `
            <div class="agent-avatar ${activeClass}" id="agent-${agentName}" data-agent="${agentName}">
                <div class="agent-icon" style="color: ${colors[agentName]}">${icons[agentName]}</div>
                <div class="agent-name">${agentName.toUpperCase()}</div>
                <div class="agent-status" id="status-${agentName}">Idle</div>
            </div>
        `;
    }

    /**
     * Render collaboration log
     */
    renderLog() {
        if (this.collaborationLog.length === 0) {
            return '<div class="log-empty">No collaboration activity yet...</div>';
        }

        let html = '';
        this.collaborationLog.slice(-10).forEach(entry => {
            html += `
                <div class="log-entry">
                    <span class="log-time">[${entry.time}]</span>
                    <span class="log-agent">${entry.agent.toUpperCase()}</span>
                    <span class="log-message">${entry.message}</span>
                </div>
            `;
        });

        return html;
    }

    /**
     * Update log
     */
    updateLog(agent, message) {
        const entry = {
            time: new Date().toLocaleTimeString(),
            agent,
            message
        };

        this.collaborationLog.push(entry);

        // Update UI if theater is open
        if (this.isTheaterOpen) {
            const logContent = document.getElementById('theaterLogContent');
            if (logContent) {
                logContent.innerHTML = this.renderLog();
                logContent.scrollTop = logContent.scrollHeight;
            }
        }
    }

    /**
     * Agent thinking event
     */
    onAgentThinking(data) {
        const agent = data.agent || 'general';

        this.activeAgents.set(agent, {
            status: 'thinking',
            task: data.task || 'Processing...'
        });

        this.updateLog(agent, 'Started thinking...');

        if (this.isTheaterOpen) {
            this.updateAgentUI(agent, 'thinking', data.task);

            if (this.getSetting('showThoughts', true)) {
                this.showThoughtBubble(agent, data.task || 'Hmm...');
            }
        }
    }

    /**
     * Agent response event
     */
    onAgentResponse(data) {
        const agent = data.agent || 'general';

        this.activeAgents.set(agent, {
            status: 'done',
            result: data.result || 'Complete'
        });

        this.updateLog(agent, 'Completed task');

        if (this.isTheaterOpen) {
            this.updateAgentUI(agent, 'done', 'Task complete!');
            this.hideThoughtBubble(agent);

            // Clear after delay
            setTimeout(() => {
                this.activeAgents.delete(agent);
                if (this.isTheaterOpen) {
                    this.updateAgentUI(agent, 'idle', 'Ready');
                }
            }, 3000);
        }
    }

    /**
     * Agent collaboration event
     */
    onAgentCollaboration(data) {
        const fromAgent = data.from || 'unknown';
        const toAgent = data.to || 'unknown';
        const message = data.message || 'Passing data';

        this.updateLog(fromAgent, `→ ${toAgent.toUpperCase()}: ${message}`);

        if (this.isTheaterOpen) {
            this.showCollaborationBeam(fromAgent, toAgent);
        }
    }

    /**
     * Update agent UI
     */
    updateAgentUI(agentName, status, message) {
        const avatar = document.getElementById(`agent-${agentName}`);
        const statusEl = document.getElementById(`status-${agentName}`);

        if (!avatar || !statusEl) return;

        // Update status
        statusEl.textContent = message;

        // Update classes
        avatar.classList.remove('active', 'thinking', 'done');
        if (status !== 'idle') {
            avatar.classList.add('active');
            if (status === 'thinking') avatar.classList.add('thinking');
            if (status === 'done') avatar.classList.add('done');
        }
    }

    /**
     * Show thought bubble
     */
    showThoughtBubble(agentName, thought) {
        const thoughtsContainer = document.getElementById('theaterThoughts');
        if (!thoughtsContainer) return;

        // Remove existing bubble for this agent
        this.hideThoughtBubble(agentName);

        const bubble = document.createElement('div');
        bubble.className = 'thought-bubble';
        bubble.id = `thought-${agentName}`;
        bubble.setAttribute('data-agent', agentName);
        bubble.textContent = thought;

        thoughtsContainer.appendChild(bubble);

        // Position near agent
        this.positionThoughtBubble(agentName);

        setTimeout(() => bubble.classList.add('visible'), 10);
    }

    /**
     * Hide thought bubble
     */
    hideThoughtBubble(agentName) {
        const bubble = document.getElementById(`thought-${agentName}`);
        if (bubble) {
            bubble.classList.remove('visible');
            setTimeout(() => bubble.remove(), 300);
        }
    }

    /**
     * Position thought bubble near agent
     */
    positionThoughtBubble(agentName) {
        const avatar = document.getElementById(`agent-${agentName}`);
        const bubble = document.getElementById(`thought-${agentName}`);

        if (!avatar || !bubble) return;

        const rect = avatar.getBoundingClientRect();
        const containerRect = avatar.parentElement.getBoundingClientRect();

        bubble.style.left = `${rect.left - containerRect.left}px`;
        bubble.style.top = `${rect.top - containerRect.top - 80}px`;
    }

    /**
     * Show collaboration beam between agents
     */
    showCollaborationBeam(fromAgent, toAgent) {
        const fromEl = document.getElementById(`agent-${fromAgent}`);
        const toEl = document.getElementById(`agent-${toAgent}`);

        if (!fromEl || !toEl) return;

        const beam = document.createElement('div');
        beam.className = 'collaboration-beam';

        const fromRect = fromEl.getBoundingClientRect();
        const toRect = toEl.getBoundingClientRect();
        const containerRect = fromEl.parentElement.getBoundingClientRect();

        const fromX = fromRect.left - containerRect.left + fromRect.width / 2;
        const fromY = fromRect.top - containerRect.top + fromRect.height / 2;
        const toX = toRect.left - containerRect.left + toRect.width / 2;
        const toY = toRect.top - containerRect.top + toRect.height / 2;

        const angle = Math.atan2(toY - fromY, toX - fromX);
        const length = Math.sqrt(Math.pow(toX - fromX, 2) + Math.pow(toY - fromY, 2));

        beam.style.left = `${fromX}px`;
        beam.style.top = `${fromY}px`;
        beam.style.width = `${length}px`;
        beam.style.transform = `rotate(${angle}rad)`;

        fromEl.parentElement.appendChild(beam);

        setTimeout(() => beam.classList.add('visible'), 10);

        setTimeout(() => {
            beam.classList.remove('visible');
            setTimeout(() => beam.remove(), 500);
        }, 1000);
    }

    /**
     * Check if multi-agent task
     */
    checkMultiAgent(data) {
        // If multiple agents will be involved, auto-show theater
        if (this.getSetting('autoShow', true)) {
            const message = data.message || '';
            const hasMultipleKeywords = (message.match(/\b(and|then|also|plus)\b/gi) || []).length > 1;

            if (hasMultipleKeywords && !this.isTheaterOpen) {
                setTimeout(() => this.showTheater(), 500);
            }
        }
    }

    getCSS() {
        const animSpeed = this.getSetting('animationSpeed', 'normal');
        const animDuration = animSpeed === 'slow' ? '2s' : animSpeed === 'fast' ? '0.5s' : '1s';

        return `
            .collaboration-theater {
                position: fixed;
                bottom: 0;
                left: 0;
                right: 0;
                height: 400px;
                background: rgba(0, 10, 10, 0.98);
                border-top: 2px solid var(--theme-primary);
                z-index: 10002;
                display: flex;
                flex-direction: column;
                opacity: 0;
                transform: translateY(100%);
                transition: all 0.3s ease;
                box-shadow: 0 -4px 32px rgba(0, 255, 255, 0.3);
            }
            .collaboration-theater.visible {
                opacity: 1;
                transform: translateY(0);
            }
            .theater-header {
                padding: 12px 20px;
                border-bottom: 1px solid rgba(0, 255, 255, 0.2);
                display: flex;
                justify-content: space-between;
                align-items: center;
                background: rgba(0, 255, 255, 0.05);
            }
            .theater-title {
                color: var(--theme-primary);
                font-size: 16px;
                font-weight: 700;
            }
            .theater-close {
                background: transparent;
                border: none;
                color: var(--theme-primary);
                font-size: 28px;
                cursor: pointer;
                width: 28px;
                height: 28px;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .theater-close:hover {
                background: rgba(0, 255, 255, 0.1);
                border-radius: 4px;
            }
            .theater-stage {
                flex: 1;
                position: relative;
                background: linear-gradient(to bottom, rgba(0, 20, 40, 0.5), rgba(0, 10, 20, 0.8));
                overflow: hidden;
            }
            .stage-floor {
                position: absolute;
                bottom: 0;
                left: 0;
                right: 0;
                height: 2px;
                background: var(--theme-primary);
                box-shadow: 0 0 10px var(--theme-primary);
            }
            .stage-agents {
                position: absolute;
                bottom: 20px;
                left: 50%;
                transform: translateX(-50%);
                display: flex;
                gap: 40px;
                padding: 20px;
            }
            .agent-avatar {
                display: flex;
                flex-direction: column;
                align-items: center;
                gap: 6px;
                opacity: 0.4;
                transition: all ${animDuration};
            }
            .agent-avatar.active {
                opacity: 1;
                transform: scale(1.1);
            }
            .agent-avatar.thinking {
                animation: think ${animDuration} ease-in-out infinite;
            }
            .agent-avatar.done {
                animation: celebrate 0.5s ease-out;
            }
            @keyframes think {
                0%, 100% { transform: scale(1.1) translateY(0); }
                50% { transform: scale(1.1) translateY(-10px); }
            }
            @keyframes celebrate {
                0%, 100% { transform: scale(1.1) rotate(0deg); }
                25% { transform: scale(1.2) rotate(-5deg); }
                75% { transform: scale(1.2) rotate(5deg); }
            }
            .agent-icon {
                font-size: 48px;
                filter: drop-shadow(0 0 10px currentColor);
            }
            .agent-name {
                color: var(--theme-primary);
                font-size: 10px;
                font-weight: 700;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
            .agent-status {
                color: #888;
                font-size: 9px;
                font-style: italic;
            }
            .stage-thoughts {
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                pointer-events: none;
            }
            .thought-bubble {
                position: absolute;
                background: rgba(255, 255, 255, 0.95);
                color: #000;
                padding: 8px 12px;
                border-radius: 12px;
                font-size: 11px;
                max-width: 150px;
                opacity: 0;
                transform: scale(0.5);
                transition: all 0.3s ease;
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);
            }
            .thought-bubble.visible {
                opacity: 1;
                transform: scale(1);
            }
            .thought-bubble::after {
                content: '';
                position: absolute;
                bottom: -10px;
                left: 50%;
                transform: translateX(-50%);
                width: 0;
                height: 0;
                border-left: 10px solid transparent;
                border-right: 10px solid transparent;
                border-top: 10px solid rgba(255, 255, 255, 0.95);
            }
            .collaboration-beam {
                position: absolute;
                height: 3px;
                background: linear-gradient(90deg, var(--theme-primary), transparent);
                transform-origin: left center;
                opacity: 0;
                transition: opacity 0.5s;
                pointer-events: none;
                box-shadow: 0 0 10px var(--theme-primary);
            }
            .collaboration-beam.visible {
                opacity: 1;
            }
            .theater-log {
                height: 100px;
                border-top: 1px solid rgba(0, 255, 255, 0.2);
                background: rgba(0, 0, 0, 0.5);
                display: flex;
                flex-direction: column;
            }
            .log-header {
                padding: 6px 12px;
                background: rgba(0, 255, 255, 0.05);
                color: var(--theme-primary);
                font-size: 11px;
                font-weight: 700;
                border-bottom: 1px solid rgba(0, 255, 255, 0.1);
            }
            .log-content {
                flex: 1;
                overflow-y: auto;
                padding: 8px 12px;
                font-family: 'Courier New', monospace;
                font-size: 10px;
            }
            .log-empty {
                color: #666;
                font-style: italic;
            }
            .log-entry {
                color: #ddd;
                margin-bottom: 4px;
                line-height: 1.4;
            }
            .log-time {
                color: #666;
            }
            .log-agent {
                color: var(--theme-primary);
                font-weight: 700;
            }
            .log-message {
                color: #aaa;
            }
        `;
    }
}

export default CollaborationTheaterPlugin;
