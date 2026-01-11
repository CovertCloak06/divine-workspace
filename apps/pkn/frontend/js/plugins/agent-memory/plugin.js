/**
 * Agent Memory Visualization Plugin
 * Track and visualize what agents know about you
 */

import { PluginBase } from '../../features/plugin-base.js';

export class AgentMemoryPlugin extends PluginBase {
    constructor(manifest) {
        super(manifest);
        this.memories = {
            coder: [],
            reasoner: [],
            researcher: [],
            executor: [],
            general: [],
            security: []
        };
    }

    async init() {
        await super.init();

        const defaults = { maxMemories: 50 };
        this.loadSettings({ ...defaults, ...this.getSettings() });

        // Load memories from storage
        this.loadMemories();

        this.injectCSS(this.getCSS());
    }

    async enable() {
        await super.enable();

        // Add button to sidebar
        this.addMemoryButton();

        // Subscribe to message events to extract memories
        this.subscribe('message:sent', (data) => this.extractMemories(data));

        // Make globally available
        window.agentMemory = this;

        console.log(`[${this.name}] Memory tracking active`);
    }

    async disable() {
        await super.disable();
        this.removeMemoryButton();
    }

    /**
     * Add memory button to sidebar
     */
    addMemoryButton() {
        const sidebar = document.querySelector('.sidebar');
        if (!sidebar) return;

        const button = document.createElement('div');
        button.className = 'sidebar-section-header clickable';
        button.id = 'agentMemoryBtn';
        button.innerHTML = '<span>Agent Memory</span>';
        button.onclick = () => this.showMemoryPanel();

        // Insert after AI Models
        const aiModelsSection = document.querySelector('.sidebar-section-header[onclick*="openAIModelsManager"]');
        if (aiModelsSection) {
            aiModelsSection.parentNode.insertBefore(button, aiModelsSection.nextSibling);
        }
    }

    /**
     * Remove memory button
     */
    removeMemoryButton() {
        const button = document.getElementById('agentMemoryBtn');
        if (button) button.remove();
        this.hideMemoryPanel();
    }

    /**
     * Show memory panel
     */
    showMemoryPanel() {
        // Remove existing panel
        this.hideMemoryPanel();

        const panel = document.createElement('div');
        panel.id = 'agentMemoryPanel';
        panel.className = 'agent-memory-panel';

        let html = `
            <div class="memory-panel-header">
                <div class="memory-panel-title">Agent Memory</div>
                <button class="memory-panel-close" onclick="window.agentMemory.hideMemoryPanel()">×</button>
            </div>
            <div class="memory-panel-body">
        `;

        // Show memories for each agent
        Object.keys(this.memories).forEach(agent => {
            const agentMemories = this.memories[agent];
            const count = agentMemories.length;

            html += `
                <div class="memory-agent-section">
                    <div class="memory-agent-header">
                        <span class="memory-agent-name">${agent.toUpperCase()}</span>
                        <span class="memory-count">${count} ${count === 1 ? 'memory' : 'memories'}</span>
                    </div>
                    <div class="memory-list">
            `;

            if (agentMemories.length === 0) {
                html += '<div class="memory-empty">No memories yet</div>';
            } else {
                agentMemories.slice(-10).reverse().forEach((memory, idx) => {
                    html += `
                        <div class="memory-item">
                            <div class="memory-text">${memory.text}</div>
                            <div class="memory-meta">
                                <span>${memory.date}</span>
                                <button class="memory-delete" onclick="window.agentMemory.deleteMemory('${agent}', ${agentMemories.length - 1 - idx})">🗑️</button>
                            </div>
                        </div>
                    `;
                });
            }

            html += `
                    </div>
                    <button class="memory-add-btn" onclick="window.agentMemory.addManualMemory('${agent}')">
                        + Add Memory
                    </button>
                </div>
            `;
        });

        html += `
            </div>
            <div class="memory-panel-footer">
                <button class="memory-footer-btn" onclick="window.agentMemory.clearAllMemories()">
                    Clear All
                </button>
                <button class="memory-footer-btn" onclick="window.agentMemory.exportMemories()">
                    Export
                </button>
            </div>
        `;

        panel.innerHTML = html;
        document.body.appendChild(panel);

        setTimeout(() => panel.classList.add('visible'), 10);
    }

    /**
     * Hide memory panel
     */
    hideMemoryPanel() {
        const panel = document.getElementById('agentMemoryPanel');
        if (panel) {
            panel.classList.remove('visible');
            setTimeout(() => panel.remove(), 300);
        }
    }

    /**
     * Extract memories from conversation
     */
    extractMemories(data) {
        // Simple extraction - look for "I" statements indicating user preferences
        const text = data.message || data.content || '';
        const lowerText = text.toLowerCase();

        // Extract preferences
        const patterns = [
            /i (prefer|like|love|use|work with) (.+)/i,
            /i (don't|dont|hate|dislike) (.+)/i,
            /my (.+) is (.+)/i,
            /i am (.+)/i,
            /i'm (.+)/i
        ];

        patterns.forEach(pattern => {
            const match = text.match(pattern);
            if (match) {
                const agent = data.agent || 'general';
                this.addMemory(agent, match[0], 'preference');
            }
        });
    }

    /**
     * Add memory
     */
    addMemory(agent, text, type = 'fact') {
        if (!this.memories[agent]) this.memories[agent] = [];

        const memory = {
            text,
            type,
            date: new Date().toLocaleDateString(),
            timestamp: Date.now()
        };

        this.memories[agent].push(memory);

        // Trim if exceeds max
        const max = this.getSetting('maxMemories', 50);
        if (this.memories[agent].length > max) {
            this.memories[agent] = this.memories[agent].slice(-max);
        }

        this.saveMemories();
    }

    /**
     * Add manual memory
     */
    addManualMemory(agent) {
        const text = prompt('Enter a memory for ' + agent.toUpperCase() + ' agent:');
        if (text && text.trim()) {
            this.addMemory(agent, text.trim(), 'manual');
            this.showMemoryPanel(); // Refresh panel
            this.showToast('Memory added', 2000, 'success');
        }
    }

    /**
     * Delete memory
     */
    deleteMemory(agent, index) {
        if (this.memories[agent] && this.memories[agent][index]) {
            this.memories[agent].splice(index, 1);
            this.saveMemories();
            this.showMemoryPanel(); // Refresh panel
            this.showToast('Memory deleted', 2000, 'success');
        }
    }

    /**
     * Clear all memories
     */
    clearAllMemories() {
        if (confirm('Clear all agent memories? This cannot be undone.')) {
            Object.keys(this.memories).forEach(agent => {
                this.memories[agent] = [];
            });
            this.saveMemories();
            this.showMemoryPanel(); // Refresh panel
            this.showToast('All memories cleared', 2000, 'success');
        }
    }

    /**
     * Export memories
     */
    exportMemories() {
        const data = JSON.stringify(this.memories, null, 2);
        const blob = new Blob([data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `agent-memories-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
        this.showToast('Memories exported', 2000, 'success');
    }

    /**
     * Load memories from storage
     */
    loadMemories() {
        try {
            const saved = localStorage.getItem('pkn_agent_memories');
            if (saved) {
                this.memories = JSON.parse(saved);
            }
        } catch (error) {
            console.error(`[${this.name}] Error loading memories:`, error);
        }
    }

    /**
     * Save memories to storage
     */
    saveMemories() {
        try {
            localStorage.setItem('pkn_agent_memories', JSON.stringify(this.memories));
        } catch (error) {
            console.error(`[${this.name}] Error saving memories:`, error);
        }
    }

    getCSS() {
        return `
            .agent-memory-panel {
                position: fixed;
                top: 0;
                right: 0;
                width: 500px;
                height: 100vh;
                background: rgba(0, 20, 20, 0.98);
                border-left: 1px solid var(--theme-primary);
                z-index: 10003;
                display: flex;
                flex-direction: column;
                opacity: 0;
                transform: translateX(100%);
                transition: all 0.3s ease;
                box-shadow: -4px 0 32px rgba(0, 255, 255, 0.2);
            }
            .agent-memory-panel.visible {
                opacity: 1;
                transform: translateX(0);
            }
            .memory-panel-header {
                padding: 20px;
                border-bottom: 1px solid rgba(0, 255, 255, 0.2);
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .memory-panel-title {
                color: var(--theme-primary);
                font-size: 18px;
                font-weight: 700;
            }
            .memory-panel-close {
                background: transparent;
                border: none;
                color: var(--theme-primary);
                font-size: 32px;
                cursor: pointer;
                padding: 0;
                width: 32px;
                height: 32px;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .memory-panel-close:hover {
                background: rgba(0, 255, 255, 0.1);
                border-radius: 4px;
            }
            .memory-panel-body {
                flex: 1;
                overflow-y: auto;
                padding: 16px;
            }
            .memory-agent-section {
                margin-bottom: 24px;
                background: rgba(0, 255, 255, 0.03);
                border: 1px solid rgba(0, 255, 255, 0.1);
                border-radius: 8px;
                padding: 12px;
            }
            .memory-agent-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 12px;
                padding-bottom: 8px;
                border-bottom: 1px solid rgba(0, 255, 255, 0.1);
            }
            .memory-agent-name {
                color: var(--theme-primary);
                font-size: 14px;
                font-weight: 700;
            }
            .memory-count {
                color: #888;
                font-size: 12px;
            }
            .memory-list {
                margin-bottom: 12px;
            }
            .memory-item {
                background: rgba(0, 0, 0, 0.3);
                border: 1px solid rgba(0, 255, 255, 0.1);
                border-radius: 6px;
                padding: 10px;
                margin-bottom: 8px;
            }
            .memory-text {
                color: #fff;
                font-size: 13px;
                margin-bottom: 6px;
            }
            .memory-meta {
                display: flex;
                justify-content: space-between;
                align-items: center;
                color: #666;
                font-size: 11px;
            }
            .memory-delete {
                background: transparent;
                border: none;
                cursor: pointer;
                font-size: 14px;
                opacity: 0.6;
                transition: opacity 0.2s;
            }
            .memory-delete:hover {
                opacity: 1;
            }
            .memory-empty {
                color: #666;
                font-size: 12px;
                font-style: italic;
                padding: 12px;
                text-align: center;
            }
            .memory-add-btn {
                width: 100%;
                padding: 8px;
                background: rgba(0, 255, 255, 0.1);
                border: 1px solid rgba(0, 255, 255, 0.3);
                border-radius: 6px;
                color: var(--theme-primary);
                font-size: 12px;
                cursor: pointer;
                transition: all 0.2s;
            }
            .memory-add-btn:hover {
                background: rgba(0, 255, 255, 0.2);
                border-color: var(--theme-primary);
            }
            .memory-panel-footer {
                padding: 16px;
                border-top: 1px solid rgba(0, 255, 255, 0.2);
                display: flex;
                gap: 12px;
            }
            .memory-footer-btn {
                flex: 1;
                padding: 10px;
                background: rgba(0, 255, 255, 0.1);
                border: 1px solid rgba(0, 255, 255, 0.3);
                border-radius: 6px;
                color: var(--theme-primary);
                font-size: 13px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.2s;
            }
            .memory-footer-btn:hover {
                background: rgba(0, 255, 255, 0.2);
                border-color: var(--theme-primary);
            }
        `;
    }
}

export default AgentMemoryPlugin;
