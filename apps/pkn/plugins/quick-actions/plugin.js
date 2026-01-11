/**
 * Quick Actions & Macros Plugin
 * Pre-built workflows and custom macros for common multi-agent tasks
 */

import { PluginBase } from '../../js/plugin-base.js';

export class QuickActionsPlugin extends PluginBase {
    constructor(manifest) {
        super(manifest);
        this.builtInActions = this.getBuiltInActions();
        this.customMacros = [];
    }

    async init() {
        await super.init();

        const defaults = { showButton: true };
        this.loadSettings({ ...defaults, ...this.getSettings() });

        // Load custom macros from storage
        this.loadCustomMacros();

        this.injectCSS(this.getCSS());
    }

    async enable() {
        await super.enable();

        if (this.getSetting('showButton', true)) {
            this.addQuickActionsButton();
        }

        // Make globally available
        window.quickActions = this;

        console.log(`[${this.name}] Quick Actions ready`);
    }

    async disable() {
        await super.disable();
        this.removeQuickActionsButton();
    }

    /**
     * Get built-in actions
     */
    getBuiltInActions() {
        return [
            {
                id: 'debug-code',
                name: '🐛 Debug This Code',
                description: 'Analyze code → Find issues → Suggest fixes',
                steps: [
                    { agent: 'coder', prompt: 'Analyze this code and identify any bugs or issues: {input}' },
                    { agent: 'reasoner', prompt: 'Based on the code analysis, what are the root causes of these issues?' },
                    { agent: 'coder', prompt: 'Provide fixed code with explanations' }
                ]
            },
            {
                id: 'research-summarize',
                name: '📚 Research & Summarize',
                description: 'Research topic → Gather info → Create summary',
                steps: [
                    { agent: 'researcher', prompt: 'Research this topic: {input}' },
                    { agent: 'general', prompt: 'Summarize the research in 3-5 bullet points' }
                ]
            },
            {
                id: 'security-audit',
                name: '🔒 Security Audit',
                description: 'Scan code → Find vulnerabilities → Recommend fixes',
                steps: [
                    { agent: 'security', prompt: 'Perform security audit on this code: {input}' },
                    { agent: 'coder', prompt: 'Show secure code examples fixing the vulnerabilities found' }
                ]
            },
            {
                id: 'explain-code',
                name: '💡 Explain Code',
                description: 'Analyze → Break down → Explain simply',
                steps: [
                    { agent: 'coder', prompt: 'Analyze this code structure: {input}' },
                    { agent: 'general', prompt: 'Explain this code in simple terms for beginners' }
                ]
            },
            {
                id: 'optimize-performance',
                name: '⚡ Optimize Performance',
                description: 'Analyze performance → Find bottlenecks → Optimize',
                steps: [
                    { agent: 'coder', prompt: 'Analyze performance issues in this code: {input}' },
                    { agent: 'reasoner', prompt: 'What are the optimization priorities?' },
                    { agent: 'coder', prompt: 'Provide optimized code with benchmarks' }
                ]
            },
            {
                id: 'write-tests',
                name: '🧪 Generate Tests',
                description: 'Analyze code → Design test cases → Write tests',
                steps: [
                    { agent: 'coder', prompt: 'Analyze this code and identify what needs testing: {input}' },
                    { agent: 'coder', prompt: 'Write comprehensive unit tests for this code' }
                ]
            }
        ];
    }

    /**
     * Add Quick Actions button to UI
     */
    addQuickActionsButton() {
        const inputRow = document.querySelector('.input-row');
        if (!inputRow || document.getElementById('quickActionsBtn')) return;

        const button = document.createElement('button');
        button.id = 'quickActionsBtn';
        button.className = 'quick-actions-btn';
        button.title = 'Quick Actions';
        button.innerHTML = '🚀';
        button.onclick = () => this.showActionsMenu();

        const sendBtn = document.getElementById('sendBtn');
        if (sendBtn) {
            // Insert AFTER send button instead of before
            sendBtn.parentNode.insertBefore(button, sendBtn.nextSibling);
        }
    }

    /**
     * Remove Quick Actions button
     */
    removeQuickActionsButton() {
        const button = document.getElementById('quickActionsBtn');
        if (button) button.remove();
        this.hideActionsMenu();
    }

    /**
     * Show actions menu
     */
    showActionsMenu() {
        // Remove existing menu
        this.hideActionsMenu();

        const menu = document.createElement('div');
        menu.id = 'quickActionsMenu';
        menu.className = 'quick-actions-menu';

        let html = '<div class="quick-actions-header">Quick Actions</div>';
        html += '<div class="quick-actions-list">';

        // Built-in actions
        this.builtInActions.forEach(action => {
            html += `
                <div class="quick-action-item" onclick="window.quickActions.executeAction('${action.id}')">
                    <div class="action-name">${action.name}</div>
                    <div class="action-description">${action.description}</div>
                </div>
            `;
        });

        // Custom macros
        if (this.customMacros.length > 0) {
            html += '<div class="actions-divider">Custom Macros</div>';
            this.customMacros.forEach(macro => {
                html += `
                    <div class="quick-action-item custom" onclick="window.quickActions.executeMacro('${macro.id}')">
                        <div class="action-name">${macro.name}</div>
                        <div class="action-description">${macro.description}</div>
                    </div>
                `;
            });
        }

        html += '</div>';
        html += `
            <div class="quick-actions-footer">
                <button class="action-footer-btn" onclick="window.quickActions.openMacroBuilder()">
                    + Create Macro
                </button>
                <button class="action-footer-btn" onclick="window.quickActions.hideActionsMenu()">
                    Close
                </button>
            </div>
        `;

        menu.innerHTML = html;
        document.body.appendChild(menu);

        // Animate in
        setTimeout(() => menu.classList.add('visible'), 10);

        // Close on outside click
        setTimeout(() => {
            document.addEventListener('click', this.closeMenuOnOutsideClick);
        }, 100);
    }

    /**
     * Hide actions menu
     */
    hideActionsMenu() {
        const menu = document.getElementById('quickActionsMenu');
        if (menu) {
            menu.classList.remove('visible');
            setTimeout(() => menu.remove(), 300);
        }
        document.removeEventListener('click', this.closeMenuOnOutsideClick);
    }

    /**
     * Close menu on outside click
     */
    closeMenuOnOutsideClick = (e) => {
        const menu = document.getElementById('quickActionsMenu');
        const button = document.getElementById('quickActionsBtn');
        if (menu && !menu.contains(e.target) && e.target !== button) {
            this.hideActionsMenu();
        }
    }

    /**
     * Execute a quick action
     */
    async executeAction(actionId) {
        const action = this.builtInActions.find(a => a.id === actionId);
        if (!action) return;

        this.hideActionsMenu();

        // Get user input
        const messageInput = document.getElementById('messageInput');
        const userInput = messageInput ? messageInput.value : '';

        if (!userInput && action.steps.some(s => s.prompt.includes('{input}'))) {
            this.showToast('Please enter some text first', 3000, 'error');
            return;
        }

        // Show progress
        this.showToast(`Running: ${action.name}`, 2000, 'info');

        // Execute steps sequentially
        for (let i = 0; i < action.steps.length; i++) {
            const step = action.steps[i];
            const prompt = step.prompt.replace('{input}', userInput);

            // Add message showing what's happening
            this.addChatMessage('user', `[Step ${i + 1}/${action.steps.length}] ${step.agent.toUpperCase()}: ${prompt}`);

            // Send to agent
            await this.sendToAgent(prompt, step.agent);

            // Wait for response before next step
            await this.waitForResponse();
        }

        this.showToast(`Completed: ${action.name}`, 2000, 'success');
        this.emit('quickAction:completed', { actionId, action });
    }

    /**
     * Execute custom macro
     */
    async executeMacro(macroId) {
        const macro = this.customMacros.find(m => m.id === macroId);
        if (!macro) return;

        this.hideActionsMenu();
        this.showToast(`Running macro: ${macro.name}`, 2000, 'info');

        // Execute macro steps
        for (const step of macro.steps) {
            await this.sendToAgent(step.prompt, step.agent);
            await this.waitForResponse();
        }

        this.showToast(`Completed: ${macro.name}`, 2000, 'success');
    }

    /**
     * Wait for AI response
     */
    waitForResponse() {
        return new Promise(resolve => {
            const checkInterval = setInterval(() => {
                const sendBtn = document.getElementById('sendBtn');
                if (sendBtn && sendBtn.getAttribute('data-state') !== 'stop') {
                    clearInterval(checkInterval);
                    setTimeout(resolve, 500); // Small delay between steps
                }
            }, 500);

            // Timeout after 60 seconds
            setTimeout(() => {
                clearInterval(checkInterval);
                resolve();
            }, 60000);
        });
    }

    /**
     * Open macro builder
     */
    openMacroBuilder() {
        this.hideActionsMenu();
        this.showToast('Macro builder coming soon!', 3000, 'info');
        // TODO: Implement full macro builder UI
    }

    /**
     * Load custom macros
     */
    loadCustomMacros() {
        try {
            const saved = localStorage.getItem('pkn_custom_macros');
            if (saved) {
                this.customMacros = JSON.parse(saved);
            }
        } catch (error) {
            console.error(`[${this.name}] Error loading macros:`, error);
        }
    }

    /**
     * Save custom macros
     */
    saveCustomMacros() {
        try {
            localStorage.setItem('pkn_custom_macros', JSON.stringify(this.customMacros));
        } catch (error) {
            console.error(`[${this.name}] Error saving macros:`, error);
        }
    }

    getCSS() {
        return `
            .quick-actions-btn {
                background: rgba(0, 255, 255, 0.1);
                border: 1px solid rgba(0, 255, 255, 0.3);
                border-radius: 8px;
                width: 48px;
                height: 48px;
                font-size: 20px;
                cursor: pointer;
                transition: all 0.2s;
                display: inline-flex;
                align-items: center;
                justify-content: center;
                margin-left: 8px;
            }
            .quick-actions-btn:hover {
                background: rgba(0, 255, 255, 0.2);
                border-color: var(--theme-primary);
                transform: translateY(-2px);
                box-shadow: 0 4px 12px rgba(0, 255, 255, 0.3);
            }
            .quick-actions-menu {
                position: fixed;
                bottom: 90px;
                right: 20px;
                background: rgba(0, 20, 20, 0.98);
                border: 1px solid var(--theme-primary);
                border-radius: 12px;
                width: 380px;
                max-height: 70vh;
                z-index: 10002;
                opacity: 0;
                transform: translateY(20px) scale(0.95);
                transition: all 0.3s ease;
                box-shadow: 0 8px 32px rgba(0, 255, 255, 0.3);
                display: flex;
                flex-direction: column;
            }
            .quick-actions-menu.visible {
                opacity: 1;
                transform: translateY(0) scale(1);
            }
            .quick-actions-header {
                padding: 16px;
                border-bottom: 1px solid rgba(0, 255, 255, 0.2);
                color: var(--theme-primary);
                font-size: 16px;
                font-weight: 700;
            }
            .quick-actions-list {
                flex: 1;
                overflow-y: auto;
                padding: 8px;
            }
            .quick-action-item {
                padding: 12px;
                margin-bottom: 8px;
                background: rgba(0, 255, 255, 0.05);
                border: 1px solid rgba(0, 255, 255, 0.1);
                border-radius: 8px;
                cursor: pointer;
                transition: all 0.2s;
            }
            .quick-action-item:hover {
                background: rgba(0, 255, 255, 0.1);
                border-color: rgba(0, 255, 255, 0.3);
                transform: translateX(4px);
            }
            .quick-action-item.custom {
                border-left: 3px solid #ff00ff;
            }
            .action-name {
                color: #fff;
                font-size: 14px;
                font-weight: 600;
                margin-bottom: 4px;
            }
            .action-description {
                color: #aaa;
                font-size: 12px;
            }
            .actions-divider {
                color: var(--theme-primary);
                font-size: 12px;
                font-weight: 600;
                padding: 12px 8px 8px 8px;
                margin-top: 8px;
                border-top: 1px solid rgba(0, 255, 255, 0.2);
            }
            .quick-actions-footer {
                padding: 12px;
                border-top: 1px solid rgba(0, 255, 255, 0.2);
                display: flex;
                gap: 8px;
            }
            .action-footer-btn {
                flex: 1;
                padding: 8px 12px;
                background: rgba(0, 255, 255, 0.1);
                border: 1px solid rgba(0, 255, 255, 0.3);
                border-radius: 6px;
                color: var(--theme-primary);
                font-size: 12px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.2s;
            }
            .action-footer-btn:hover {
                background: rgba(0, 255, 255, 0.2);
                border-color: var(--theme-primary);
            }
        `;
    }
}

export default QuickActionsPlugin;
