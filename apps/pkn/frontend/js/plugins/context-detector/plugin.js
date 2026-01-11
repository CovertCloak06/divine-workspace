/**
 * Smart Context Detector Plugin
 * Analyzes user input and suggests the best agent for the task
 */

import { PluginBase } from '../../features/plugin-base.js';

export class ContextDetectorPlugin extends PluginBase {
    constructor(manifest) {
        super(manifest);
        this.inputHandler = null;
        this.pasteHandler = null;
        this.detectionTimeout = null;
    }

    async init() {
        await super.init();
        const defaults = {
            autoSwitch: false,
            showToast: true,
            detectionDelay: 500
        };
        this.loadSettings({ ...defaults, ...this.getSettings() });

        // Inject CSS
        this.injectCSS(this.getCSS());
    }

    async enable() {
        await super.enable();

        // Set up input monitoring
        const messageInput = document.getElementById('messageInput');
        if (messageInput) {
            const delay = this.getSetting('detectionDelay', 500);

            this.inputHandler = (e) => {
                clearTimeout(this.detectionTimeout);
                this.detectionTimeout = setTimeout(() => {
                    this.analyzeContext(e.target.value);
                }, delay);
            };

            this.pasteHandler = (e) => {
                setTimeout(() => {
                    this.analyzeContext(e.target.value, true);
                }, 100);
            };

            messageInput.addEventListener('input', this.inputHandler);
            messageInput.addEventListener('paste', this.pasteHandler);
        }

        // Make this available globally for toast buttons
        window.contextDetector = this;

        console.log(`[${this.name}] Active - monitoring input`);
    }

    async disable() {
        await super.disable();

        const messageInput = document.getElementById('messageInput');
        if (messageInput) {
            if (this.inputHandler) messageInput.removeEventListener('input', this.inputHandler);
            if (this.pasteHandler) messageInput.removeEventListener('paste', this.pasteHandler);
        }

        clearTimeout(this.detectionTimeout);
    }

    /**
     * Analyze context and suggest agent
     */
    analyzeContext(text, isPaste = false) {
        if (!text || text.length < 20) return;

        const lowerText = text.toLowerCase();

        // Detect code patterns
        if (this.isCode(text)) {
            this.suggestAgent('coder', 'Code detected');
            return;
        }

        // Detect URLs
        if (this.hasURL(text)) {
            this.suggestAgent('researcher', 'URL detected');
            return;
        }

        // Detect error messages
        if (this.hasError(text)) {
            this.suggestAgent('reasoner', 'Error detected');
            return;
        }

        // Detect commands
        if (this.hasCommand(text)) {
            this.suggestAgent('executor', 'Command detected');
            return;
        }

        // Detect questions
        if (this.isQuestion(text)) {
            this.suggestAgent('general', 'Question detected');
            return;
        }
    }

    /**
     * Detect code patterns
     */
    isCode(text) {
        const codePatterns = [
            /function\s+\w+\s*\(/,
            /class\s+\w+/,
            /const\s+\w+\s*=/,
            /let\s+\w+\s*=/,
            /var\s+\w+\s*=/,
            /def\s+\w+\(/,
            /import\s+.*from/,
            /export\s+(default|const|function)/,
            /```[\s\S]*```/,
            /if\s*\(.*\)\s*{/,
            /=>\s*{/
        ];
        return codePatterns.some(pattern => pattern.test(text));
    }

    /**
     * Detect URLs
     */
    hasURL(text) {
        return /https?:\/\/[^\s]+/.test(text);
    }

    /**
     * Detect error messages
     */
    hasError(text) {
        const errorPatterns = [
            /error:/i,
            /exception/i,
            /traceback/i,
            /stack trace/i,
            /undefined is not/i,
            /cannot read property/i,
            /syntax error/i
        ];
        return errorPatterns.some(pattern => pattern.test(text));
    }

    /**
     * Detect commands
     */
    hasCommand(text) {
        return /^(git|npm|pip|docker|cd|ls|mkdir|rm)\s+/i.test(text.trim());
    }

    /**
     * Detect questions
     */
    isQuestion(text) {
        const questionWords = ['how', 'what', 'why', 'when', 'where', 'who', 'which'];
        const lowerText = text.toLowerCase();
        return questionWords.some(word => lowerText.startsWith(word)) || text.includes('?');
    }

    /**
     * Suggest agent
     */
    suggestAgent(agent, reason) {
        const autoSwitch = this.getSetting('autoSwitch', false);
        const showToastSetting = this.getSetting('showToast', true);

        if (autoSwitch) {
            this.switchToAgent(agent);
            if (showToastSetting) {
                this.showToast(`Switched to ${agent.toUpperCase()}`, 2000, 'success');
            }
        } else if (showToastSetting) {
            this.showSuggestionToast(agent, reason);
        }
    }

    /**
     * Switch to agent
     */
    switchToAgent(agent) {
        const agentSelect = document.getElementById('agentSelect');
        if (agentSelect) {
            agentSelect.value = agent;
            agentSelect.dispatchEvent(new Event('change'));
        }
    }

    /**
     * Show suggestion toast
     */
    showSuggestionToast(agent, reason) {
        // Remove existing suggestions
        document.querySelectorAll('.context-suggestion-toast').forEach(el => el.remove());

        const toast = document.createElement('div');
        toast.className = 'context-suggestion-toast';
        toast.innerHTML = `
            <div class="suggestion-content">
                <span class="suggestion-icon">💡</span>
                <div class="suggestion-text">
                    <strong>${reason}</strong>
                    <div>Switch to ${agent.toUpperCase()} agent?</div>
                </div>
            </div>
            <div class="suggestion-actions">
                <button class="suggestion-yes" onclick="window.contextDetector.acceptSuggestion('${agent}', this.closest('.context-suggestion-toast'))">
                    Switch
                </button>
                <button class="suggestion-no" onclick="this.closest('.context-suggestion-toast').remove()">
                    Dismiss
                </button>
            </div>
        `;

        document.body.appendChild(toast);
        setTimeout(() => toast.classList.add('visible'), 10);
        setTimeout(() => { if (toast.parentElement) toast.remove(); }, 8000);
    }

    /**
     * Accept suggestion
     */
    acceptSuggestion(agent, toastElement) {
        this.switchToAgent(agent);
        toastElement.remove();
        this.showToast(`Switched to ${agent.toUpperCase()}`, 2000, 'success');
    }

    getCSS() {
        return `
            .context-suggestion-toast {
                position: fixed;
                top: 80px;
                right: 20px;
                background: rgba(0, 30, 30, 0.95);
                border: 1px solid var(--theme-primary);
                border-radius: 8px;
                padding: 16px;
                min-width: 300px;
                z-index: 10001;
                opacity: 0;
                transform: translateX(400px);
                transition: all 0.3s ease;
                box-shadow: 0 4px 20px rgba(0, 255, 255, 0.3);
            }
            .context-suggestion-toast.visible {
                opacity: 1;
                transform: translateX(0);
            }
            .suggestion-content {
                display: flex;
                gap: 12px;
                margin-bottom: 12px;
            }
            .suggestion-icon {
                font-size: 24px;
            }
            .suggestion-text {
                flex: 1;
                color: #fff;
                font-size: 13px;
            }
            .suggestion-text strong {
                color: var(--theme-primary);
                display: block;
                margin-bottom: 4px;
            }
            .suggestion-actions {
                display: flex;
                gap: 8px;
                justify-content: flex-end;
            }
            .suggestion-yes, .suggestion-no {
                padding: 6px 16px;
                border-radius: 4px;
                font-size: 12px;
                cursor: pointer;
                transition: all 0.2s;
                font-weight: 600;
            }
            .suggestion-yes {
                background: var(--theme-primary);
                border: none;
                color: #000;
            }
            .suggestion-yes:hover {
                background: #00cccc;
                box-shadow: 0 2px 8px rgba(0, 255, 255, 0.4);
            }
            .suggestion-no {
                background: transparent;
                border: 1px solid #666;
                color: #aaa;
            }
            .suggestion-no:hover {
                border-color: var(--theme-primary);
                color: #fff;
            }
        `;
    }
}

export default ContextDetectorPlugin;
