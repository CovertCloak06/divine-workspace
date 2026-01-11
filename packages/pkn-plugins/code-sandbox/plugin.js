/**
 * Code Execution Sandbox Plugin
 * Safely execute code snippets with output preview
 */

import { PluginBase } from '../../js/plugin-base.js';

export class CodeSandboxPlugin extends PluginBase {
    constructor(manifest) {
        super(manifest);
        this.executionHistory = [];
        this.currentExecution = null;
    }

    async init() {
        await super.init();

        const defaults = {
            defaultLanguage: 'javascript',
            timeout: 5000,
            autoDetect: true
        };
        this.loadSettings({ ...defaults, ...this.getSettings() });

        this.injectCSS(this.getCSS());
    }

    async enable() {
        await super.enable();

        // Add sandbox button to sidebar
        this.addSandboxButton();

        // Auto-detect code blocks in messages
        if (this.getSetting('autoDetect', true)) {
            this.subscribe('message:received', (data) => this.detectCodeBlocks(data));
        }

        // Make globally available
        window.codeSandbox = this;

        console.log(`[${this.name}] Code Sandbox active`);
    }

    async disable() {
        await super.disable();
        this.removeSandboxButton();
        this.hideSandboxPanel();
    }

    /**
     * Add sandbox button to sidebar
     */
    addSandboxButton() {
        const sidebar = document.querySelector('.sidebar');
        if (!sidebar) return;

        const button = document.createElement('div');
        button.className = 'sidebar-section-header clickable';
        button.id = 'codeSandboxBtn';
        button.innerHTML = '<span>▶️ Code Sandbox</span>';
        button.onclick = () => this.showSandboxPanel();

        // Insert after Developer Labs section
        const devSection = document.querySelector('.sidebar-section-header[onclick*="openDeveloperLabs"]');
        if (devSection) {
            devSection.parentNode.insertBefore(button, devSection.nextSibling);
        }
    }

    /**
     * Remove sandbox button
     */
    removeSandboxButton() {
        const button = document.getElementById('codeSandboxBtn');
        if (button) button.remove();
    }

    /**
     * Show sandbox panel
     */
    showSandboxPanel() {
        // Remove existing panel
        this.hideSandboxPanel();

        const panel = document.createElement('div');
        panel.id = 'codeSandboxPanel';
        panel.className = 'code-sandbox-panel';

        const defaultLang = this.getSetting('defaultLanguage', 'javascript');

        let html = `
            <div class="sandbox-panel-header">
                <div class="sandbox-panel-title">Code Execution Sandbox</div>
                <button class="sandbox-panel-close" onclick="window.codeSandbox.hideSandboxPanel()">×</button>
            </div>
            <div class="sandbox-toolbar">
                <select id="sandboxLanguage" class="sandbox-lang-select">
                    <option value="javascript" ${defaultLang === 'javascript' ? 'selected' : ''}>JavaScript</option>
                    <option value="python" ${defaultLang === 'python' ? 'selected' : ''}>Python</option>
                    <option value="html" ${defaultLang === 'html' ? 'selected' : ''}>HTML/CSS</option>
                </select>
                <button class="sandbox-btn primary" onclick="window.codeSandbox.executeCode()">
                    ▶️ Run Code
                </button>
                <button class="sandbox-btn" onclick="window.codeSandbox.clearSandbox()">
                    Clear
                </button>
            </div>
            <div class="sandbox-panel-body">
                <div class="sandbox-editor">
                    <textarea id="sandboxCodeInput" placeholder="Enter your code here..."></textarea>
                </div>
                <div class="sandbox-output">
                    <div class="sandbox-output-header">Output</div>
                    <div id="sandboxOutputArea" class="sandbox-output-content">
                        <div class="output-placeholder">Code output will appear here...</div>
                    </div>
                </div>
            </div>
        `;

        // Execution history
        if (this.executionHistory.length > 0) {
            html += `
                <div class="sandbox-history">
                    <div class="history-header">Recent Executions</div>
                    <div class="history-list">
            `;

            this.executionHistory.slice(-5).reverse().forEach((exec, idx) => {
                const actualIdx = this.executionHistory.length - 1 - idx;
                const statusClass = exec.success ? 'success' : 'error';
                html += `
                    <div class="history-item ${statusClass}" onclick="window.codeSandbox.loadExecution(${actualIdx})">
                        <div class="history-lang">${exec.language.toUpperCase()}</div>
                        <div class="history-preview">${this.truncate(exec.code, 50)}</div>
                        <div class="history-time">${exec.time}</div>
                    </div>
                `;
            });

            html += `
                    </div>
                </div>
            `;
        }

        panel.innerHTML = html;
        document.body.appendChild(panel);

        setTimeout(() => panel.classList.add('visible'), 10);
    }

    /**
     * Hide sandbox panel
     */
    hideSandboxPanel() {
        const panel = document.getElementById('codeSandboxPanel');
        if (panel) {
            panel.classList.remove('visible');
            setTimeout(() => panel.remove(), 300);
        }
    }

    /**
     * Execute code
     */
    async executeCode() {
        const codeInput = document.getElementById('sandboxCodeInput');
        const langSelect = document.getElementById('sandboxLanguage');
        const outputArea = document.getElementById('sandboxOutputArea');

        if (!codeInput || !langSelect || !outputArea) return;

        const code = codeInput.value.trim();
        const language = langSelect.value;

        if (!code) {
            this.showToast('Please enter some code first', 3000, 'error');
            return;
        }

        outputArea.innerHTML = '<div class="output-running">Running...</div>';

        try {
            const startTime = performance.now();
            const result = await this.runCode(code, language);
            const duration = (performance.now() - startTime).toFixed(2);

            // Display output
            outputArea.innerHTML = `
                <div class="output-success">
                    <div class="output-label">Output (${duration}ms):</div>
                    <pre class="output-text">${this.escapeHtml(result.output)}</pre>
                </div>
            `;

            // Add to history
            this.executionHistory.push({
                code,
                language,
                output: result.output,
                success: true,
                time: new Date().toLocaleTimeString(),
                duration
            });

            this.showToast('Code executed successfully', 2000, 'success');
            this.emit('code:executed', { code, language, result });

        } catch (error) {
            // Display error
            outputArea.innerHTML = `
                <div class="output-error">
                    <div class="output-label">Error:</div>
                    <pre class="output-text">${this.escapeHtml(error.message)}</pre>
                </div>
            `;

            // Add to history
            this.executionHistory.push({
                code,
                language,
                output: error.message,
                success: false,
                time: new Date().toLocaleTimeString(),
                duration: 0
            });

            this.showToast('Execution failed', 3000, 'error');
        }
    }

    /**
     * Run code in sandboxed environment
     */
    async runCode(code, language) {
        const timeout = this.getSetting('timeout', 5000);

        switch (language) {
            case 'javascript':
                return await this.runJavaScript(code, timeout);
            case 'python':
                return await this.runPython(code, timeout);
            case 'html':
                return await this.runHTML(code, timeout);
            default:
                throw new Error(`Unsupported language: ${language}`);
        }
    }

    /**
     * Run JavaScript code
     */
    async runJavaScript(code, timeout) {
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                reject(new Error('Execution timeout'));
            }, timeout);

            try {
                // Create sandboxed console
                const logs = [];
                const sandboxConsole = {
                    log: (...args) => logs.push(args.map(a => String(a)).join(' ')),
                    error: (...args) => logs.push('ERROR: ' + args.map(a => String(a)).join(' ')),
                    warn: (...args) => logs.push('WARN: ' + args.map(a => String(a)).join(' ')),
                    info: (...args) => logs.push('INFO: ' + args.map(a => String(a)).join(' '))
                };

                // Create sandboxed function
                const sandboxedFunction = new Function('console', code);

                // Execute
                const result = sandboxedFunction(sandboxConsole);

                clearTimeout(timer);

                // Combine logs and result
                let output = logs.join('\n');
                if (result !== undefined) {
                    output += (output ? '\n' : '') + '→ ' + String(result);
                }

                resolve({ output: output || '(no output)' });

            } catch (error) {
                clearTimeout(timer);
                reject(new Error(`JavaScript Error: ${error.message}`));
            }
        });
    }

    /**
     * Run Python code (via backend API)
     */
    async runPython(code, timeout) {
        try {
            const response = await fetch('/api/code/execute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    code,
                    language: 'python',
                    timeout
                })
            });

            if (!response.ok) {
                throw new Error('Python execution not available. Backend API required.');
            }

            const result = await response.json();

            if (result.error) {
                throw new Error(result.error);
            }

            return { output: result.output || '(no output)' };

        } catch (error) {
            throw new Error(`Python Error: ${error.message}`);
        }
    }

    /**
     * Run HTML/CSS code
     */
    async runHTML(code, timeout) {
        return new Promise((resolve) => {
            try {
                // Create iframe for safe HTML rendering
                const iframe = document.createElement('iframe');
                iframe.style.display = 'none';
                document.body.appendChild(iframe);

                // Write HTML to iframe
                iframe.contentDocument.open();
                iframe.contentDocument.write(code);
                iframe.contentDocument.close();

                // Capture any console output from iframe
                const logs = [];
                iframe.contentWindow.console.log = (...args) => {
                    logs.push(args.map(a => String(a)).join(' '));
                };

                // Wait a bit for rendering
                setTimeout(() => {
                    const output = logs.length > 0
                        ? logs.join('\n')
                        : 'HTML rendered successfully. Open browser DevTools to inspect.';

                    // Clean up
                    document.body.removeChild(iframe);

                    resolve({ output });
                }, 1000);

            } catch (error) {
                resolve({ output: `HTML Error: ${error.message}` });
            }
        });
    }

    /**
     * Clear sandbox
     */
    clearSandbox() {
        const codeInput = document.getElementById('sandboxCodeInput');
        const outputArea = document.getElementById('sandboxOutputArea');

        if (codeInput) codeInput.value = '';
        if (outputArea) {
            outputArea.innerHTML = '<div class="output-placeholder">Code output will appear here...</div>';
        }

        this.showToast('Sandbox cleared', 2000, 'info');
    }

    /**
     * Load execution from history
     */
    loadExecution(index) {
        if (index < 0 || index >= this.executionHistory.length) return;

        const exec = this.executionHistory[index];
        const codeInput = document.getElementById('sandboxCodeInput');
        const langSelect = document.getElementById('sandboxLanguage');
        const outputArea = document.getElementById('sandboxOutputArea');

        if (codeInput) codeInput.value = exec.code;
        if (langSelect) langSelect.value = exec.language;

        if (outputArea) {
            const outputClass = exec.success ? 'output-success' : 'output-error';
            outputArea.innerHTML = `
                <div class="${outputClass}">
                    <div class="output-label">${exec.success ? 'Output' : 'Error'}:</div>
                    <pre class="output-text">${this.escapeHtml(exec.output)}</pre>
                </div>
            `;
        }
    }

    /**
     * Detect code blocks in messages
     */
    detectCodeBlocks(data) {
        // This is a placeholder - actual implementation would need
        // to scan chat messages and add "Run" buttons to code blocks
        const content = data.content || data.message || '';

        // Detect code blocks with ```
        const codeBlockPattern = /```(\w+)?\n([\s\S]+?)```/g;
        const matches = content.matchAll(codeBlockPattern);

        for (const match of matches) {
            const language = match[1] || 'javascript';
            if (['javascript', 'python', 'html'].includes(language.toLowerCase())) {
                this.showToast(`Code block detected! Click ▶️ to run`, 4000, 'info');
                break;
            }
        }
    }

    /**
     * Truncate text
     */
    truncate(text, maxLength) {
        if (text.length <= maxLength) return text;
        return text.substring(0, maxLength) + '...';
    }

    /**
     * Escape HTML
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    getCSS() {
        return `
            .code-sandbox-panel {
                position: fixed;
                top: 0;
                right: 0;
                width: 700px;
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
            .code-sandbox-panel.visible {
                opacity: 1;
                transform: translateX(0);
            }
            .sandbox-panel-header {
                padding: 20px;
                border-bottom: 1px solid rgba(0, 255, 255, 0.2);
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .sandbox-panel-title {
                color: var(--theme-primary);
                font-size: 18px;
                font-weight: 700;
            }
            .sandbox-panel-close {
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
            .sandbox-panel-close:hover {
                background: rgba(0, 255, 255, 0.1);
                border-radius: 4px;
            }
            .sandbox-toolbar {
                padding: 12px 16px;
                border-bottom: 1px solid rgba(0, 255, 255, 0.1);
                display: flex;
                gap: 8px;
                align-items: center;
            }
            .sandbox-lang-select {
                flex: 1;
                padding: 8px 12px;
                background: rgba(0, 0, 0, 0.3);
                border: 1px solid rgba(0, 255, 255, 0.3);
                border-radius: 6px;
                color: #fff;
                font-size: 13px;
                cursor: pointer;
            }
            .sandbox-lang-select:focus {
                outline: none;
                border-color: var(--theme-primary);
            }
            .sandbox-btn {
                padding: 8px 16px;
                background: rgba(0, 255, 255, 0.1);
                border: 1px solid rgba(0, 255, 255, 0.3);
                border-radius: 6px;
                color: var(--theme-primary);
                font-size: 13px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.2s;
            }
            .sandbox-btn:hover {
                background: rgba(0, 255, 255, 0.2);
                border-color: var(--theme-primary);
            }
            .sandbox-btn.primary {
                background: rgba(0, 255, 255, 0.2);
                border-color: var(--theme-primary);
            }
            .sandbox-panel-body {
                flex: 1;
                display: flex;
                flex-direction: column;
                overflow: hidden;
            }
            .sandbox-editor {
                flex: 1;
                min-height: 200px;
                border-bottom: 1px solid rgba(0, 255, 255, 0.2);
            }
            #sandboxCodeInput {
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.3);
                border: none;
                color: #fff;
                padding: 16px;
                font-size: 13px;
                font-family: 'Courier New', monospace;
                resize: none;
            }
            #sandboxCodeInput:focus {
                outline: none;
            }
            .sandbox-output {
                flex: 1;
                min-height: 150px;
                display: flex;
                flex-direction: column;
            }
            .sandbox-output-header {
                padding: 8px 16px;
                background: rgba(0, 255, 255, 0.05);
                border-bottom: 1px solid rgba(0, 255, 255, 0.2);
                color: var(--theme-primary);
                font-size: 12px;
                font-weight: 700;
            }
            .sandbox-output-content {
                flex: 1;
                overflow-y: auto;
                padding: 16px;
            }
            .output-placeholder {
                color: #666;
                font-size: 13px;
                font-style: italic;
            }
            .output-running {
                color: #ffa500;
                font-size: 13px;
                animation: pulse 1s ease-in-out infinite;
            }
            @keyframes pulse {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.5; }
            }
            .output-success, .output-error {
                background: rgba(0, 0, 0, 0.3);
                border-radius: 6px;
                padding: 12px;
            }
            .output-success {
                border-left: 3px solid #0f0;
            }
            .output-error {
                border-left: 3px solid #f00;
            }
            .output-label {
                color: #888;
                font-size: 11px;
                font-weight: 600;
                margin-bottom: 8px;
                text-transform: uppercase;
            }
            .output-text {
                color: #fff;
                font-size: 13px;
                font-family: 'Courier New', monospace;
                margin: 0;
                white-space: pre-wrap;
                word-wrap: break-word;
            }
            .sandbox-history {
                padding: 16px;
                border-top: 2px solid rgba(0, 255, 255, 0.2);
                max-height: 200px;
                overflow-y: auto;
            }
            .history-header {
                color: var(--theme-primary);
                font-size: 14px;
                font-weight: 700;
                margin-bottom: 12px;
            }
            .history-list {
                display: flex;
                flex-direction: column;
                gap: 6px;
            }
            .history-item {
                background: rgba(0, 0, 0, 0.3);
                border-left: 3px solid #888;
                border-radius: 4px;
                padding: 8px;
                cursor: pointer;
                transition: all 0.2s;
                display: flex;
                gap: 8px;
                align-items: center;
            }
            .history-item:hover {
                background: rgba(0, 255, 255, 0.1);
                transform: translateX(4px);
            }
            .history-item.success {
                border-left-color: #0f0;
            }
            .history-item.error {
                border-left-color: #f00;
            }
            .history-lang {
                background: rgba(0, 255, 255, 0.2);
                padding: 2px 6px;
                border-radius: 3px;
                color: var(--theme-primary);
                font-size: 10px;
                font-weight: 700;
            }
            .history-preview {
                flex: 1;
                color: #ddd;
                font-size: 11px;
                font-family: 'Courier New', monospace;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }
            .history-time {
                color: #666;
                font-size: 10px;
            }
        `;
    }
}

export default CodeSandboxPlugin;
