/**
 * Divine Debugger - Mobile Debug Panel for PKN
 * Features: Console, Code Analysis, Security Scanner
 */
(function() {
    'use strict';

    // Prevent double initialization
    if (window.DivineDebugger) return;

    const DD = window.DivineDebugger = {
        panel: null,
        logs: [],
        visible: false,
        activeTab: 'console'
    };

    // Original console methods
    const originalConsole = {
        log: console.log.bind(console),
        error: console.error.bind(console),
        warn: console.warn.bind(console),
        info: console.info.bind(console)
    };

    // Create panel HTML
    function createPanel() {
        const panel = document.createElement('div');
        panel.id = 'divine-debugger';
        panel.innerHTML = `
            <div class="dd-header">
                <span class="dd-title">Divine Debugger</span>
                <div class="dd-tabs">
                    <button class="dd-tab active" data-tab="console">Console</button>
                    <button class="dd-tab" data-tab="analysis">Analysis</button>
                    <button class="dd-tab" data-tab="security">Security</button>
                </div>
                <button class="dd-close">X</button>
            </div>
            <div class="dd-content">
                <div class="dd-panel active" id="dd-console"></div>
                <div class="dd-panel" id="dd-analysis"></div>
                <div class="dd-panel" id="dd-security"></div>
            </div>
            <div class="dd-actions">
                <button class="dd-btn" id="dd-clear">Clear</button>
                <button class="dd-btn" id="dd-refresh">Refresh</button>
            </div>
        `;

        // Add styles
        const style = document.createElement('style');
        style.textContent = `
            #divine-debugger {
                position: fixed;
                bottom: 60px;
                left: 10px;
                width: calc(100vw - 20px);
                max-width: 400px;
                height: 300px;
                background: #111;
                border: 2px solid #0ff;
                border-radius: 8px;
                z-index: 999999;
                font-family: monospace;
                font-size: 12px;
                color: #eee;
                display: none;
                flex-direction: column;
                box-shadow: 0 4px 20px rgba(0,255,255,0.3);
            }
            #divine-debugger.visible { display: flex; }
            .dd-header {
                display: flex;
                align-items: center;
                padding: 8px;
                background: #1a1a1a;
                border-bottom: 1px solid #333;
                border-radius: 6px 6px 0 0;
                gap: 8px;
                flex-wrap: wrap;
            }
            .dd-title {
                color: #0ff;
                font-weight: bold;
                font-size: 13px;
            }
            .dd-tabs {
                display: flex;
                gap: 4px;
                flex: 1;
            }
            .dd-tab {
                background: #222;
                border: 1px solid #444;
                color: #888;
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 11px;
                cursor: pointer;
            }
            .dd-tab.active {
                background: #0ff;
                color: #000;
                border-color: #0ff;
            }
            .dd-close {
                background: #f66;
                border: none;
                color: #fff;
                width: 24px;
                height: 24px;
                border-radius: 4px;
                cursor: pointer;
                font-weight: bold;
            }
            .dd-content {
                flex: 1;
                overflow: hidden;
                position: relative;
            }
            .dd-panel {
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                overflow-y: auto;
                padding: 8px;
                display: none;
            }
            .dd-panel.active { display: block; }
            .dd-log {
                padding: 4px 6px;
                border-bottom: 1px solid #222;
                word-break: break-word;
            }
            .dd-log.error { color: #f66; }
            .dd-log.warn { color: #fa0; }
            .dd-log.info { color: #6af; }
            .dd-actions {
                display: flex;
                gap: 8px;
                padding: 8px;
                border-top: 1px solid #333;
            }
            .dd-btn {
                flex: 1;
                background: #0ff;
                border: none;
                color: #000;
                padding: 8px;
                border-radius: 4px;
                font-weight: bold;
                cursor: pointer;
            }
            .dd-section {
                margin-bottom: 12px;
            }
            .dd-section-title {
                color: #0ff;
                font-weight: bold;
                margin-bottom: 6px;
                padding-bottom: 4px;
                border-bottom: 1px solid #333;
            }
            .dd-item {
                padding: 4px 0;
                color: #aaa;
            }
            .dd-item.ok { color: #6f6; }
            .dd-item.warn { color: #fa0; }
            .dd-item.error { color: #f66; }
        `;
        document.head.appendChild(style);
        document.body.appendChild(panel);

        // Event listeners
        panel.querySelector('.dd-close').onclick = () => toggleDebugger();
        panel.querySelector('#dd-clear').onclick = () => clearConsole();
        panel.querySelector('#dd-refresh').onclick = () => refreshAnalysis();

        panel.querySelectorAll('.dd-tab').forEach(tab => {
            tab.onclick = () => switchTab(tab.dataset.tab);
        });

        return panel;
    }

    // Switch tabs
    function switchTab(tabName) {
        DD.activeTab = tabName;
        DD.panel.querySelectorAll('.dd-tab').forEach(t => {
            t.classList.toggle('active', t.dataset.tab === tabName);
        });
        DD.panel.querySelectorAll('.dd-panel').forEach(p => {
            p.classList.toggle('active', p.id === 'dd-' + tabName);
        });

        if (tabName === 'analysis') runCodeAnalysis();
        if (tabName === 'security') runSecurityScan();
    }

    // Log message to console panel
    function logMessage(msg, type = 'log') {
        const entry = { msg, type, time: new Date() };
        DD.logs.push(entry);

        if (DD.panel) {
            const consolePanel = DD.panel.querySelector('#dd-console');
            const div = document.createElement('div');
            div.className = 'dd-log ' + type;
            div.textContent = `[${entry.time.toLocaleTimeString()}] ${msg}`;
            consolePanel.appendChild(div);
            consolePanel.scrollTop = consolePanel.scrollHeight;
        }
    }

    // Clear console
    function clearConsole() {
        DD.logs = [];
        const consolePanel = DD.panel.querySelector('#dd-console');
        consolePanel.innerHTML = '';
        logMessage('Console cleared', 'info');
    }

    // Refresh analysis
    function refreshAnalysis() {
        if (DD.activeTab === 'analysis') runCodeAnalysis();
        if (DD.activeTab === 'security') runSecurityScan();
        logMessage('Analysis refreshed', 'info');
    }

    // Code Analysis
    function runCodeAnalysis() {
        const panel = DD.panel.querySelector('#dd-analysis');
        const results = [];

        // Check for duplicate IDs
        const ids = {};
        document.querySelectorAll('[id]').forEach(el => {
            if (ids[el.id]) {
                results.push({ type: 'error', msg: `Duplicate ID: #${el.id}` });
            }
            ids[el.id] = true;
        });

        // Check for missing elements referenced in onclick
        document.querySelectorAll('[onclick]').forEach(el => {
            const onclick = el.getAttribute('onclick');
            const matches = onclick.match(/getElementById\(['"]([^'"]+)['"]\)/g);
            if (matches) {
                matches.forEach(m => {
                    const id = m.match(/['"]([^'"]+)['"]/)[1];
                    if (!document.getElementById(id)) {
                        results.push({ type: 'warn', msg: `Missing element: #${id} in onclick` });
                    }
                });
            }
        });

        // Check for undefined functions in onclick
        document.querySelectorAll('[onclick]').forEach(el => {
            const onclick = el.getAttribute('onclick');
            const funcMatch = onclick.match(/^(\w+)\(/);
            if (funcMatch && typeof window[funcMatch[1]] !== 'function') {
                results.push({ type: 'error', msg: `Undefined function: ${funcMatch[1]}()` });
            }
        });

        // Check inline styles (potential issues)
        const inlineStyles = document.querySelectorAll('[style]').length;
        if (inlineStyles > 20) {
            results.push({ type: 'warn', msg: `${inlineStyles} inline styles found` });
        }

        // Scripts count
        const scripts = document.querySelectorAll('script').length;
        results.push({ type: 'ok', msg: `${scripts} script tags loaded` });

        // Render results
        panel.innerHTML = `
            <div class="dd-section">
                <div class="dd-section-title">Code Analysis</div>
                ${results.length === 0 ? '<div class="dd-item ok">No issues found</div>' : ''}
                ${results.map(r => `<div class="dd-item ${r.type}">${r.type.toUpperCase()}: ${r.msg}</div>`).join('')}
            </div>
        `;
    }

    // Security Scan
    function runSecurityScan() {
        const panel = DD.panel.querySelector('#dd-security');
        const results = [];

        // Protocol check
        const isSecure = location.protocol === 'https:';
        results.push({
            type: isSecure ? 'ok' : 'warn',
            msg: `Protocol: ${location.protocol} ${isSecure ? '(secure)' : '(insecure)'}`
        });

        // Cookies
        const cookies = document.cookie.split(';').filter(c => c.trim()).length;
        results.push({ type: 'ok', msg: `Cookies: ${cookies}` });

        // LocalStorage
        const storageKeys = Object.keys(localStorage).length;
        results.push({ type: 'ok', msg: `LocalStorage keys: ${storageKeys}` });

        // SessionStorage
        const sessionKeys = Object.keys(sessionStorage).length;
        results.push({ type: 'ok', msg: `SessionStorage keys: ${sessionKeys}` });

        // External scripts
        const externalScripts = Array.from(document.querySelectorAll('script[src]'))
            .filter(s => s.src && !s.src.startsWith(location.origin));
        if (externalScripts.length > 0) {
            results.push({ type: 'warn', msg: `External scripts: ${externalScripts.length}` });
            externalScripts.forEach(s => {
                try {
                    const url = new URL(s.src);
                    results.push({ type: 'info', msg: `  - ${url.hostname}` });
                } catch(e) {}
            });
        } else {
            results.push({ type: 'ok', msg: 'No external scripts' });
        }

        // Forms without HTTPS action
        const insecureForms = Array.from(document.querySelectorAll('form[action]'))
            .filter(f => f.action.startsWith('http:'));
        if (insecureForms.length > 0) {
            results.push({ type: 'error', msg: `Insecure form actions: ${insecureForms.length}` });
        }

        // Password fields without autocomplete off
        const pwFields = document.querySelectorAll('input[type="password"]');
        pwFields.forEach((f, i) => {
            if (f.autocomplete !== 'off' && f.autocomplete !== 'new-password' && f.autocomplete !== 'current-password') {
                results.push({ type: 'warn', msg: `Password field ${i+1} missing autocomplete attribute` });
            }
        });

        // Render results
        panel.innerHTML = `
            <div class="dd-section">
                <div class="dd-section-title">Security Scan</div>
                ${results.map(r => `<div class="dd-item ${r.type}">${r.msg}</div>`).join('')}
            </div>
        `;
    }

    // Intercept console methods
    function interceptConsole() {
        console.log = function(...args) {
            originalConsole.log(...args);
            logMessage(args.map(a => typeof a === 'object' ? JSON.stringify(a) : String(a)).join(' '), 'log');
        };
        console.error = function(...args) {
            originalConsole.error(...args);
            logMessage(args.map(a => typeof a === 'object' ? JSON.stringify(a) : String(a)).join(' '), 'error');
        };
        console.warn = function(...args) {
            originalConsole.warn(...args);
            logMessage(args.map(a => typeof a === 'object' ? JSON.stringify(a) : String(a)).join(' '), 'warn');
        };
        console.info = function(...args) {
            originalConsole.info(...args);
            logMessage(args.map(a => typeof a === 'object' ? JSON.stringify(a) : String(a)).join(' '), 'info');
        };
    }

    // Catch global errors
    function interceptErrors() {
        window.addEventListener('error', (e) => {
            logMessage(`${e.message} at ${e.filename}:${e.lineno}`, 'error');
        });
        window.addEventListener('unhandledrejection', (e) => {
            logMessage(`Unhandled Promise: ${e.reason}`, 'error');
        });
    }

    // Toggle debugger visibility
    window.toggleDebugger = function() {
        if (!DD.panel) {
            DD.panel = createPanel();
            interceptConsole();
            interceptErrors();
            logMessage('Divine Debugger initialized', 'info');
            logMessage(`Page: ${location.href}`, 'info');
        }

        DD.visible = !DD.visible;
        DD.panel.classList.toggle('visible', DD.visible);

        if (DD.visible && DD.activeTab === 'console' && DD.logs.length === 0) {
            logMessage('Console ready. Logs will appear here.', 'info');
        }
    };

    // Auto-init if hash contains #debug
    if (location.hash === '#debug') {
        document.addEventListener('DOMContentLoaded', toggleDebugger);
    }

    originalConsole.log('[Divine Debugger] Module loaded');
})();
