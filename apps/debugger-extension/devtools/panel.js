/**
 * Divine Debugger - Chrome Extension Panel
 * Adapts the debugger app to work with inspected page via chrome.devtools API
 */

import AdvancedConsole from './advanced-console.js';
import SecurityPanel from './security-panel.js';

class ExtensionDebugger {
    constructor() {
        this.selectedElement = null;
        this.selectedPath = null;
        this.advancedConsole = null;
        this.securityPanel = null;
        this.init();
    }

    init() {
        console.log('Divine Debugger Extension initialized');

        // Initialize advanced console
        this.advancedConsole = new AdvancedConsole();

        // Initialize security panel
        this.securityPanel = new SecurityPanel((code, callback) => this.execute(code, callback));

        this.setupEventListeners();
        this.loadElements();
        this.setupConsoleIntercept();
        this.addConsoleControls();
        this.setupSecurityPanel();
    }

    // Execute code in the inspected page
    execute(code, callback) {
        chrome.devtools.inspectedWindow.eval(code, callback);
    }

    // Load all interactive elements from the page
    loadElements() {
        const code = `
            (function() {
                const elements = document.querySelectorAll('*');
                const result = [];
                elements.forEach((el, idx) => {
                    if (el.tagName) {
                        const path = el.tagName.toLowerCase() +
                            (el.id ? '#' + el.id : '') +
                            (el.className ? '.' + el.className.split(' ').join('.') : '');
                        result.push({
                            index: idx,
                            tag: el.tagName,
                            id: el.id,
                            className: el.className,
                            path: path
                        });
                    }
                });
                return result;
            })();
        `;

        this.execute(code, (result, error) => {
            if (error) {
                console.error('Error loading elements:', error);
                return;
            }
            this.populateElementSelector(result);
        });
    }

    populateElementSelector(elements) {
        const selector = document.getElementById('elementSelector');
        selector.innerHTML = '<option value="">Select element...</option>';

        elements.forEach(el => {
            const option = document.createElement('option');
            option.value = el.index;
            option.textContent = `${el.tag}${el.id ? '#' + el.id : ''}${el.className ? '.' + el.className.split(' ')[0] : ''}`;
            selector.appendChild(option);
        });
    }

    // Select an element by index
    selectElement(index) {
        const code = `
            (function() {
                const el = document.querySelectorAll('*')[${index}];
                if (!el) return null;

                const computed = window.getComputedStyle(el);
                return {
                    tag: el.tagName,
                    id: el.id,
                    className: el.className,
                    styles: {
                        width: computed.width,
                        height: computed.height,
                        padding: computed.padding,
                        margin: computed.margin,
                        backgroundColor: computed.backgroundColor,
                        color: computed.color,
                        fontSize: computed.fontSize,
                        fontFamily: computed.fontFamily,
                        fontWeight: computed.fontWeight
                    }
                };
            })();
        `;

        this.execute(code, (result, error) => {
            if (error || !result) {
                console.error('Error selecting element:', error);
                return;
            }
            this.selectedElement = index;
            this.updateElementInfo(result);
            this.updateStyleControls(result.styles);
        });
    }

    updateElementInfo(info) {
        const infoBox = document.getElementById('elementInfo');
        infoBox.innerHTML = `
            <div><strong>Tag:</strong> ${info.tag}</div>
            ${info.id ? `<div><strong>ID:</strong> ${info.id}</div>` : ''}
            ${info.className ? `<div><strong>Class:</strong> ${info.className}</div>` : ''}
        `;
    }

    updateStyleControls(styles) {
        // Update width/height
        if (styles.width) document.getElementById('widthValue').value = styles.width;
        if (styles.height) document.getElementById('heightValue').value = styles.height;

        // Update colors
        if (styles.backgroundColor) {
            try {
                const rgb = styles.backgroundColor.match(/\\d+/g);
                if (rgb) {
                    const hex = '#' + rgb.map(x => parseInt(x).toString(16).padStart(2, '0')).join('');
                    document.getElementById('bgColor').value = hex;
                }
            } catch (e) {}
        }

        // Update font size
        if (styles.fontSize) {
            const size = parseInt(styles.fontSize);
            document.getElementById('fontSize').value = size;
            document.getElementById('fontSizeValue').textContent = size + 'px';
        }
    }

    // Apply style change to selected element
    applyStyle(property, value) {
        if (this.selectedElement === null) return;

        const code = `
            (function() {
                const el = document.querySelectorAll('*')[${this.selectedElement}];
                if (el) {
                    el.style.${property} = '${value}';
                }
            })();
        `;

        this.execute(code);
    }

    // Highlight element on page
    highlightElement() {
        if (this.selectedElement === null) return;

        const code = `
            (function() {
                const el = document.querySelectorAll('*')[${this.selectedElement}];
                if (el) {
                    el.style.outline = '3px solid #00FFFF';
                    el.style.outlineOffset = '2px';
                    setTimeout(() => {
                        el.style.outline = '';
                        el.style.outlineOffset = '';
                    }, 2000);
                }
            })();
        `;

        this.execute(code);
    }

    // Console intercept
    setupConsoleIntercept() {
        // Listen to console messages from inspected window
        chrome.devtools.network.onNavigated.addListener(() => {
            this.loadElements(); // Reload elements on page navigation
        });
    }

    // Add advanced console controls
    addConsoleControls() {
        // Add search box to console controls
        const consoleControls = document.querySelector('.console-controls');
        if (consoleControls) {
            const searchBox = document.createElement('input');
            searchBox.type = 'text';
            searchBox.id = 'logSearch';
            searchBox.placeholder = 'Search logs...';
            searchBox.style.cssText = 'margin-left: 10px; padding: 4px 8px; background: #222; border: 1px solid #444; color: #0FF; border-radius: 3px;';
            consoleControls.appendChild(searchBox);

            const exportBtn = document.createElement('button');
            exportBtn.id = 'exportLogs';
            exportBtn.className = 'btn-sm';
            exportBtn.textContent = '📥 Export';
            consoleControls.appendChild(exportBtn);

            const pauseBtn = document.createElement('button');
            pauseBtn.id = 'pauseLogs';
            pauseBtn.className = 'btn-sm';
            pauseBtn.textContent = '⏸️ Pause';
            consoleControls.appendChild(pauseBtn);

            const statsBtn = document.createElement('button');
            statsBtn.id = 'showStats';
            statsBtn.className = 'btn-sm';
            statsBtn.textContent = '📊 Stats';
            statsBtn.addEventListener('click', () => {
                this.showConsoleStats();
            });
            consoleControls.appendChild(statsBtn);
        }
    }

    // Show console statistics
    showConsoleStats() {
        if (!this.advancedConsole) return;

        const stats = this.advancedConsole.getStats();
        const slowest = this.advancedConsole.getSlowestRequests(5);

        const statsHtml = `
            <div style="padding: 15px; background: #1a1a1a; border: 1px solid #333; border-radius: 4px; margin: 10px 0;">
                <h3 style="color: #0FF; margin: 0 0 10px 0;">📊 Console Statistics</h3>

                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-bottom: 15px;">
                    <div style="background: #222; padding: 10px; border-radius: 4px;">
                        <div style="color: #888; font-size: 11px;">Total Logs</div>
                        <div style="color: #0FF; font-size: 24px; font-weight: bold;">${stats.total}</div>
                    </div>
                    <div style="background: #222; padding: 10px; border-radius: 4px;">
                        <div style="color: #888; font-size: 11px;">Errors</div>
                        <div style="color: #F44; font-size: 24px; font-weight: bold;">${stats.errors}</div>
                    </div>
                    <div style="background: #222; padding: 10px; border-radius: 4px;">
                        <div style="color: #888; font-size: 11px;">Warnings</div>
                        <div style="color: #FA0; font-size: 24px; font-weight: bold;">${stats.warnings}</div>
                    </div>
                </div>

                <div style="background: #222; padding: 10px; border-radius: 4px; margin-bottom: 10px;">
                    <div style="color: #888; font-size: 11px; margin-bottom: 5px;">Network Requests</div>
                    <div style="color: #0FF; font-size: 18px;">${stats.network} requests</div>
                    <div style="color: #888; font-size: 12px;">Avg: ${stats.avgNetworkTime.toFixed(2)}ms</div>
                </div>

                <div style="background: #222; padding: 10px; border-radius: 4px;">
                    <div style="color: #888; font-size: 11px; margin-bottom: 5px;">⚠️ Slowest Requests</div>
                    ${slowest.map(req => `
                        <div style="margin: 5px 0; padding: 5px; background: #1a1a1a; border-radius: 3px;">
                            <div style="color: #0FF; font-size: 11px; font-family: monospace;">${req.method} ${req.url}</div>
                            <div style="color: #FA0; font-size: 12px;">${req.duration.toFixed(2)}ms</div>
                        </div>
                    `).join('')}
                </div>

                <button onclick="this.parentElement.remove()" style="margin-top: 10px; padding: 8px 16px; background: #444; border: none; color: #0FF; border-radius: 4px; cursor: pointer;">
                    Close
                </button>
            </div>
        `;

        const consoleOutput = document.getElementById('consoleOutput');
        if (consoleOutput) {
            const statsEl = document.createElement('div');
            statsEl.innerHTML = statsHtml;
            consoleOutput.insertBefore(statsEl.firstElementChild, consoleOutput.firstChild);
        }
    }

    setupEventListeners() {
        // Element selector
        document.getElementById('elementSelector').addEventListener('change', (e) => {
            if (e.target.value) {
                this.selectElement(parseInt(e.target.value));
            }
        });

        // Refresh button
        document.getElementById('refreshElements').addEventListener('click', () => {
            this.loadElements();
        });

        // Highlight button
        document.getElementById('highlightElement').addEventListener('click', () => {
            this.highlightElement();
        });

        // Hide/Show buttons
        document.getElementById('hideElement').addEventListener('click', () => {
            this.applyStyle('display', 'none');
        });

        document.getElementById('showElement').addEventListener('click', () => {
            this.applyStyle('display', 'block');
        });

        // Style controls
        this.setupStyleControl('width', 'widthValue', (val) => `${val}px`);
        this.setupStyleControl('height', 'heightValue', (val) => `${val}px`);
        this.setupStyleControl('padding', 'paddingValue', (val) => `${val}px`);
        this.setupStyleControl('margin', 'marginValue', (val) => `${val}px`);
        this.setupStyleControl('borderRadius', 'borderRadiusValue', (val) => `${val}px`);
        this.setupStyleControl('opacity', 'opacityValue', (val) => (val / 100).toString());
        this.setupStyleControl('fontSize', 'fontSizeValue', (val) => `${val}px`);

        // Color controls
        document.getElementById('bgColor').addEventListener('input', (e) => {
            this.applyStyle('backgroundColor', e.target.value);
        });

        document.getElementById('textColor').addEventListener('input', (e) => {
            this.applyStyle('color', e.target.value);
        });

        // Select controls
        document.getElementById('fontFamily').addEventListener('change', (e) => {
            this.applyStyle('fontFamily', e.target.value);
        });

        document.getElementById('fontWeight').addEventListener('change', (e) => {
            this.applyStyle('fontWeight', e.target.value);
        });

        document.getElementById('zIndex').addEventListener('input', (e) => {
            this.applyStyle('zIndex', e.target.value);
        });

        // Tabs
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                const tabName = e.target.dataset.tab;
                this.switchTab(tabName);
            });
        });

        // State evaluator
        document.getElementById('evaluateBtn').addEventListener('click', () => {
            this.evaluateExpression();
        });

        document.getElementById('expressionInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.evaluateExpression();
            }
        });

        // Console clear
        document.getElementById('clearConsole').addEventListener('click', () => {
            document.getElementById('consoleOutput').innerHTML = '';
        });
    }

    setupStyleControl(property, displayId, formatter) {
        const control = document.getElementById(property);
        const display = document.getElementById(displayId);

        control.addEventListener('input', (e) => {
            const value = formatter(e.target.value);
            display.textContent = value;
            this.applyStyle(property, value);
        });
    }

    switchTab(tabName) {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));

        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
        document.getElementById(`${tabName}Tab`).classList.add('active');
    }

    evaluateExpression() {
        const expression = document.getElementById('expressionInput').value;
        if (!expression) return;

        this.execute(expression, (result, error) => {
            const output = document.getElementById('stateOutput');
            const entry = document.createElement('div');
            entry.className = 'state-entry';

            if (error) {
                entry.innerHTML = `
                    <div class="state-expression">❌ ${expression}</div>
                    <div class="state-error">${error.value || error}</div>
                `;
            } else {
                entry.innerHTML = `
                    <div class="state-expression">✅ ${expression}</div>
                    <div class="state-result">${JSON.stringify(result, null, 2)}</div>
                `;
            }

            output.insertBefore(entry, output.firstChild);
        });
    }

    // Setup Security Panel
    setupSecurityPanel() {
        const runScanBtn = document.getElementById('runSecurityScan');
        const output = document.getElementById('securityOutput');

        if (runScanBtn) {
            runScanBtn.addEventListener('click', async () => {
                output.innerHTML = '<div style="text-align:center;padding:40px;color:#00FFFF;"><div style="font-size:32px;margin-bottom:10px;">🔍</div>Scanning page security...</div>';

                try {
                    const results = await this.securityPanel.runFullScan();
                    output.innerHTML = this.securityPanel.generateReport(results);
                } catch (err) {
                    output.innerHTML = `<div style="color:#ef4444;padding:20px;">Error: ${err.message}</div>`;
                }
            });
        }

        // Individual check buttons
        document.querySelectorAll('.security-check-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const check = btn.dataset.check;
                output.innerHTML = `<div style="text-align:center;padding:40px;color:#00FFFF;">Checking ${check}...</div>`;

                try {
                    let result;
                    switch (check) {
                        case 'headers': result = await this.securityPanel.analyzeHeaders(); break;
                        case 'cookies': result = await this.securityPanel.analyzeCookies(); break;
                        case 'forms': result = await this.securityPanel.analyzeForms(); break;
                        case 'storage': result = await this.securityPanel.analyzeStorage(); break;
                        case 'scripts': result = await this.securityPanel.analyzeScripts(); break;
                        case 'links': result = await this.securityPanel.analyzeLinks(); break;
                    }
                    output.innerHTML = `<pre style="color:#00FFFF;font-size:12px;white-space:pre-wrap;">${JSON.stringify(result, null, 2)}</pre>`;
                } catch (err) {
                    output.innerHTML = `<div style="color:#ef4444;">Error: ${err.message}</div>`;
                }
            });
        });
    }
}

// Initialize extension
const debugger = new ExtensionDebugger();
