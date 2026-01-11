/**
 * State Module
 * JavaScript expression evaluation and state inspection
 */

export class StateManager {
    constructor() {
        this.history = [];
        this.init();
    }

    init() {
        this.setupEventListeners();
    }

    setupEventListeners() {
        document.getElementById('evaluateBtn').addEventListener('click', () => {
            this.evaluate();
        });

        document.getElementById('expressionInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.evaluate();
            }
        });
    }

    evaluate() {
        const input = document.getElementById('expressionInput');
        const expression = input.value.trim();

        if (!expression) return;

        try {
            // Attempt to evaluate in iframe context if available
            const iframe = document.getElementById('targetFrame');
            let result;
            let context = 'debugger';

            try {
                const iframeWindow = iframe.contentWindow;
                result = iframeWindow.eval(expression);
                context = 'iframe';
            } catch (e) {
                // Fallback to debugger app context
                result = eval(expression);
            }

            this.addResult(expression, result, 'success', context);
        } catch (error) {
            this.addResult(expression, error.message, 'error', 'debugger');
        }

        // Clear input
        input.value = '';
    }

    addResult(expression, result, type, context) {
        const entry = {
            expression,
            result,
            type,
            context,
            timestamp: new Date().toLocaleTimeString(),
            id: Date.now() + Math.random()
        };

        this.history.push(entry);

        // Keep only last 100 results
        if (this.history.length > 100) {
            this.history.shift();
        }

        this.render();
    }

    render() {
        const container = document.getElementById('stateOutput');
        container.innerHTML = '';

        if (this.history.length === 0) {
            container.innerHTML = '<div style="color: #888; padding: 12px;">No evaluations yet. Try entering a JavaScript expression above.</div>';
            return;
        }

        // Render in reverse order (newest first)
        [...this.history].reverse().forEach(entry => {
            const item = document.createElement('div');
            item.style.cssText = `
                background: #0d0d0d;
                border: 1px solid #333;
                border-radius: 8px;
                padding: 12px;
                margin-bottom: 12px;
            `;

            const header = document.createElement('div');
            header.style.cssText = `
                display: flex;
                justify-content: space-between;
                margin-bottom: 8px;
                padding-bottom: 8px;
                border-bottom: 1px solid #222;
            `;

            const timestamp = document.createElement('span');
            timestamp.textContent = entry.timestamp;
            timestamp.style.color = '#888';
            timestamp.style.fontSize = '11px';

            const contextBadge = document.createElement('span');
            contextBadge.textContent = entry.context;
            contextBadge.style.cssText = `
                background: #222;
                color: #00FFFF;
                padding: 2px 8px;
                border-radius: 4px;
                font-size: 10px;
                text-transform: uppercase;
            `;

            header.appendChild(timestamp);
            header.appendChild(contextBadge);

            const exprDiv = document.createElement('div');
            exprDiv.style.cssText = `
                color: #00FFFF;
                font-family: 'Courier New', monospace;
                margin-bottom: 8px;
                word-break: break-all;
            `;
            exprDiv.textContent = `> ${entry.expression}`;

            const resultDiv = document.createElement('div');
            resultDiv.style.cssText = `
                color: ${entry.type === 'error' ? '#FF4444' : '#00FF88'};
                font-family: 'Courier New', monospace;
                padding: 8px;
                background: #111;
                border-radius: 4px;
                white-space: pre-wrap;
                word-break: break-all;
            `;

            let displayResult = entry.result;
            if (typeof entry.result === 'object' && entry.result !== null) {
                try {
                    displayResult = JSON.stringify(entry.result, null, 2);
                } catch (e) {
                    displayResult = String(entry.result);
                }
            }

            resultDiv.textContent = displayResult;

            item.appendChild(header);
            item.appendChild(exprDiv);
            item.appendChild(resultDiv);
            container.appendChild(item);
        });
    }
}

window.StateManager = StateManager;
