/**
 * Console Module
 * Real-time console logging with filtering
 */

export class ConsoleLogger {
    constructor() {
        this.logs = [];
        this.filter = 'all';
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.interceptConsole();
        this.addWelcomeMessage();
    }

    setupEventListeners() {
        document.getElementById('clearConsole').addEventListener('click', () => {
            this.clear();
        });

        document.getElementById('logLevel').addEventListener('change', (e) => {
            this.filter = e.target.value;
            this.render();
        });
    }

    interceptConsole() {
        // Store original console methods
        const originalLog = console.log;
        const originalWarn = console.warn;
        const originalError = console.error;
        const originalInfo = console.info;

        // Intercept console.log
        console.log = (...args) => {
            this.addLog('log', args);
            originalLog.apply(console, args);
        };

        // Intercept console.warn
        console.warn = (...args) => {
            this.addLog('warn', args);
            originalWarn.apply(console, args);
        };

        // Intercept console.error
        console.error = (...args) => {
            this.addLog('error', args);
            originalError.apply(console, args);
        };

        // Intercept console.info
        console.info = (...args) => {
            this.addLog('info', args);
            originalInfo.apply(console, args);
        };
    }

    addWelcomeMessage() {
        this.addLog('info', ['Debugger App Console initialized']);
        this.addLog('info', ['All console messages will appear here']);
    }

    addLog(level, args) {
        const log = {
            level,
            message: args.map(arg => this.stringify(arg)).join(' '),
            timestamp: new Date().toLocaleTimeString(),
            id: Date.now() + Math.random()
        };

        this.logs.push(log);

        // Keep only last 1000 logs
        if (this.logs.length > 1000) {
            this.logs.shift();
        }

        this.render();
    }

    stringify(value) {
        if (typeof value === 'object') {
            try {
                return JSON.stringify(value, null, 2);
            } catch (e) {
                return String(value);
            }
        }
        return String(value);
    }

    render() {
        const container = document.getElementById('consoleOutput');
        container.innerHTML = '';

        const filtered = this.filter === 'all'
            ? this.logs
            : this.logs.filter(log => log.level === this.filter);

        if (filtered.length === 0) {
            container.innerHTML = '<div style="color: #888; padding: 12px;">No logs to display</div>';
            return;
        }

        filtered.forEach(log => {
            const entry = document.createElement('div');
            entry.className = `log-entry ${log.level}`;
            entry.innerHTML = `
                <span style="color: #888; margin-right: 8px;">[${log.timestamp}]</span>
                <span style="color: #00FFFF; margin-right: 8px;">[${log.level.toUpperCase()}]</span>
                <span>${this.escapeHtml(log.message)}</span>
            `;
            container.appendChild(entry);
        });

        // Auto-scroll to bottom
        container.scrollTop = container.scrollHeight;
    }

    clear() {
        this.logs = [];
        this.render();
        console.info('Console cleared');
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

window.ConsoleLogger = ConsoleLogger;
