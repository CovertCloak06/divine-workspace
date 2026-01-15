/**
 * Advanced Console for Divine Debugger Extension
 * Receives logs from PKN frontend via chrome.devtools API
 * Displays network requests, errors, performance metrics
 * Surpasses Chrome DevTools with custom features
 */

export class AdvancedConsole {
    constructor() {
        this.logs = [];
        this.filter = 'all';
        this.searchTerm = '';
        this.showExplanations = false;
        this.tabId = chrome.devtools.inspectedWindow.tabId;

        this.init();
    }

    init() {
        console.log('🚀 Advanced Console initialized');
        this.setupEventListeners();
        this.setupInspectedWindowListener();
        this.injectLoggerIntoPage();
        this.loadPersistedLogs();
    }

    // Inject our logger script into the inspected page
    injectLoggerIntoPage() {
        const code = `
            (function() {
                if (window.pknLogger) {
                    console.info('PKN Logger already loaded');
                    return;
                }

                // Load the logger script
                const script = document.createElement('script');
                script.type = 'module';
                script.src = '/js/utils/logger.js';
                document.head.appendChild(script);

                // Listen for our logs
                window.addEventListener('message', (event) => {
                    if (event.data.type === 'PKN_LOG') {
                        // Forward to extension
                        chrome.runtime.sendMessage({
                            type: 'LOG_FROM_PAGE',
                            log: event.data.log
                        });
                    }
                });
            })();
        `;

        chrome.devtools.inspectedWindow.eval(code, (result, error) => {
            if (error) {
                console.error('Failed to inject logger:', error);
            } else {
                console.info('Logger injected successfully');
            }
        });
    }

    // Listen to logs from inspected window
    setupInspectedWindowListener() {
        // Listen to console API calls
        chrome.devtools.inspectedWindow.onResourceAdded.addListener((resource) => {
            this.addLog({
                type: 'resource',
                level: 'info',
                url: resource.url,
                timestamp: Date.now()
            });
        });

        // Listen to messages from content script
        chrome.runtime.onMessage.addListener((message, sender) => {
            if (message.type === 'LOG_FROM_PAGE') {
                this.addLog(message.log);
            }
        });

        // Poll for network requests
        this.startNetworkMonitoring();
    }

    // Monitor network requests
    startNetworkMonitoring() {
        chrome.devtools.network.onRequestFinished.addListener((request) => {
            this.addLog({
                type: 'network',
                level: request.response.status >= 400 ? 'error' : 'info',
                method: request.request.method,
                url: request.request.url,
                status: request.response.status,
                statusText: request.response.statusText,
                duration: request.time,
                size: request.response.bodySize,
                timestamp: Date.now()
            });
        });
    }

    // Add log to store
    addLog(log) {
        // Ensure log has required fields
        log.id = log.id || `${Date.now()}-${Math.random()}`;
        log.timestamp = log.timestamp || Date.now();

        this.logs.push(log);

        // Limit to 10000 logs
        if (this.logs.length > 10000) {
            this.logs.shift();
        }

        this.renderLogs();
        this.persistLogs();
    }

    // Render logs to console output
    renderLogs() {
        const container = document.getElementById('consoleOutput');
        if (!container) return;

        // Apply filters
        let filtered = this.filterLogs();

        // Clear container
        container.innerHTML = '';

        if (filtered.length === 0) {
            container.innerHTML = '<div class="empty-state">No logs match current filters</div>';
            return;
        }

        // Render each log
        filtered.forEach(log => {
            const logElement = this.createLogElement(log);
            container.appendChild(logElement);
        });

        // Auto-scroll to bottom
        container.scrollTop = container.scrollHeight;
    }

    // Filter logs based on current filter settings
    filterLogs() {
        let filtered = [...this.logs];

        // Filter by type/level
        if (this.filter !== 'all') {
            filtered = filtered.filter(log =>
                log.level === this.filter || log.type === this.filter
            );
        }

        // Filter by search term
        if (this.searchTerm) {
            const search = this.searchTerm.toLowerCase();
            filtered = filtered.filter(log => {
                const message = String(log.message || '').toLowerCase();
                const url = String(log.url || '').toLowerCase();
                return message.includes(search) || url.includes(search);
            });
        }

        return filtered;
    }

    // Create HTML element for a log entry
    createLogElement(log) {
        const entry = document.createElement('div');
        entry.className = `log-entry log-${log.type} log-${log.level}`;
        entry.dataset.logId = log.id;

        // Timestamp
        const time = new Date(log.timestamp).toLocaleTimeString();

        // Icon based on type
        const icon = this.getLogIcon(log);

        // Build content based on log type
        let content = '';

        switch (log.type) {
            case 'console':
                content = `
                    <div class="log-header">
                        <span class="log-icon">${icon}</span>
                        <span class="log-time">${time}</span>
                        <span class="log-level">${log.level}</span>
                    </div>
                    <div class="log-message">${this.formatMessage(log.message)}</div>
                    ${log.stack ? `<div class="log-stack">${this.formatStack(log.stack)}</div>` : ''}
                `;
                break;

            case 'network':
                const statusColor = log.status >= 400 ? '#FF4444' : '#00FF00';
                content = `
                    <div class="log-header">
                        <span class="log-icon">${icon}</span>
                        <span class="log-time">${time}</span>
                        <span class="log-method">${log.method}</span>
                        <span class="log-status" style="color: ${statusColor}">${log.status}</span>
                        <span class="log-duration">${log.duration.toFixed(2)}ms</span>
                    </div>
                    <div class="log-message">${log.url}</div>
                    ${log.error ? `<div class="log-error">${log.error}</div>` : ''}
                `;
                break;

            case 'error':
            case 'promise-rejection':
                content = `
                    <div class="log-header">
                        <span class="log-icon">${icon}</span>
                        <span class="log-time">${time}</span>
                        <span class="log-level">ERROR</span>
                    </div>
                    <div class="log-message error-message">${log.message}</div>
                    ${log.filename ? `<div class="log-file">${log.filename}:${log.lineno}:${log.colno}</div>` : ''}
                    ${log.stack ? `<div class="log-stack">${this.formatStack(log.stack)}</div>` : ''}
                `;
                break;

            case 'performance':
                content = `
                    <div class="log-header">
                        <span class="log-icon">${icon}</span>
                        <span class="log-time">${time}</span>
                        <span class="log-metric">${log.metric}</span>
                        ${log.duration ? `<span class="log-duration">${log.duration.toFixed(2)}ms</span>` : ''}
                    </div>
                    <div class="log-message">${log.name || log.metric}</div>
                `;
                break;

            case 'user-action':
                content = `
                    <div class="log-header">
                        <span class="log-icon">${icon}</span>
                        <span class="log-time">${time}</span>
                        <span class="log-action">${log.action}</span>
                    </div>
                    <div class="log-message">${log.selector || log.element}</div>
                `;
                break;

            default:
                content = `
                    <div class="log-header">
                        <span class="log-icon">${icon}</span>
                        <span class="log-time">${time}</span>
                    </div>
                    <div class="log-message">${JSON.stringify(log, null, 2)}</div>
                `;
        }

        entry.innerHTML = content;

        // Make clickable for details
        entry.addEventListener('click', () => {
            this.showLogDetails(log);
        });

        return entry;
    }

    // Get icon for log type
    getLogIcon(log) {
        const icons = {
            console: {
                log: '📝',
                info: 'ℹ️',
                warn: '⚠️',
                error: '❌',
                debug: '🐛'
            },
            network: '🌐',
            error: '💥',
            'promise-rejection': '🚫',
            performance: '⚡',
            'user-action': '👆'
        };

        if (log.type === 'console') {
            return icons.console[log.level] || '📝';
        }

        return icons[log.type] || '📋';
    }

    // Format message with syntax highlighting
    formatMessage(message) {
        if (!message) return '';

        // Escape HTML
        message = String(message).replace(/</g, '&lt;').replace(/>/g, '&gt;');

        // Highlight JSON
        try {
            const parsed = JSON.parse(message);
            message = `<pre>${JSON.stringify(parsed, null, 2)}</pre>`;
        } catch (e) {
            // Not JSON, keep as is
        }

        return message;
    }

    // Format stack trace with clickable links
    formatStack(stack) {
        if (!stack) return '';

        const lines = stack.split('\n');
        const formatted = lines.map(line => {
            // Match file:line:col patterns
            const match = line.match(/([^/]+):(\d+):(\d+)/);
            if (match) {
                const [, file, lineno, colno] = match;
                return `<span class="stack-line" data-file="${file}" data-line="${lineno}" data-col="${colno}">${line}</span>`;
            }
            return `<span class="stack-line">${line}</span>`;
        });

        return formatted.join('\n');
    }

    // Show detailed log information in modal/sidebar
    showLogDetails(log) {
        // TODO: Implement modal or side panel for detailed log view
        console.log('Log details:', log);
    }

    // Event listeners for UI controls
    setupEventListeners() {
        // Clear console
        const clearBtn = document.getElementById('clearConsole');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                this.logs = [];
                this.renderLogs();
                localStorage.removeItem('debugger_logs');
            });
        }

        // Log level filter
        const levelSelect = document.getElementById('logLevel');
        if (levelSelect) {
            levelSelect.addEventListener('change', (e) => {
                this.filter = e.target.value;
                this.renderLogs();
            });
        }

        // Search filter
        const searchInput = document.getElementById('logSearch');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.searchTerm = e.target.value;
                this.renderLogs();
            });
        }

        // Export logs
        const exportBtn = document.getElementById('exportLogs');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                this.exportLogs();
            });
        }

        // Pause logging
        const pauseBtn = document.getElementById('pauseLogs');
        if (pauseBtn) {
            pauseBtn.addEventListener('click', () => {
                this.paused = !this.paused;
                pauseBtn.textContent = this.paused ? '▶️ Resume' : '⏸️ Pause';
            });
        }
    }

    // Persist logs to chrome.storage
    persistLogs() {
        try {
            // Only persist last 1000 logs
            const toStore = this.logs.slice(-1000);
            localStorage.setItem('debugger_logs', JSON.stringify(toStore));
        } catch (e) {
            console.warn('Failed to persist logs:', e);
        }
    }

    // Load persisted logs
    loadPersistedLogs() {
        try {
            const stored = localStorage.getItem('debugger_logs');
            if (stored) {
                this.logs = JSON.parse(stored);
                this.renderLogs();
            }
        } catch (e) {
            console.warn('Failed to load persisted logs:', e);
        }
    }

    // Export logs to JSON file
    exportLogs() {
        const data = JSON.stringify(this.logs, null, 2);
        const blob = new Blob([data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);

        const a = document.createElement('a');
        a.href = url;
        a.download = `debugger-logs-${Date.now()}.json`;
        a.click();

        URL.revokeObjectURL(url);
    }

    // Advanced features beyond Chrome DevTools

    // Group similar logs
    groupSimilar() {
        // TODO: Group consecutive similar logs (like Chrome does)
    }

    // Filter by time range
    filterByTimeRange(start, end) {
        return this.logs.filter(log =>
            log.timestamp >= start && log.timestamp <= end
        );
    }

    // Get statistics
    getStats() {
        return {
            total: this.logs.length,
            errors: this.logs.filter(l => l.level === 'error').length,
            warnings: this.logs.filter(l => l.level === 'warn').length,
            network: this.logs.filter(l => l.type === 'network').length,
            avgNetworkTime: this.getAvgNetworkTime(),
            slowestRequests: this.getSlowestRequests(5)
        };
    }

    getAvgNetworkTime() {
        const networkLogs = this.logs.filter(l => l.type === 'network' && l.duration);
        if (networkLogs.length === 0) return 0;

        const total = networkLogs.reduce((sum, log) => sum + log.duration, 0);
        return total / networkLogs.length;
    }

    getSlowestRequests(count = 5) {
        return this.logs
            .filter(l => l.type === 'network' && l.duration)
            .sort((a, b) => b.duration - a.duration)
            .slice(0, count);
    }
}

export default AdvancedConsole;
