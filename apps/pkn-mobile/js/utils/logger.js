/**
 * Advanced Logging System for PKN Frontend
 * Captures all errors, warnings, network requests, and user actions
 * Sends logs to debugger extension and backend for analysis
 */

export class PKNLogger {
    constructor() {
        this.logs = [];
        this.maxLogs = 5000;
        this.logLevel = 'debug'; // debug, info, warn, error
        this.enableNetworkLogging = true;
        this.enableUserActionLogging = true;
        this.enablePerformanceLogging = true;

        this.init();
    }

    init() {
        this.interceptConsole();
        this.interceptErrors();
        this.interceptNetwork();
        this.interceptUserActions();
        this.interceptPerformance();
        this.setupStoragePersistence();

        console.info('🔍 PKN Logger initialized');
    }

    // Intercept all console methods
    interceptConsole() {
        const methods = ['log', 'info', 'warn', 'error', 'debug'];
        const original = {};

        methods.forEach(method => {
            original[method] = console[method];

            console[method] = (...args) => {
                // Add to our log store
                this.addLog({
                    type: 'console',
                    level: method,
                    message: args.map(arg => this.stringify(arg)).join(' '),
                    args: args,
                    timestamp: Date.now(),
                    stack: new Error().stack
                });

                // Call original
                original[method].apply(console, args);
            };
        });

        // Store originals for later use
        this._originalConsole = original;
    }

    // Intercept window errors
    interceptErrors() {
        window.addEventListener('error', (event) => {
            this.addLog({
                type: 'error',
                level: 'error',
                message: event.message,
                filename: event.filename,
                lineno: event.lineno,
                colno: event.colno,
                stack: event.error?.stack,
                timestamp: Date.now()
            });
        });

        window.addEventListener('unhandledrejection', (event) => {
            this.addLog({
                type: 'promise-rejection',
                level: 'error',
                message: event.reason?.message || String(event.reason),
                stack: event.reason?.stack,
                timestamp: Date.now()
            });
        });
    }

    // Intercept fetch/XHR requests
    interceptNetwork() {
        if (!this.enableNetworkLogging) return;

        // Intercept fetch
        const originalFetch = window.fetch;
        window.fetch = async (...args) => {
            const startTime = performance.now();
            const url = typeof args[0] === 'string' ? args[0] : args[0].url;
            const method = args[1]?.method || 'GET';

            try {
                const response = await originalFetch.apply(window, args);
                const duration = performance.now() - startTime;

                this.addLog({
                    type: 'network',
                    level: 'info',
                    method: method,
                    url: url,
                    status: response.status,
                    statusText: response.statusText,
                    duration: duration,
                    timestamp: Date.now()
                });

                return response;
            } catch (error) {
                const duration = performance.now() - startTime;

                this.addLog({
                    type: 'network',
                    level: 'error',
                    method: method,
                    url: url,
                    error: error.message,
                    duration: duration,
                    timestamp: Date.now()
                });

                throw error;
            }
        };

        // Intercept XHR
        const XHR = XMLHttpRequest.prototype;
        const originalOpen = XHR.open;
        const originalSend = XHR.send;

        XHR.open = function(method, url) {
            this._pknLogData = { method, url, startTime: performance.now() };
            return originalOpen.apply(this, arguments);
        };

        XHR.send = function() {
            const logData = this._pknLogData;

            this.addEventListener('load', function() {
                const duration = performance.now() - logData.startTime;
                window.pknLogger?.addLog({
                    type: 'network',
                    level: 'info',
                    method: logData.method,
                    url: logData.url,
                    status: this.status,
                    statusText: this.statusText,
                    duration: duration,
                    timestamp: Date.now()
                });
            });

            this.addEventListener('error', function() {
                const duration = performance.now() - logData.startTime;
                window.pknLogger?.addLog({
                    type: 'network',
                    level: 'error',
                    method: logData.method,
                    url: logData.url,
                    error: 'Network request failed',
                    duration: duration,
                    timestamp: Date.now()
                });
            });

            return originalSend.apply(this, arguments);
        };
    }

    // Log user actions (clicks, inputs, navigation)
    interceptUserActions() {
        if (!this.enableUserActionLogging) return;

        // Click logging
        document.addEventListener('click', (e) => {
            const target = e.target;
            const selector = this.getElementSelector(target);

            this.addLog({
                type: 'user-action',
                level: 'debug',
                action: 'click',
                element: target.tagName,
                selector: selector,
                text: target.textContent?.substring(0, 50),
                timestamp: Date.now()
            });
        }, true);

        // Input logging (debounced)
        let inputTimeout;
        document.addEventListener('input', (e) => {
            clearTimeout(inputTimeout);
            inputTimeout = setTimeout(() => {
                const target = e.target;
                this.addLog({
                    type: 'user-action',
                    level: 'debug',
                    action: 'input',
                    element: target.tagName,
                    name: target.name,
                    id: target.id,
                    valueLength: target.value?.length || 0,
                    timestamp: Date.now()
                });
            }, 500);
        }, true);
    }

    // Performance monitoring
    interceptPerformance() {
        if (!this.enablePerformanceLogging) return;

        // Log page load metrics
        window.addEventListener('load', () => {
            setTimeout(() => {
                const perf = performance.getEntriesByType('navigation')[0];

                this.addLog({
                    type: 'performance',
                    level: 'info',
                    metric: 'page-load',
                    domContentLoaded: perf.domContentLoadedEventEnd - perf.domContentLoadedEventStart,
                    loadComplete: perf.loadEventEnd - perf.loadEventStart,
                    domInteractive: perf.domInteractive,
                    timestamp: Date.now()
                });
            }, 0);
        });

        // Monitor long tasks (>50ms)
        if ('PerformanceObserver' in window) {
            try {
                const observer = new PerformanceObserver((list) => {
                    for (const entry of list.getEntries()) {
                        if (entry.duration > 50) {
                            this.addLog({
                                type: 'performance',
                                level: 'warn',
                                metric: 'long-task',
                                duration: entry.duration,
                                name: entry.name,
                                timestamp: Date.now()
                            });
                        }
                    }
                });

                observer.observe({ entryTypes: ['longtask', 'measure'] });
            } catch (e) {
                // PerformanceLongTaskTiming not supported
            }
        }
    }

    // Add log entry
    addLog(logEntry) {
        // Check log level filtering
        const levels = { debug: 0, info: 1, warn: 2, error: 3 };
        const currentLevel = levels[this.logLevel] || 0;
        const entryLevel = levels[logEntry.level] || 0;

        if (entryLevel < currentLevel) return;

        // Add unique ID
        logEntry.id = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

        // Add to logs
        this.logs.push(logEntry);

        // Trim if too many
        if (this.logs.length > this.maxLogs) {
            this.logs.shift();
        }

        // Persist to localStorage
        this.persist();

        // Send to debugger extension if available
        this.sendToDebugger(logEntry);

        // Send critical errors to backend
        if (logEntry.level === 'error') {
            this.sendToBackend(logEntry);
        }
    }

    // Get CSS selector for element
    getElementSelector(element) {
        if (!element) return '';

        if (element.id) {
            return `#${element.id}`;
        }

        let path = [];
        while (element && element.nodeType === Node.ELEMENT_NODE) {
            let selector = element.nodeName.toLowerCase();
            if (element.className) {
                selector += '.' + element.className.split(' ').filter(c => c).join('.');
            }
            path.unshift(selector);
            element = element.parentNode;
            if (path.length > 3) break; // Max depth
        }

        return path.join(' > ');
    }

    // Convert values to strings
    stringify(value) {
        if (value === null) return 'null';
        if (value === undefined) return 'undefined';
        if (typeof value === 'function') return value.toString();

        if (typeof value === 'object') {
            try {
                // Handle DOM elements
                if (value instanceof HTMLElement) {
                    return `<${value.tagName.toLowerCase()}${value.id ? '#' + value.id : ''}>`;
                }
                return JSON.stringify(value, null, 2);
            } catch (e) {
                return String(value);
            }
        }

        return String(value);
    }

    // Persist logs to localStorage
    setupStoragePersistence() {
        // Load existing logs on init
        try {
            const stored = localStorage.getItem('pkn_logs');
            if (stored) {
                const parsed = JSON.parse(stored);
                this.logs = parsed.slice(-1000); // Keep last 1000
            }
        } catch (e) {
            console.warn('Could not load persisted logs:', e);
        }
    }

    persist() {
        try {
            // Only persist last 1000 logs (storage limit)
            const toStore = this.logs.slice(-1000);
            localStorage.setItem('pkn_logs', JSON.stringify(toStore));
        } catch (e) {
            // Storage full, clear old logs
            this.logs = this.logs.slice(-500);
        }
    }

    // Send log to debugger extension
    sendToDebugger(log) {
        // Post message to extension if it's listening
        window.postMessage({
            type: 'PKN_LOG',
            log: log
        }, '*');
    }

    // Send critical errors to backend for analysis
    async sendToBackend(log) {
        try {
            await fetch('/api/logs/error', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(log)
            });
        } catch (e) {
            // Silent fail - don't create infinite error loop
        }
    }

    // Public API methods
    getLogs(filter = {}) {
        let filtered = [...this.logs];

        if (filter.type) {
            filtered = filtered.filter(log => log.type === filter.type);
        }

        if (filter.level) {
            filtered = filtered.filter(log => log.level === filter.level);
        }

        if (filter.search) {
            const search = filter.search.toLowerCase();
            filtered = filtered.filter(log =>
                log.message?.toLowerCase().includes(search) ||
                log.url?.toLowerCase().includes(search)
            );
        }

        if (filter.since) {
            filtered = filtered.filter(log => log.timestamp >= filter.since);
        }

        return filtered;
    }

    clearLogs() {
        this.logs = [];
        localStorage.removeItem('pkn_logs');
        console.info('Logs cleared');
    }

    setLogLevel(level) {
        this.logLevel = level;
        localStorage.setItem('pkn_log_level', level);
    }

    exportLogs() {
        const data = JSON.stringify(this.logs, null, 2);
        const blob = new Blob([data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);

        const a = document.createElement('a');
        a.href = url;
        a.download = `pkn-logs-${Date.now()}.json`;
        a.click();

        URL.revokeObjectURL(url);
    }

    // Performance mark/measure helpers
    mark(name) {
        performance.mark(name);
    }

    measure(name, startMark, endMark) {
        try {
            performance.measure(name, startMark, endMark);
            const measure = performance.getEntriesByName(name)[0];

            this.addLog({
                type: 'performance',
                level: 'info',
                metric: 'measure',
                name: name,
                duration: measure.duration,
                timestamp: Date.now()
            });
        } catch (e) {
            console.warn('Performance measure failed:', e);
        }
    }
}

// Create global instance
if (typeof window !== 'undefined') {
    window.pknLogger = new PKNLogger();
}

export default PKNLogger;
