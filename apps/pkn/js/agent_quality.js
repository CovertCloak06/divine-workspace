/**
 * Agent Quality Monitoring System
 * Tracks performance, errors, and provides health checks
 */

class AgentQualityMonitor {
    constructor() {
        this.metrics = {
            totalRequests: 0,
            successfulRequests: 0,
            failedRequests: 0,
            averageResponseTime: 0,
            agentPerformance: {},
            errorLog: [],
            healthStatus: 'unknown'
        };

        this.performanceThresholds = {
            fast: 5000,      // < 5s is fast
            acceptable: 30000, // < 30s is acceptable
            slow: 120000     // < 120s is slow (but tolerable)
        };

        this.init();
    }

    init() {
        // Run initial health check
        this.runHealthCheck();

        // Periodic health check every 5 minutes
        setInterval(() => this.runHealthCheck(), 300000);

        // Create stats panel (hidden by default)
        this.createStatsPanel();

        console.log('[QualityMonitor] Initialized');
    }

    async runHealthCheck() {
        try {
            // Check backend health
            const response = await fetch('/health');
            const data = await response.json();

            this.metrics.healthStatus = response.ok ? 'healthy' : 'degraded';

            // Check multi-agent availability
            try {
                const agentsResponse = await fetch('/api/multi-agent/agents');
                const agentsData = await agentsResponse.json();

                if (agentsData.status === 'success') {
                    this.metrics.healthStatus = 'healthy';
                    console.log(`[QualityMonitor] Health check: OK (${agentsData.count} agents)`);
                }
            } catch (e) {
                this.metrics.healthStatus = 'degraded';
                console.warn('[QualityMonitor] Multi-agent system unavailable');
            }

        } catch (error) {
            this.metrics.healthStatus = 'unhealthy';
            console.error('[QualityMonitor] Health check failed:', error);
        }

        this.updateStatsPanel();
    }

    trackRequest(agentType, startTime) {
        const endTime = Date.now();
        const duration = endTime - startTime;

        this.metrics.totalRequests++;

        // Update average response time
        const prevAvg = this.metrics.averageResponseTime;
        const prevCount = this.metrics.totalRequests - 1;
        this.metrics.averageResponseTime = (prevAvg * prevCount + duration) / this.metrics.totalRequests;

        // Track per-agent performance
        if (!this.metrics.agentPerformance[agentType]) {
            this.metrics.agentPerformance[agentType] = {
                requests: 0,
                totalTime: 0,
                avgTime: 0,
                errors: 0
            };
        }

        const agentStats = this.metrics.agentPerformance[agentType];
        agentStats.requests++;
        agentStats.totalTime += duration;
        agentStats.avgTime = agentStats.totalTime / agentStats.requests;

        return this.getPerformanceRating(duration);
    }

    trackSuccess(agentType) {
        this.metrics.successfulRequests++;
        console.log(`[QualityMonitor] Success: ${agentType} (${this.getSuccessRate().toFixed(1)}% success rate)`);
        this.updateStatsPanel();
    }

    trackError(agentType, error, context = {}) {
        this.metrics.failedRequests++;

        const errorEntry = {
            timestamp: new Date().toISOString(),
            agent: agentType,
            error: error.message || error,
            context: context
        };

        this.metrics.errorLog.push(errorEntry);

        // Keep only last 50 errors
        if (this.metrics.errorLog.length > 50) {
            this.metrics.errorLog.shift();
        }

        // Update agent stats
        if (this.metrics.agentPerformance[agentType]) {
            this.metrics.agentPerformance[agentType].errors++;
        }

        console.error(`[QualityMonitor] Error: ${agentType}`, error);
        this.updateStatsPanel();

        return errorEntry;
    }

    getPerformanceRating(duration) {
        if (duration < this.performanceThresholds.fast) {
            return {
                rating: 'fast',
                label: 'Fast',
                color: '#0f0',
                emoji: '⚡'
            };
        } else if (duration < this.performanceThresholds.acceptable) {
            const themeColor = getComputedStyle(document.documentElement).getPropertyValue('--theme-primary').trim() || '#00ffff';
            return {
                rating: 'acceptable',
                label: 'Normal',
                color: themeColor,
                emoji: '✓'
            };
        } else if (duration < this.performanceThresholds.slow) {
            return {
                rating: 'slow',
                label: 'Slow',
                color: '#f60',
                emoji: '🐌'
            };
        } else {
            return {
                rating: 'very_slow',
                label: 'Very Slow',
                color: '#f00',
                emoji: '⚠️'
            };
        }
    }

    getSuccessRate() {
        if (this.metrics.totalRequests === 0) return 0;
        return (this.metrics.successfulRequests / this.metrics.totalRequests) * 100;
    }

    getHealthBadge() {
        const status = this.metrics.healthStatus;
        const badges = {
            'healthy': { emoji: '✅', text: 'Healthy', color: '#0f0' },
            'degraded': { emoji: '⚠️', text: 'Degraded', color: '#ff0' },
            'unhealthy': { emoji: '❌', text: 'Unhealthy', color: '#f00' },
            'unknown': { emoji: '❓', text: 'Unknown', color: '#999' }
        };
        return badges[status] || badges.unknown;
    }

    createStatsPanel() {
        const panel = document.createElement('div');
        panel.id = 'agentStatsPanel';
        panel.className = 'agent-stats-panel';
        panel.innerHTML = `
            <div class="agent-stats-title">
                🔍 Agent Quality Monitor
                <button style="float: right; background: none; border: none; color: var(--theme-primary); cursor: pointer; font-size: 16px;"
                        onclick="document.getElementById('agentStatsPanel').classList.remove('visible')">
                    ×
                </button>
            </div>
            <div id="agentStatsContent"></div>
            <div style="margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--theme-primary-fade);">
                <button class="retry-btn" onclick="window.agentQualityMonitor.runHealthCheck()" style="width: 100%;">
                    Refresh Health Check
                </button>
            </div>
        `;
        document.body.appendChild(panel);

        // Add toggle button to sidebar
        this.addStatsToggle();
    }

    addStatsToggle() {
        const sidebarFooter = document.querySelector('.sidebar-footer');
        if (!sidebarFooter) return;

        const toggle = document.createElement('div');
        toggle.className = 'settings-link';
        toggle.onclick = () => this.toggleStatsPanel();
        toggle.innerHTML = `
            <span class="settings-icon">📊</span>
            <span>Quality Monitor</span>
        `;

        sidebarFooter.insertBefore(toggle, sidebarFooter.firstChild);
    }

    toggleStatsPanel() {
        const panel = document.getElementById('agentStatsPanel');
        if (panel) {
            panel.classList.toggle('visible');
            this.updateStatsPanel();
        }
    }

    updateStatsPanel() {
        const content = document.getElementById('agentStatsContent');
        if (!content) return;

        const health = this.getHealthBadge();
        const successRate = this.getSuccessRate();

        let html = `
            <div class="agent-stat-item">
                <span>Health Status:</span>
                <span class="agent-stat-value" style="color: ${health.color}">${health.emoji} ${health.text}</span>
            </div>
            <div class="agent-stat-item">
                <span>Total Requests:</span>
                <span class="agent-stat-value">${this.metrics.totalRequests}</span>
            </div>
            <div class="agent-stat-item">
                <span>Success Rate:</span>
                <span class="agent-stat-value">${successRate.toFixed(1)}%</span>
            </div>
            <div class="agent-stat-item">
                <span>Avg Response:</span>
                <span class="agent-stat-value">${(this.metrics.averageResponseTime / 1000).toFixed(2)}s</span>
            </div>
        `;

        // Per-agent stats
        if (Object.keys(this.metrics.agentPerformance).length > 0) {
            html += '<div style="margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--theme-primary-fade);"><strong style="color: var(--theme-primary); font-size: 12px;">Per-Agent Stats:</strong></div>';

            for (const [agent, stats] of Object.entries(this.metrics.agentPerformance)) {
                const rating = this.getPerformanceRating(stats.avgTime);
                html += `
                    <div class="agent-stat-item" style="margin-top: 8px;">
                        <span>${agent}:</span>
                        <span class="agent-stat-value" style="color: ${rating.color}">
                            ${rating.emoji} ${(stats.avgTime / 1000).toFixed(1)}s
                            (${stats.requests})
                        </span>
                    </div>
                `;
            }
        }

        // Recent errors
        if (this.metrics.errorLog.length > 0) {
            html += '<div style="margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--theme-primary-fade);"><strong style="color: #f60; font-size: 12px;">Recent Errors (${this.metrics.errorLog.length}):</strong></div>';

            const recentErrors = this.metrics.errorLog.slice(-3).reverse();
            recentErrors.forEach(err => {
                html += `
                    <div style="margin-top: 6px; font-size: 10px; color: #f60; border-left: 2px solid #f60; padding-left: 6px;">
                        ${err.agent}: ${err.error.substring(0, 40)}...
                    </div>
                `;
            });
        }

        content.innerHTML = html;
    }

    // Retry helper for failed requests
    async retryRequest(requestFn, maxRetries = 2, delay = 2000) {
        let lastError;

        for (let attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                if (attempt > 0) {
                    console.log(`[QualityMonitor] Retry attempt ${attempt}/${maxRetries}`);
                    await new Promise(resolve => setTimeout(resolve, delay * attempt));
                }

                const result = await requestFn();
                return result;
            } catch (error) {
                lastError = error;
                console.warn(`[QualityMonitor] Attempt ${attempt + 1} failed:`, error.message);
            }
        }

        throw lastError;
    }

    // Export metrics for debugging
    exportMetrics() {
        const data = {
            ...this.metrics,
            exportedAt: new Date().toISOString(),
            successRate: this.getSuccessRate(),
            health: this.getHealthBadge()
        };

        console.log('[QualityMonitor] Metrics:', data);
        return data;
    }
}

// Initialize quality monitor
let agentQualityMonitor;
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        agentQualityMonitor = new AgentQualityMonitor();
        window.agentQualityMonitor = agentQualityMonitor;
    });
} else {
    agentQualityMonitor = new AgentQualityMonitor();
    window.agentQualityMonitor = agentQualityMonitor;
}
