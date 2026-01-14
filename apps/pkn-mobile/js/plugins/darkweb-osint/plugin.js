/**
 * Dark Web OSINT Plugin
 * Threat intelligence and breach monitoring for security research
 *
 * EDUCATIONAL/RESEARCH USE ONLY
 * This plugin is intended for legitimate security research and defensive purposes.
 */

import { PluginBase } from '../../features/plugin-base.js';

export class DarkWebOSINTPlugin extends PluginBase {
    constructor(manifest) {
        super(manifest);
        this.breachCache = new Map();
        this.monitoredEmails = [];
        this.threatFeeds = [];
    }

    async init() {
        await super.init();

        const defaults = {
            alertOnBreaches: true,
            monitoredEmails: '',
            apiKey: ''
        };
        this.loadSettings({ ...defaults, ...this.getSettings() });

        // Load monitored emails
        this.loadMonitoredEmails();

        this.injectCSS(this.getCSS());
    }

    async enable() {
        await super.enable();

        // Add OSINT button to sidebar
        this.addOSINTButton();

        // Periodic breach monitoring
        if (this.getSetting('alertOnBreaches', true) && this.monitoredEmails.length > 0) {
            this.startBreachMonitoring();
        }

        // Make globally available
        window.darkWebOSINT = this;

        console.log(`[${this.name}] Dark Web OSINT active (research mode)`);
    }

    async disable() {
        await super.disable();
        this.removeOSINTButton();
        this.hideOSINTPanel();
        this.stopBreachMonitoring();
    }

    /**
     * Add OSINT button to sidebar
     */
    addOSINTButton() {
        const sidebar = document.querySelector('.sidebar');
        if (!sidebar) return;

        const button = document.createElement('div');
        button.className = 'sidebar-section-header clickable';
        button.id = 'darkWebOSINTBtn';
        button.innerHTML = '<span>🕵️ Dark Web OSINT</span>';
        button.onclick = () => this.showOSINTPanel();

        // Insert after OSINT Tools section
        const osintSection = document.querySelector('.sidebar-section-header[onclick*="openOSINTTools"]');
        if (osintSection) {
            osintSection.parentNode.insertBefore(button, osintSection.nextSibling);
        }
    }

    /**
     * Remove OSINT button
     */
    removeOSINTButton() {
        const button = document.getElementById('darkWebOSINTBtn');
        if (button) button.remove();
    }

    /**
     * Show OSINT panel
     */
    showOSINTPanel() {
        // Remove existing panel
        this.hideOSINTPanel();

        const panel = document.createElement('div');
        panel.id = 'darkWebOSINTPanel';
        panel.className = 'darkweb-osint-panel';

        let html = `
            <div class="osint-panel-header">
                <div class="osint-panel-title">🕵️ Dark Web OSINT Research</div>
                <button class="osint-panel-close" onclick="window.darkWebOSINT.hideOSINTPanel()">×</button>
            </div>
            <div class="osint-warning">
                ⚠️ Educational/Research Use Only - Use responsibly and ethically
            </div>
            <div class="osint-panel-body">
                <div class="osint-tabs">
                    <button class="osint-tab active" onclick="window.darkWebOSINT.switchTab('breach')">
                        Breach Lookup
                    </button>
                    <button class="osint-tab" onclick="window.darkWebOSINT.switchTab('monitor')">
                        Monitoring
                    </button>
                    <button class="osint-tab" onclick="window.darkWebOSINT.switchTab('threat')">
                        Threat Intel
                    </button>
                    <button class="osint-tab" onclick="window.darkWebOSINT.switchTab('onion')">
                        .onion Tools
                    </button>
                </div>
                <div class="osint-tab-content" id="osintTabContent">
                    ${this.renderBreachTab()}
                </div>
            </div>
        `;

        panel.innerHTML = html;
        document.body.appendChild(panel);

        setTimeout(() => panel.classList.add('visible'), 10);
    }

    /**
     * Hide OSINT panel
     */
    hideOSINTPanel() {
        const panel = document.getElementById('darkWebOSINTPanel');
        if (panel) {
            panel.classList.remove('visible');
            setTimeout(() => panel.remove(), 300);
        }
    }

    /**
     * Switch tabs
     */
    switchTab(tabName) {
        const tabs = document.querySelectorAll('.osint-tab');
        tabs.forEach(tab => tab.classList.remove('active'));

        const activeTab = Array.from(tabs).find(tab =>
            tab.textContent.toLowerCase().includes(tabName)
        );
        if (activeTab) activeTab.classList.add('active');

        const content = document.getElementById('osintTabContent');
        if (!content) return;

        switch (tabName) {
            case 'breach':
                content.innerHTML = this.renderBreachTab();
                break;
            case 'monitor':
                content.innerHTML = this.renderMonitorTab();
                break;
            case 'threat':
                content.innerHTML = this.renderThreatTab();
                break;
            case 'onion':
                content.innerHTML = this.renderOnionTab();
                break;
        }
    }

    /**
     * Render breach lookup tab
     */
    renderBreachTab() {
        return `
            <div class="osint-section">
                <div class="section-title">Data Breach Lookup</div>
                <div class="section-description">
                    Check if an email address has appeared in known data breaches
                </div>
                <div class="osint-input-group">
                    <input type="email" id="breachEmailInput" placeholder="Enter email address..."
                           class="osint-input" />
                    <button class="osint-btn primary" onclick="window.darkWebOSINT.checkBreach()">
                        🔍 Check Breaches
                    </button>
                </div>
                <div id="breachResults" class="osint-results"></div>
            </div>
        `;
    }

    /**
     * Render monitoring tab
     */
    renderMonitorTab() {
        let html = `
            <div class="osint-section">
                <div class="section-title">Email Breach Monitoring</div>
                <div class="section-description">
                    Monitor email addresses for new breaches
                </div>
                <div class="osint-input-group">
                    <input type="email" id="monitorEmailInput" placeholder="Enter email to monitor..."
                           class="osint-input" />
                    <button class="osint-btn primary" onclick="window.darkWebOSINT.addMonitoredEmail()">
                        + Add Email
                    </button>
                </div>
        `;

        if (this.monitoredEmails.length > 0) {
            html += '<div class="monitored-list">';
            this.monitoredEmails.forEach((email, idx) => {
                html += `
                    <div class="monitored-item">
                        <span class="monitored-email">${email}</span>
                        <button class="osint-btn-small" onclick="window.darkWebOSINT.removeMonitoredEmail(${idx})">
                            Remove
                        </button>
                    </div>
                `;
            });
            html += '</div>';
        } else {
            html += '<div class="osint-empty">No emails being monitored</div>';
        }

        html += '</div>';
        return html;
    }

    /**
     * Render threat intel tab
     */
    renderThreatTab() {
        return `
            <div class="osint-section">
                <div class="section-title">Threat Intelligence Feeds</div>
                <div class="section-description">
                    Access threat intelligence from public sources
                </div>
                <div class="threat-feeds">
                    <div class="feed-item">
                        <div class="feed-name">🔴 Recent CVEs</div>
                        <div class="feed-desc">Latest security vulnerabilities</div>
                        <button class="osint-btn" onclick="window.darkWebOSINT.fetchThreatFeed('cve')">
                            View Feed
                        </button>
                    </div>
                    <div class="feed-item">
                        <div class="feed-name">🟠 Malware Hashes</div>
                        <div class="feed-desc">Known malicious file signatures</div>
                        <button class="osint-btn" onclick="window.darkWebOSINT.fetchThreatFeed('malware')">
                            View Feed
                        </button>
                    </div>
                    <div class="feed-item">
                        <div class="feed-name">🟡 Phishing Domains</div>
                        <div class="feed-desc">Recently detected phishing sites</div>
                        <button class="osint-btn" onclick="window.darkWebOSINT.fetchThreatFeed('phishing')">
                            View Feed
                        </button>
                    </div>
                    <div class="feed-item">
                        <div class="feed-name">🔵 Botnet C&C</div>
                        <div class="feed-desc">Command & control servers</div>
                        <button class="osint-btn" onclick="window.darkWebOSINT.fetchThreatFeed('botnet')">
                            View Feed
                        </button>
                    </div>
                </div>
                <div id="threatResults" class="osint-results"></div>
            </div>
        `;
    }

    /**
     * Render onion tools tab
     */
    renderOnionTab() {
        return `
            <div class="osint-section">
                <div class="section-title">.onion Domain Tools</div>
                <div class="section-description">
                    Research tools for .onion addresses (Tor network)
                </div>
                <div class="osint-input-group">
                    <input type="text" id="onionDomainInput" placeholder="Enter .onion address..."
                           class="osint-input" />
                    <button class="osint-btn primary" onclick="window.darkWebOSINT.checkOnion()">
                        🧅 Analyze
                    </button>
                </div>
                <div class="onion-tools">
                    <div class="tool-item">
                        <div class="tool-name">📊 Domain Info</div>
                        <div class="tool-desc">Check .onion address validity and structure</div>
                    </div>
                    <div class="tool-item">
                        <div class="tool-name">🔍 Public Directory</div>
                        <div class="tool-desc">Search known .onion sites (research databases)</div>
                    </div>
                    <div class="tool-item">
                        <div class="tool-name">⚠️ Safety Check</div>
                        <div class="tool-desc">Check against known malicious .onion addresses</div>
                    </div>
                </div>
                <div id="onionResults" class="osint-results"></div>
                <div class="osint-note">
                    ⚠️ Note: Actual Tor connections require Tor Browser. This tool provides metadata only.
                </div>
            </div>
        `;
    }

    /**
     * Check breach (using HaveIBeenPwned API or similar)
     */
    async checkBreach() {
        const input = document.getElementById('breachEmailInput');
        const results = document.getElementById('breachResults');

        if (!input || !results) return;

        const email = input.value.trim();
        if (!email || !this.isValidEmail(email)) {
            this.showToast('Please enter a valid email address', 3000, 'error');
            return;
        }

        results.innerHTML = '<div class="osint-loading">Checking breaches...</div>';

        try {
            // Check if we have it cached
            if (this.breachCache.has(email)) {
                const cached = this.breachCache.get(email);
                results.innerHTML = this.renderBreachResults(cached);
                return;
            }

            // In a real implementation, this would call HaveIBeenPwned API
            // For now, show a demo result
            await new Promise(resolve => setTimeout(resolve, 1500));

            const mockResult = {
                breaches: [
                    {
                        name: 'Example Breach 2023',
                        domain: 'example.com',
                        date: '2023-05-15',
                        compromised: ['Emails', 'Passwords', 'Usernames']
                    },
                    {
                        name: 'Demo Leak 2024',
                        domain: 'demo.org',
                        date: '2024-01-10',
                        compromised: ['Emails', 'Phone Numbers']
                    }
                ],
                count: 2
            };

            this.breachCache.set(email, mockResult);
            results.innerHTML = this.renderBreachResults(mockResult);

            this.showToast(`Found ${mockResult.count} breaches`, 3000, 'warning');

        } catch (error) {
            results.innerHTML = `<div class="osint-error">Error: ${error.message}</div>`;
            this.showToast('Breach check failed', 3000, 'error');
        }
    }

    /**
     * Render breach results
     */
    renderBreachResults(data) {
        if (!data.breaches || data.breaches.length === 0) {
            return '<div class="osint-success">✅ No breaches found for this email</div>';
        }

        let html = `
            <div class="osint-warning-box">
                ⚠️ Found ${data.count} breach${data.count === 1 ? '' : 'es'}
            </div>
            <div class="breach-list">
        `;

        data.breaches.forEach(breach => {
            html += `
                <div class="breach-item">
                    <div class="breach-header">
                        <div class="breach-name">${breach.name}</div>
                        <div class="breach-date">${breach.date}</div>
                    </div>
                    <div class="breach-domain">${breach.domain}</div>
                    <div class="breach-data">
                        Compromised: ${breach.compromised.join(', ')}
                    </div>
                </div>
            `;
        });

        html += '</div>';
        return html;
    }

    /**
     * Add monitored email
     */
    addMonitoredEmail() {
        const input = document.getElementById('monitorEmailInput');
        if (!input) return;

        const email = input.value.trim();
        if (!email || !this.isValidEmail(email)) {
            this.showToast('Please enter a valid email address', 3000, 'error');
            return;
        }

        if (this.monitoredEmails.includes(email)) {
            this.showToast('Email already being monitored', 2000, 'info');
            return;
        }

        this.monitoredEmails.push(email);
        this.saveMonitoredEmails();

        input.value = '';
        this.switchTab('monitor'); // Refresh tab

        this.showToast('Email added to monitoring', 2000, 'success');
    }

    /**
     * Remove monitored email
     */
    removeMonitoredEmail(index) {
        if (index >= 0 && index < this.monitoredEmails.length) {
            this.monitoredEmails.splice(index, 1);
            this.saveMonitoredEmails();
            this.switchTab('monitor'); // Refresh tab
            this.showToast('Email removed from monitoring', 2000, 'success');
        }
    }

    /**
     * Fetch threat feed
     */
    async fetchThreatFeed(feedType) {
        const results = document.getElementById('threatResults');
        if (!results) return;

        results.innerHTML = '<div class="osint-loading">Loading threat feed...</div>';

        // Mock threat feed data
        await new Promise(resolve => setTimeout(resolve, 1000));

        const mockFeeds = {
            cve: [
                { id: 'CVE-2024-0001', severity: 'Critical', description: 'Example vulnerability in web server' },
                { id: 'CVE-2024-0002', severity: 'High', description: 'Buffer overflow in network service' },
                { id: 'CVE-2024-0003', severity: 'Medium', description: 'XSS vulnerability in web app' }
            ],
            malware: [
                { hash: 'a1b2c3d4e5f6...', name: 'ExampleTrojan', type: 'Trojan' },
                { hash: 'f6e5d4c3b2a1...', name: 'DemoRansomware', type: 'Ransomware' }
            ],
            phishing: [
                { domain: 'evil-example.com', reported: '2024-01-15', status: 'Active' },
                { domain: 'fake-bank.net', reported: '2024-01-14', status: 'Taken down' }
            ],
            botnet: [
                { ip: '192.0.2.1', port: '8080', malware: 'ExampleBot', status: 'Active' },
                { ip: '198.51.100.1', port: '443', malware: 'DemoBot', status: 'Sinkholed' }
            ]
        };

        const feed = mockFeeds[feedType] || [];
        results.innerHTML = this.renderThreatFeed(feedType, feed);
    }

    /**
     * Render threat feed
     */
    renderThreatFeed(type, data) {
        let html = `<div class="threat-feed-results">`;

        data.forEach(item => {
            html += '<div class="threat-item">';
            Object.entries(item).forEach(([key, value]) => {
                html += `<div><strong>${key}:</strong> ${value}</div>`;
            });
            html += '</div>';
        });

        html += '</div>';
        return html;
    }

    /**
     * Check .onion domain
     */
    async checkOnion() {
        const input = document.getElementById('onionDomainInput');
        const results = document.getElementById('onionResults');

        if (!input || !results) return;

        const domain = input.value.trim();
        if (!domain.endsWith('.onion')) {
            this.showToast('Please enter a valid .onion address', 3000, 'error');
            return;
        }

        results.innerHTML = '<div class="osint-loading">Analyzing .onion address...</div>';

        await new Promise(resolve => setTimeout(resolve, 1000));

        const analysis = {
            valid: domain.match(/^[a-z2-7]{16,56}\.onion$/i) !== null,
            version: domain.length === 56 + 6 ? 'v3' : domain.length === 16 + 6 ? 'v2' : 'unknown',
            status: 'Educational analysis - actual connection requires Tor'
        };

        results.innerHTML = `
            <div class="onion-analysis">
                <div class="analysis-row">
                    <strong>Valid Format:</strong> ${analysis.valid ? '✅ Yes' : '❌ No'}
                </div>
                <div class="analysis-row">
                    <strong>Version:</strong> ${analysis.version}
                </div>
                <div class="analysis-row">
                    <strong>Status:</strong> ${analysis.status}
                </div>
            </div>
        `;
    }

    /**
     * Start breach monitoring
     */
    startBreachMonitoring() {
        // Check every 24 hours
        this.monitoringInterval = setInterval(() => {
            this.checkMonitoredEmails();
        }, 24 * 60 * 60 * 1000);
    }

    /**
     * Stop breach monitoring
     */
    stopBreachMonitoring() {
        if (this.monitoringInterval) {
            clearInterval(this.monitoringInterval);
        }
    }

    /**
     * Check monitored emails
     */
    async checkMonitoredEmails() {
        // Placeholder for periodic monitoring
        console.log('[Dark Web OSINT] Checking monitored emails...');
    }

    /**
     * Validate email
     */
    isValidEmail(email) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    }

    /**
     * Load monitored emails
     */
    loadMonitoredEmails() {
        try {
            const saved = localStorage.getItem('pkn_monitored_emails');
            if (saved) {
                this.monitoredEmails = JSON.parse(saved);
            }

            // Also check settings
            const settingsEmails = this.getSetting('monitoredEmails', '');
            if (settingsEmails) {
                const emails = settingsEmails.split(',').map(e => e.trim()).filter(e => e);
                this.monitoredEmails = [...new Set([...this.monitoredEmails, ...emails])];
            }
        } catch (error) {
            console.error(`[${this.name}] Error loading monitored emails:`, error);
        }
    }

    /**
     * Save monitored emails
     */
    saveMonitoredEmails() {
        try {
            localStorage.setItem('pkn_monitored_emails', JSON.stringify(this.monitoredEmails));
        } catch (error) {
            console.error(`[${this.name}] Error saving monitored emails:`, error);
        }
    }

    getCSS() {
        return `
            .darkweb-osint-panel {
                position: fixed;
                top: 0;
                right: 0;
                width: 700px;
                height: 100vh;
                background: rgba(10, 0, 0, 0.98);
                border-left: 2px solid #8b0000;
                z-index: 10003;
                display: flex;
                flex-direction: column;
                opacity: 0;
                transform: translateX(100%);
                transition: all 0.3s ease;
                box-shadow: -4px 0 32px rgba(139, 0, 0, 0.5);
            }
            .darkweb-osint-panel.visible {
                opacity: 1;
                transform: translateX(0);
            }
            .osint-panel-header {
                padding: 20px;
                border-bottom: 2px solid #8b0000;
                display: flex;
                justify-content: space-between;
                align-items: center;
                background: rgba(139, 0, 0, 0.1);
            }
            .osint-panel-title {
                color: #ff4444;
                font-size: 18px;
                font-weight: 700;
            }
            .osint-panel-close {
                background: transparent;
                border: none;
                color: #ff4444;
                font-size: 32px;
                cursor: pointer;
                padding: 0;
                width: 32px;
                height: 32px;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .osint-panel-close:hover {
                background: rgba(255, 68, 68, 0.1);
                border-radius: 4px;
            }
            .osint-warning {
                padding: 12px 20px;
                background: rgba(255, 165, 0, 0.2);
                border-bottom: 1px solid rgba(255, 165, 0, 0.5);
                color: #ffa500;
                font-size: 12px;
                font-weight: 600;
                text-align: center;
            }
            .osint-panel-body {
                flex: 1;
                display: flex;
                flex-direction: column;
                overflow: hidden;
            }
            .osint-tabs {
                display: flex;
                gap: 4px;
                padding: 12px 16px;
                background: rgba(0, 0, 0, 0.3);
                border-bottom: 1px solid rgba(139, 0, 0, 0.3);
            }
            .osint-tab {
                flex: 1;
                padding: 8px 12px;
                background: transparent;
                border: 1px solid rgba(139, 0, 0, 0.3);
                border-radius: 6px;
                color: #ff4444;
                font-size: 12px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.2s;
            }
            .osint-tab:hover {
                background: rgba(139, 0, 0, 0.1);
            }
            .osint-tab.active {
                background: rgba(139, 0, 0, 0.3);
                border-color: #8b0000;
            }
            .osint-tab-content {
                flex: 1;
                overflow-y: auto;
                padding: 20px;
            }
            .osint-section {
                margin-bottom: 24px;
            }
            .section-title {
                color: #ff4444;
                font-size: 16px;
                font-weight: 700;
                margin-bottom: 8px;
            }
            .section-description {
                color: #aaa;
                font-size: 13px;
                margin-bottom: 16px;
            }
            .osint-input-group {
                display: flex;
                gap: 8px;
                margin-bottom: 16px;
            }
            .osint-input {
                flex: 1;
                padding: 10px 12px;
                background: rgba(0, 0, 0, 0.5);
                border: 1px solid rgba(139, 0, 0, 0.5);
                border-radius: 6px;
                color: #fff;
                font-size: 13px;
            }
            .osint-input:focus {
                outline: none;
                border-color: #8b0000;
            }
            .osint-btn {
                padding: 10px 16px;
                background: rgba(139, 0, 0, 0.2);
                border: 1px solid rgba(139, 0, 0, 0.5);
                border-radius: 6px;
                color: #ff4444;
                font-size: 13px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.2s;
            }
            .osint-btn:hover {
                background: rgba(139, 0, 0, 0.3);
                border-color: #8b0000;
            }
            .osint-btn.primary {
                background: rgba(139, 0, 0, 0.3);
                border-color: #8b0000;
            }
            .osint-btn-small {
                padding: 4px 8px;
                background: transparent;
                border: 1px solid rgba(139, 0, 0, 0.3);
                border-radius: 4px;
                color: #ff4444;
                font-size: 11px;
                cursor: pointer;
            }
            .osint-results {
                margin-top: 16px;
            }
            .osint-loading {
                color: #ffa500;
                font-size: 13px;
                padding: 12px;
                text-align: center;
                animation: pulse 1s ease-in-out infinite;
            }
            .osint-success {
                background: rgba(0, 255, 0, 0.1);
                border-left: 3px solid #0f0;
                padding: 12px;
                color: #0f0;
                font-size: 13px;
            }
            .osint-error {
                background: rgba(255, 0, 0, 0.1);
                border-left: 3px solid #f00;
                padding: 12px;
                color: #f00;
                font-size: 13px;
            }
            .osint-warning-box {
                background: rgba(255, 165, 0, 0.1);
                border-left: 3px solid #ffa500;
                padding: 12px;
                color: #ffa500;
                font-size: 13px;
                margin-bottom: 12px;
            }
            .breach-list, .threat-feed-results {
                display: flex;
                flex-direction: column;
                gap: 12px;
            }
            .breach-item, .threat-item {
                background: rgba(0, 0, 0, 0.3);
                border: 1px solid rgba(139, 0, 0, 0.3);
                border-radius: 6px;
                padding: 12px;
            }
            .breach-header {
                display: flex;
                justify-content: space-between;
                margin-bottom: 6px;
            }
            .breach-name {
                color: #ff4444;
                font-size: 14px;
                font-weight: 700;
            }
            .breach-date {
                color: #888;
                font-size: 12px;
            }
            .breach-domain {
                color: #aaa;
                font-size: 12px;
                margin-bottom: 6px;
            }
            .breach-data {
                color: #ffa500;
                font-size: 11px;
            }
            .monitored-list {
                display: flex;
                flex-direction: column;
                gap: 8px;
            }
            .monitored-item {
                background: rgba(0, 0, 0, 0.3);
                border: 1px solid rgba(139, 0, 0, 0.2);
                border-radius: 6px;
                padding: 10px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .monitored-email {
                color: #fff;
                font-size: 13px;
            }
            .threat-feeds {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 12px;
                margin-bottom: 16px;
            }
            .feed-item {
                background: rgba(0, 0, 0, 0.3);
                border: 1px solid rgba(139, 0, 0, 0.3);
                border-radius: 6px;
                padding: 12px;
            }
            .feed-name {
                color: #ff4444;
                font-size: 13px;
                font-weight: 700;
                margin-bottom: 4px;
            }
            .feed-desc {
                color: #aaa;
                font-size: 11px;
                margin-bottom: 8px;
            }
            .onion-tools, .tool-item {
                margin-bottom: 12px;
            }
            .tool-name {
                color: #ff4444;
                font-size: 13px;
                font-weight: 600;
            }
            .tool-desc {
                color: #aaa;
                font-size: 12px;
            }
            .onion-analysis {
                background: rgba(0, 0, 0, 0.3);
                border: 1px solid rgba(139, 0, 0, 0.3);
                border-radius: 6px;
                padding: 12px;
            }
            .analysis-row {
                color: #ddd;
                font-size: 13px;
                margin-bottom: 8px;
            }
            .osint-note {
                margin-top: 16px;
                padding: 12px;
                background: rgba(255, 165, 0, 0.1);
                border-radius: 6px;
                color: #ffa500;
                font-size: 11px;
            }
            .osint-empty {
                color: #666;
                font-size: 13px;
                font-style: italic;
                padding: 20px;
                text-align: center;
            }
        `;
    }
}

export default DarkWebOSINTPlugin;
