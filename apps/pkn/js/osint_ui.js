/**
 * OSINT Tools UI Module
 * Provides user interface for OSINT (Open Source Intelligence) capabilities
 *
 * ⚠️ LEGAL NOTICE:
 * These tools are for AUTHORIZED and LEGAL use only.
 * Users must comply with applicable laws and regulations.
 */

const OSINTTools = {
    baseUrl: window.location.origin,
    currentPanel: null,

    /**
     * Initialize OSINT UI
     */
    init() {
        console.log('[OSINT] Initializing OSINT Tools UI');
        this.createOSINTPanel();
        this.attachEventListeners();
    },

    /**
     * Create the main OSINT panel in the UI
     */
    createOSINTPanel() {
        // Find or create OSINT modal overlay
        let container = document.getElementById('osint-tools-container');

        if (!container) {
            // Create modal overlay similar to Files panel
            container = document.createElement('div');
            container.id = 'osint-tools-container';
            container.className = 'settings-overlay hidden';
            container.setAttribute('aria-hidden', 'true');
            document.body.appendChild(container);
        }

        container.innerHTML = `
            <div class="settings-panel" style="max-width: 1200px; max-height: 90vh;">
                <div class="settings-header">
                    <div class="settings-title">🔍 OSINT Tools</div>
                    <button class="settings-close-x" onclick="OSINTTools.closePanel()">×</button>
                </div>

                <div class="settings-body" style="max-height: calc(90vh - 80px); overflow-y: auto;">
                    <div class="osint-warning" style="background: rgba(255, 165, 0, 0.1); border: 1px solid #ffa500; border-radius: 5px; padding: 10px; margin-bottom: 15px; color: #ffa500; text-align: center; font-weight: bold;">
                        ⚠️ AUTHORIZED USE ONLY - Comply with all applicable laws
                    </div>

                <div class="osint-categories">
                    <!-- Domain Intelligence -->
                    <div class="osint-category">
                        <h4>🌐 Domain Intelligence</h4>
                        <button onclick="OSINTTools.showTool('whois')" class="osint-btn">WHOIS Lookup</button>
                        <button onclick="OSINTTools.showTool('dns')" class="osint-btn">DNS Lookup</button>
                        <button onclick="OSINTTools.showTool('subdomain')" class="osint-btn">Subdomain Enum</button>
                        <button onclick="OSINTTools.showTool('ssl')" class="osint-btn">SSL Certificate</button>
                    </div>

                    <!-- IP & Network -->
                    <div class="osint-category">
                        <h4>🌍 IP & Network</h4>
                        <button onclick="OSINTTools.showTool('ipgeo')" class="osint-btn">IP Geolocation</button>
                        <button onclick="OSINTTools.showTool('reversedns')" class="osint-btn">Reverse DNS</button>
                        <button onclick="OSINTTools.showTool('portscan')" class="osint-btn">Port Scan</button>
                    </div>

                    <!-- Email & Username -->
                    <div class="osint-category">
                        <h4>📧 Email & Username</h4>
                        <button onclick="OSINTTools.showTool('emailvalidate')" class="osint-btn">Email Validate</button>
                        <button onclick="OSINTTools.showTool('username')" class="osint-btn">Username Search</button>
                    </div>

                    <!-- Web Intelligence -->
                    <div class="osint-category">
                        <h4>🌐 Web Intelligence</h4>
                        <button onclick="OSINTTools.showTool('webtech')" class="osint-btn">Web Technologies</button>
                        <button onclick="OSINTTools.showTool('wayback')" class="osint-btn">Wayback Machine</button>
                    </div>

                    <!-- Phone -->
                    <div class="osint-category">
                        <h4>📱 Phone</h4>
                        <button onclick="OSINTTools.showTool('phone')" class="osint-btn">Phone Lookup</button>
                    </div>
                </div>

                <!-- Tool execution area -->
                <div id="osint-tool-area" class="osint-tool-area hidden">
                    <div class="osint-tool-header">
                        <h4 id="osint-tool-title">Tool</h4>
                        <button onclick="OSINTTools.closeTool()" class="close-btn">✕</button>
                    </div>
                    <div id="osint-tool-content" class="osint-tool-content"></div>
                    <div id="osint-tool-results" class="osint-tool-results"></div>
                </div>
                </div>
            </div>
        `;

        this.currentPanel = container;
    },

    /**
     * Toggle OSINT panel visibility (open modal)
     */
    togglePanel() {
        const container = document.getElementById('osint-tools-container');
        if (container) {
            container.classList.remove('hidden');
            container.setAttribute('aria-hidden', 'false');
        }
    },

    /**
     * Close OSINT panel
     */
    closePanel() {
        const container = document.getElementById('osint-tools-container');
        if (container) {
            container.classList.add('hidden');
            container.setAttribute('aria-hidden', 'true');
        }
    },

    /**
     * Show specific OSINT tool
     */
    showTool(toolName) {
        const toolArea = document.getElementById('osint-tool-area');
        const toolTitle = document.getElementById('osint-tool-title');
        const toolContent = document.getElementById('osint-tool-content');
        const toolResults = document.getElementById('osint-tool-results');

        // Clear previous results
        toolResults.innerHTML = '';

        // Show tool area
        toolArea.classList.remove('hidden');

        // Generate tool-specific UI
        const toolConfigs = {
            'whois': {
                title: 'WHOIS Lookup',
                fields: [{name: 'domain', label: 'Domain', placeholder: 'example.com', type: 'text'}],
                endpoint: '/api/osint/whois'
            },
            'dns': {
                title: 'DNS Lookup',
                fields: [{name: 'domain', label: 'Domain', placeholder: 'example.com', type: 'text'}],
                endpoint: '/api/osint/dns'
            },
            'ipgeo': {
                title: 'IP Geolocation',
                fields: [{name: 'ip', label: 'IP Address', placeholder: '8.8.8.8', type: 'text'}],
                endpoint: '/api/osint/ip-geo'
            },
            'portscan': {
                title: 'Port Scan',
                fields: [{name: 'host', label: 'Host', placeholder: 'example.com or IP', type: 'text'}],
                endpoint: '/api/osint/port-scan'
            },
            'emailvalidate': {
                title: 'Email Validation',
                fields: [{name: 'email', label: 'Email', placeholder: 'user@example.com', type: 'email'}],
                endpoint: '/api/osint/email-validate'
            },
            'username': {
                title: 'Username Search',
                fields: [{name: 'username', label: 'Username', placeholder: 'johndoe', type: 'text'}],
                endpoint: '/api/osint/username-search'
            },
            'webtech': {
                title: 'Web Technologies',
                fields: [{name: 'url', label: 'URL', placeholder: 'https://example.com', type: 'url'}],
                endpoint: '/api/osint/web-tech'
            },
            'ssl': {
                title: 'SSL Certificate',
                fields: [{name: 'domain', label: 'Domain', placeholder: 'example.com', type: 'text'}],
                endpoint: '/api/osint/ssl-cert'
            },
            'wayback': {
                title: 'Wayback Machine',
                fields: [{name: 'url', label: 'URL', placeholder: 'https://example.com', type: 'url'}],
                endpoint: '/api/osint/wayback'
            },
            'subdomain': {
                title: 'Subdomain Enumeration',
                fields: [{name: 'domain', label: 'Domain', placeholder: 'example.com', type: 'text'}],
                endpoint: '/api/osint/subdomain-enum'
            },
            'reversedns': {
                title: 'Reverse DNS',
                fields: [{name: 'ip', label: 'IP Address', placeholder: '8.8.8.8', type: 'text'}],
                endpoint: '/api/osint/reverse-dns'
            },
            'phone': {
                title: 'Phone Number Lookup',
                fields: [{name: 'phone', label: 'Phone', placeholder: '+1-555-123-4567', type: 'tel'}],
                endpoint: '/api/osint/phone-lookup'
            }
        };

        const config = toolConfigs[toolName];
        if (!config) {
            toolContent.innerHTML = '<p class="error">Unknown tool</p>';
            return;
        }

        toolTitle.textContent = config.title;

        // Generate form
        let formHTML = '<form id="osint-form" class="osint-form">';

        config.fields.forEach(field => {
            formHTML += `
                <div class="osint-field">
                    <label for="osint-${field.name}">${field.label}:</label>
                    <input
                        type="${field.type}"
                        id="osint-${field.name}"
                        name="${field.name}"
                        placeholder="${field.placeholder}"
                        required
                    />
                </div>
            `;
        });

        formHTML += `
            <button type="submit" class="osint-submit-btn">Execute</button>
        </form>`;

        toolContent.innerHTML = formHTML;

        // Attach form submit handler
        document.getElementById('osint-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.executeTool(config.endpoint, new FormData(e.target));
        });
    },

    /**
     * Execute OSINT tool
     */
    async executeTool(endpoint, formData) {
        const resultsDiv = document.getElementById('osint-tool-results');

        // Show loading
        resultsDiv.innerHTML = '<div class="osint-loading">🔍 Executing OSINT query...</div>';

        try {
            // Convert FormData to JSON
            const data = {};
            for (let [key, value] of formData.entries()) {
                data[key] = value;
            }

            const response = await fetch(`${this.baseUrl}${endpoint}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data)
            });

            const result = await response.json();

            if (!response.ok || result.error) {
                throw new Error(result.error || 'Request failed');
            }

            // Display results
            this.displayResults(result);

        } catch (error) {
            resultsDiv.innerHTML = `<div class="osint-error">❌ Error: ${error.message}</div>`;
        }
    },

    /**
     * Display OSINT results
     */
    displayResults(result) {
        const resultsDiv = document.getElementById('osint-tool-results');

        let html = '<div class="osint-results-container">';
        html += '<h5>Results:</h5>';

        // Recursive function to display nested objects
        const formatObject = (obj, level = 0) => {
            let output = '';
            const indent = '  '.repeat(level);

            if (Array.isArray(obj)) {
                obj.forEach((item, index) => {
                    if (typeof item === 'object') {
                        output += `${indent}[${index}]:\n${formatObject(item, level + 1)}`;
                    } else {
                        output += `${indent}${item}\n`;
                    }
                });
            } else if (typeof obj === 'object' && obj !== null) {
                for (let [key, value] of Object.entries(obj)) {
                    if (key === 'success' || key === 'error') continue; // Skip meta fields

                    if (typeof value === 'object' && value !== null) {
                        output += `${indent}${key}:\n${formatObject(value, level + 1)}`;
                    } else {
                        output += `${indent}${key}: ${value}\n`;
                    }
                }
            } else {
                output += `${indent}${obj}\n`;
            }

            return output;
        };

        const formatted = formatObject(result);
        html += `<pre class="osint-results-pre">${formatted}</pre>`;
        html += '</div>';

        resultsDiv.innerHTML = html;
    },

    /**
     * Close tool area
     */
    closeTool() {
        const toolArea = document.getElementById('osint-tool-area');
        toolArea.classList.add('hidden');
    },

    /**
     * Attach event listeners
     */
    attachEventListeners() {
        console.log('[OSINT] Event listeners attached');
    }
};

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => OSINTTools.init());
} else {
    OSINTTools.init();
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = OSINTTools;
}
