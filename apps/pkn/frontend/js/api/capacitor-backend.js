/**
 * Capacitor Backend Auto-Start Integration
 * Handles Termux backend initialization and health checking
 */

class CapacitorBackend {
    constructor() {
        this.backendUrl = 'http://localhost:8010';
        this.healthCheckInterval = null;
        this.isBackendReady = false;
        this.maxRetries = 30; // 30 seconds max wait
        this.retryCount = 0;
    }

    /**
     * Initialize backend - called on app startup
     */
    async init() {
        console.log('[Capacitor] Initializing backend...');

        // Show loading overlay
        this.showLoadingOverlay();

        // Check if backend is already running
        const isRunning = await this.checkBackendHealth();

        if (isRunning) {
            console.log('[Capacitor] Backend already running');
            this.hideLoadingOverlay();
            this.isBackendReady = true;
            return true;
        }

        // Backend not running, try to start it
        console.log('[Capacitor] Backend not running, attempting to start...');
        await this.startTermuxBackend();

        // Wait for backend to be ready
        return await this.waitForBackend();
    }

    /**
     * Check if backend is healthy
     */
    async checkBackendHealth() {
        try {
            const response = await fetch(`${this.backendUrl}/health`, {
                method: 'GET',
                timeout: 2000
            });

            if (response.ok) {
                const data = await response.json();
                return data.status === 'healthy';
            }
            return false;
        } catch (error) {
            console.log('[Capacitor] Backend health check failed:', error.message);
            return false;
        }
    }

    /**
     * Start Termux backend via intent
     */
    async startTermuxBackend() {
        console.log('[Capacitor] Starting Termux backend...');

        try {
            // Method 1: Try to use Capacitor's App plugin to send intent
            if (window.Capacitor && window.Capacitor.Plugins.App) {
                // Send intent to Termux to run startup script
                const intent = {
                    action: 'com.termux.RUN_COMMAND',
                    extra: {
                        'com.termux.RUN_COMMAND_PATH': '/data/data/com.termux/files/home/pkn/termux_start.sh',
                        'com.termux.RUN_COMMAND_BACKGROUND': 'true'
                    }
                };

                console.log('[Capacitor] Sending Termux intent:', intent);
                // Note: This will be implemented in native Android code
                await this.sendTermuxIntent(intent);
            } else {
                // Method 2: Fallback - show instructions
                console.log('[Capacitor] Capacitor App plugin not available');
                this.showManualStartInstructions();
            }
        } catch (error) {
            console.error('[Capacitor] Failed to start Termux backend:', error);
            this.showManualStartInstructions();
        }
    }

    /**
     * Send intent to Termux (implemented in native Android code)
     */
    async sendTermuxIntent(intent) {
        if (window.Capacitor && window.Capacitor.Plugins.TermuxBridge) {
            return await window.Capacitor.Plugins.TermuxBridge.startBackend(intent);
        }
        throw new Error('TermuxBridge not available');
    }

    /**
     * Wait for backend to become ready
     */
    async waitForBackend() {
        return new Promise((resolve, reject) => {
            const checkInterval = setInterval(async () => {
                this.retryCount++;

                this.updateLoadingMessage(`Waiting for backend... (${this.retryCount}/${this.maxRetries})`);

                const isHealthy = await this.checkBackendHealth();

                if (isHealthy) {
                    console.log('[Capacitor] Backend is ready!');
                    clearInterval(checkInterval);
                    this.hideLoadingOverlay();
                    this.isBackendReady = true;
                    resolve(true);
                } else if (this.retryCount >= this.maxRetries) {
                    console.error('[Capacitor] Backend failed to start within timeout');
                    clearInterval(checkInterval);
                    this.showErrorOverlay();
                    reject(new Error('Backend timeout'));
                }
            }, 1000); // Check every second
        });
    }

    /**
     * Show loading overlay
     */
    showLoadingOverlay() {
        // Remove existing overlay if present
        this.hideLoadingOverlay();

        const overlay = document.createElement('div');
        overlay.id = 'capacitor-loading-overlay';
        overlay.innerHTML = `
            <div class="capacitor-loading-content">
                <div class="capacitor-spinner"></div>
                <h2>Divine Node</h2>
                <p id="capacitor-loading-message">Starting backend...</p>
                <div class="capacitor-progress-bar">
                    <div class="capacitor-progress-fill"></div>
                </div>
            </div>
        `;

        // Add styles
        const style = document.createElement('style');
        style.textContent = `
            #capacitor-loading-overlay {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: #0a0a0a;
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 99999;
            }

            .capacitor-loading-content {
                text-align: center;
                padding: 40px;
                max-width: 400px;
            }

            .capacitor-spinner {
                width: 60px;
                height: 60px;
                border: 4px solid rgba(0, 255, 255, 0.1);
                border-top: 4px solid #00ffff;
                border-radius: 50%;
                margin: 0 auto 30px;
                animation: spin 1s linear infinite;
            }

            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }

            .capacitor-loading-content h2 {
                color: #00ffff;
                font-size: 28px;
                margin-bottom: 16px;
                font-family: 'Inter', sans-serif;
            }

            .capacitor-loading-content p {
                color: #888;
                font-size: 14px;
                margin-bottom: 20px;
            }

            .capacitor-progress-bar {
                width: 100%;
                height: 4px;
                background: rgba(0, 255, 255, 0.1);
                border-radius: 2px;
                overflow: hidden;
            }

            .capacitor-progress-fill {
                height: 100%;
                background: #00ffff;
                width: 0%;
                animation: progress 30s linear;
            }

            @keyframes progress {
                0% { width: 0%; }
                100% { width: 100%; }
            }
        `;

        document.head.appendChild(style);
        document.body.appendChild(overlay);
    }

    /**
     * Update loading message
     */
    updateLoadingMessage(message) {
        const messageEl = document.getElementById('capacitor-loading-message');
        if (messageEl) {
            messageEl.textContent = message;
        }
    }

    /**
     * Hide loading overlay
     */
    hideLoadingOverlay() {
        const overlay = document.getElementById('capacitor-loading-overlay');
        if (overlay) {
            overlay.remove();
        }
    }

    /**
     * Show error overlay with retry option
     */
    showErrorOverlay() {
        const overlay = document.getElementById('capacitor-loading-overlay');
        if (overlay) {
            overlay.innerHTML = `
                <div class="capacitor-loading-content">
                    <div style="font-size: 48px; margin-bottom: 20px;">⚠️</div>
                    <h2 style="color: #ff4444;">Backend Not Responding</h2>
                    <p>The backend server couldn't be started automatically.</p>
                    <div style="margin-top: 30px;">
                        <button onclick="capacitorBackend.retryStartup()" class="capacitor-retry-btn">
                            Retry
                        </button>
                        <button onclick="capacitorBackend.showManualStartInstructions()" class="capacitor-manual-btn">
                            Manual Start
                        </button>
                    </div>
                </div>
            `;

            // Add button styles
            const style = document.createElement('style');
            style.textContent = `
                .capacitor-retry-btn, .capacitor-manual-btn {
                    padding: 12px 24px;
                    margin: 0 8px;
                    border: none;
                    border-radius: 8px;
                    font-size: 14px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.3s;
                }

                .capacitor-retry-btn {
                    background: #00ffff;
                    color: #000;
                }

                .capacitor-retry-btn:hover {
                    background: #00cccc;
                }

                .capacitor-manual-btn {
                    background: #333;
                    color: #fff;
                }

                .capacitor-manual-btn:hover {
                    background: #444;
                }
            `;
            document.head.appendChild(style);
        }
    }

    /**
     * Show manual start instructions
     */
    showManualStartInstructions() {
        const overlay = document.getElementById('capacitor-loading-overlay');
        if (overlay) {
            overlay.innerHTML = `
                <div class="capacitor-loading-content">
                    <h2 style="color: #00ffff;">Manual Start Required</h2>
                    <div style="text-align: left; margin: 20px 0; padding: 20px; background: rgba(0,255,255,0.1); border-radius: 8px;">
                        <p style="margin-bottom: 10px; color: #fff;">1. Open Termux</p>
                        <p style="margin-bottom: 10px; color: #fff;">2. Run: <code style="background: #000; padding: 4px 8px; border-radius: 4px; color: #00ffff;">cd ~/pkn && ./termux_start.sh</code></p>
                        <p style="color: #fff;">3. Return to this app</p>
                    </div>
                    <button onclick="capacitorBackend.retryStartup()" class="capacitor-retry-btn">
                        I've Started It - Retry Connection
                    </button>
                </div>
            `;
        }
    }

    /**
     * Retry startup process
     */
    async retryStartup() {
        this.retryCount = 0;
        this.showLoadingOverlay();
        await this.init();
    }

    /**
     * Monitor backend health in background
     */
    startHealthMonitoring() {
        if (this.healthCheckInterval) {
            clearInterval(this.healthCheckInterval);
        }

        this.healthCheckInterval = setInterval(async () => {
            const isHealthy = await this.checkBackendHealth();

            if (!isHealthy && this.isBackendReady) {
                console.warn('[Capacitor] Backend became unhealthy');
                this.isBackendReady = false;
                this.showBackendDisconnectedNotice();
            } else if (isHealthy && !this.isBackendReady) {
                console.log('[Capacitor] Backend recovered');
                this.isBackendReady = true;
                this.hideBackendDisconnectedNotice();
            }
        }, 10000); // Check every 10 seconds
    }

    /**
     * Show backend disconnected notice
     */
    showBackendDisconnectedNotice() {
        // Create a small notification banner
        const notice = document.createElement('div');
        notice.id = 'backend-disconnected-notice';
        notice.innerHTML = `
            <div style="position: fixed; top: 0; left: 0; right: 0; background: #ff4444; color: #fff; padding: 12px; text-align: center; z-index: 9998; font-size: 14px;">
                ⚠️ Backend disconnected. Retrying...
            </div>
        `;
        document.body.appendChild(notice);
    }

    /**
     * Hide backend disconnected notice
     */
    hideBackendDisconnectedNotice() {
        const notice = document.getElementById('backend-disconnected-notice');
        if (notice) {
            notice.remove();
        }
    }
}

// Initialize on app load
const capacitorBackend = new CapacitorBackend();

// Auto-start when running in Capacitor
if (window.Capacitor) {
    console.log('[Capacitor] Running in Capacitor environment');

    document.addEventListener('DOMContentLoaded', async () => {
        try {
            await capacitorBackend.init();
            capacitorBackend.startHealthMonitoring();
        } catch (error) {
            console.error('[Capacitor] Initialization failed:', error);
        }
    });
} else {
    console.log('[Capacitor] Running in browser (PWA mode)');
}

// Make available globally
window.capacitorBackend = capacitorBackend;
