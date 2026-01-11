/**
 * Utility Functions Module
 * Shared utilities used across the application
 */

/**
 * Toast notification system for user feedback
 * @param {string} message - The message to display
 * @param {number} duration - How long to show the toast (ms)
 * @param {string} type - Type of toast: 'info', 'success', 'error'
 */
export function showToast(message, duration = 3000, type = 'info') {
    const container = document.getElementById('toastContainer') || document.body;
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    toast.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        background: ${type === 'error' ? '#ef4444' : type === 'success' ? '#10b981' : '#3b82f6'};
        color: white;
        padding: 12px 20px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        z-index: 10000;
        animation: slideIn 0.3s ease-out;
        max-width: 350px;
        word-wrap: break-word;
    `;
    container.appendChild(toast);

    // Auto-remove after duration
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

/**
 * Escape HTML to prevent XSS
 * @param {string} str - String to escape
 * @returns {string} Escaped string
 */
export function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

/**
 * Toggle sidebar sections
 * @param {string} sectionId - ID of section to toggle
 */
export function toggleSection(sectionId) {
    const section = document.getElementById(sectionId);
    if (!section) return;
    section.classList.toggle('collapsed');
    const chevronId = sectionId.replace(/Section$/, 'Chevron');
    const chevron = document.getElementById(chevronId);
    if (chevron) chevron.textContent = section.classList.contains('collapsed') ? '►' : '▼';
}

/**
 * Close any open history menu
 */
export function closeHistoryMenu() {
    if (window.openMenuElement) {
        window.openMenuElement.remove();
        window.openMenuElement = null;
    }
}

/**
 * Show backend status banner
 * @param {string} htmlMessage - HTML message to display
 */
export function showBackendBanner(htmlMessage) {
    let banner = document.getElementById('backendBanner');
    if (!banner) {
        banner = document.createElement('div');
        banner.id = 'backendBanner';
        banner.style.cssText = 'position:fixed;top:8px;left:36px;right:8px;z-index:9999;padding:10px;border-radius:6px;background:#ff5a5a;color:#fff;display:flex;align-items:center;justify-content:space-between;gap:12px;box-shadow:0 6px 18px rgba(0,0,0,0.6);font-size:13px;';
        document.body.appendChild(banner);
    }
    banner.innerHTML = `<span>${htmlMessage}</span><button onclick="this.parentElement.remove()" style="background:transparent;border:1px solid #fff;color:#fff;padding:4px 8px;border-radius:3px;cursor:pointer;">Dismiss</button>`;
}

/**
 * Hide backend status banner
 */
export function hideBackendBanner() {
    const banner = document.getElementById('backendBanner');
    if (banner) banner.remove();
}

/**
 * Check backend availability
 * @param {boolean} showToastOnFail - Whether to show toast notification on failure
 * @returns {Promise<boolean>} True if backend is available
 */
export async function checkBackend(showToastOnFail = true) {
    const tryFetch = async (url) => {
        try {
            const r = await fetch(url, { cache: 'no-store' });
            return r && r.ok;
        } catch (e) {
            return false;
        }
    };

    try {
        let ok = await tryFetch('/api/health');
        if (!ok) ok = await tryFetch('/health');

        if (!ok) {
            showBackendBanner('Backend API not reachable. Start the Flask backend: <code>python divinenode_server.py --host 0.0.0.0 --port 8010</code> or run <code>./pkn_control.sh start-all</code>.');
            if (showToastOnFail) showToast('Backend not detected - APIs disabled');
            return false;
        } else {
            hideBackendBanner();
            // Dynamic import to avoid circular dependency
            if (typeof window.refreshOllamaModels === 'function') {
                window.refreshOllamaModels();
            }
            if (showToastOnFail) showToast('Backend online', 1200, 'success');
            return true;
        }
    } catch (e) {
        console.error('Backend check failed', e);
        showBackendBanner('Failed to check backend: ' + (e?.message || e));
        if (showToastOnFail) showToast('Backend check failed', 3000, 'error');
        return false;
    }
}

// Add CSS animations for toast if not already present
if (!document.getElementById('toast-animations')) {
    const style = document.createElement('style');
    style.id = 'toast-animations';
    style.textContent = `
        @keyframes slideIn {
            from { transform: translateX(400px); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOut {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(400px); opacity: 0; }
        }
    `;
    document.head.appendChild(style);
}
