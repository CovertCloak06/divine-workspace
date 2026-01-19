/**
 * Error Handling Module
 * Maps technical errors to user-friendly messages with actionable recovery steps
 */

import { showToast } from './utils.js';

/**
 * Error message mappings for common issues
 */
export const ERROR_MESSAGES = {
    // Network & Connection Errors
    'ECONNREFUSED': {
        title: 'Service Not Running',
        message: 'The AI service isn\'t responding.',
        actions: [
            'Start services: Open Settings -> CLI Access -> Copy Commands',
            'Or run: ./pkn_control.sh start-all',
            'Check status: ./pkn_control.sh status'
        ],
        severity: 'error',
        docs: '#service-not-running'
    },
    'Failed to fetch': {
        title: 'Connection Failed',
        message: 'Cannot reach the server.',
        actions: [
            'Check if server is running: curl http://localhost:8010/health',
            'Restart services: ./pkn_control.sh restart-divinenode',
            'Check browser console (F12) for details'
        ],
        severity: 'error',
        docs: '#connection-failed'
    },
    'NetworkError': {
        title: 'Network Error',
        message: 'Network request failed.',
        actions: [
            'Check your internet connection',
            'Verify server is running on port 8010',
            'Try refreshing the page'
        ],
        severity: 'error'
    },

    // Port & Service Errors
    'port 8010': {
        title: 'Port Conflict',
        message: 'Port 8010 is already in use by another application.',
        actions: [
            'Stop conflicting service: lsof -i :8010',
            'Or change Divine Node port in divinenode_server.py',
            'Then restart: ./pkn_control.sh restart-divinenode'
        ],
        severity: 'warning',
        docs: '#port-conflict'
    },
    'port 8000': {
        title: 'LLM Port Conflict',
        message: 'Port 8000 (llama.cpp) is already in use.',
        actions: [
            'Stop conflicting service: lsof -i :8000',
            'Or restart llama.cpp: ./pkn_control.sh restart-llama'
        ],
        severity: 'warning'
    },

    // Image Generation Errors
    'IndexError': {
        title: 'Image Generation Failed',
        message: 'The image generator encountered a configuration error.',
        actions: [
            'Restart services: ./pkn_control.sh restart-divinenode',
            'Check logs: tail -20 divinenode.log',
            'Try a simpler prompt'
        ],
        severity: 'error',
        docs: '#image-generation'
    },
    'timed out': {
        title: 'Generation Timeout',
        message: 'The operation took too long to complete.',
        actions: [
            'CPU mode takes ~3 minutes - this is normal',
            'If using GPU and still timing out, check GPU availability',
            'Try reducing image complexity or step count'
        ],
        severity: 'warning'
    },

    // Model & AI Errors
    'Model not found': {
        title: 'Model Not Available',
        message: 'The requested AI model isn\'t loaded.',
        actions: [
            'Check available models: curl http://localhost:8000/v1/models',
            'Verify model path in pkn_control.sh',
            'Download model if missing'
        ],
        severity: 'error',
        docs: '#model-not-found'
    },
    'CUDA': {
        title: 'GPU Not Available',
        message: 'CUDA not available - using CPU mode.',
        actions: [
            'This is expected on systems without NVIDIA GPU',
            'CPU mode works fine, just slower (~3-5x)',
            'No action needed unless you expected GPU acceleration'
        ],
        severity: 'info'
    },

    // File & Storage Errors
    'QuotaExceededError': {
        title: 'Storage Full',
        message: 'Browser storage limit exceeded.',
        actions: [
            'Clear old chats: Settings -> Delete Chats',
            'Clear images: Settings -> Clear Images',
            'Export important chats first: Settings -> Export Chats'
        ],
        severity: 'warning',
        docs: '#storage-full'
    },
    'File too large': {
        title: 'File Too Large',
        message: 'The uploaded file exceeds size limits.',
        actions: [
            'Maximum file size: 10MB',
            'Try compressing the file',
            'Or split into smaller chunks'
        ],
        severity: 'warning'
    },

    // HTTP Status Errors
    '404': {
        title: 'Not Found',
        message: 'The requested resource doesn\'t exist.',
        actions: [
            'Check the URL or endpoint',
            'Verify server is running latest version',
            'Try restarting services'
        ],
        severity: 'error'
    },
    '500': {
        title: 'Server Error',
        message: 'Internal server error occurred.',
        actions: [
            'Check server logs: tail -20 divinenode.log',
            'Restart services: ./pkn_control.sh restart-all',
            'Report issue if error persists'
        ],
        severity: 'error',
        docs: '#server-errors'
    },
    '503': {
        title: 'Service Unavailable',
        message: 'Server is temporarily unavailable.',
        actions: [
            'Server might be starting up (wait 10-15 seconds)',
            'Check status: ./pkn_control.sh status',
            'Restart if needed: ./pkn_control.sh restart-all'
        ],
        severity: 'warning'
    }
};

/**
 * Format error into user-friendly message with recovery actions
 * @param {Error|string} error - Error object or message
 * @param {string} context - Optional context (e.g., "image_generation", "chat")
 * @returns {Object} Formatted error with title, message, actions, severity
 */
export function formatError(error, context = '') {
    const errorMsg = typeof error === 'string' ? error : (error.message || String(error));

    // Try to match error patterns
    for (const [pattern, errorInfo] of Object.entries(ERROR_MESSAGES)) {
        if (errorMsg.includes(pattern) || errorMsg.toLowerCase().includes(pattern.toLowerCase())) {
            return {
                title: errorInfo.title,
                message: errorInfo.message,
                actions: errorInfo.actions || [],
                severity: errorInfo.severity || 'error',
                docs: errorInfo.docs || null,
                originalError: errorMsg
            };
        }
    }

    // Fallback for unknown errors
    return {
        title: 'Error',
        message: errorMsg,
        actions: [
            'Check browser console (F12) for details',
            'View server logs: tail -20 divinenode.log',
            'Try restarting services if issue persists'
        ],
        severity: 'error',
        originalError: errorMsg
    };
}

/**
 * Get color for severity level
 */
function getSeverityColor(severity) {
    switch (severity) {
        case 'error': return '#ef4444';
        case 'warning': return '#f59e0b';
        case 'info': return '#3b82f6';
        default: return '#ef4444';
    }
}

/**
 * Display formatted error to user with recovery options
 * @param {Error|string} error - Error object or message
 * @param {string} context - Optional context
 * @param {HTMLElement} targetElement - Optional element to show error in
 */
export function showFormattedError(error, context = '', targetElement = null) {
    const formatted = formatError(error, context);
    const color = getSeverityColor(formatted.severity);

    const errorHTML = `
        <div class="error-card" style="
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid ${color};
            border-radius: 8px;
            padding: 16px;
            margin: 12px 0;
            font-size: 13px;
        ">
            <div class="error-title" style="
                color: ${color};
                font-weight: 700;
                font-size: 14px;
                margin-bottom: 8px;
            ">${formatted.title}</div>

            <div class="error-message" style="color: #ccc; margin-bottom: 12px;">
                ${formatted.message}
            </div>

            ${formatted.actions.length > 0 ? `
                <div class="error-actions" style="margin-top: 12px;">
                    <div style="color: #999; font-size: 12px; margin-bottom: 6px; font-weight: 600;">Try these fixes:</div>
                    <ul style="margin: 0; padding-left: 20px; color: #aaa; font-size: 12px; line-height: 1.6;">
                        ${formatted.actions.map(action => `<li>${action}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}

            ${formatted.docs ? `
                <div style="margin-top: 12px; padding-top: 12px; border-top: 1px solid rgba(255,255,255,0.1);">
                    <a href="/docs${formatted.docs}" style="color: var(--theme-primary); font-size: 12px; text-decoration: none;">
                        Learn more
                    </a>
                </div>
            ` : ''}

            <details style="margin-top: 12px; font-size: 11px;">
                <summary style="cursor: pointer; color: #666;">Technical details</summary>
                <pre style="margin-top: 6px; padding: 8px; background: #000; border-radius: 4px; overflow-x: auto; color: #999;">${formatted.originalError}</pre>
            </details>
        </div>
    `;

    if (targetElement) {
        targetElement.innerHTML = errorHTML;
        targetElement.style.display = 'block';
    } else {
        const container = document.getElementById('messagesContainer');
        if (container) {
            const errorDiv = document.createElement('div');
            errorDiv.className = 'message system-message';
            errorDiv.innerHTML = errorHTML;
            container.appendChild(errorDiv);
            container.scrollTop = container.scrollHeight;
        }
    }

    showToast(formatted.title, 4000, formatted.severity);
}
