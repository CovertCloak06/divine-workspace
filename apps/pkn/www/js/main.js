/**
 * Main Application Initialization
 * Ties together all modules and sets up event handlers
 */

import { showToast, toggleSection, closeHistoryMenu, checkBackend } from './utils.js';
import { sendMessage, addMessage, renderHistory } from './chat.js';
import { initModelSelector } from './models.js';
import { renderProjects } from './projects.js';
import {
    toggleSettings,
    saveTemperature,
    saveMaxTokens,
    saveTopP,
    saveFrequencyPenalty,
    savePresencePenalty,
    saveEnterToSend,
    saveShowTimestamps,
    saveApiKey
} from './settings.js';
import { showFilesPanel, hideFilesPanel, initFilesPanelRefs } from './files.js';
import {
    openImageGenerator,
    closeImageGenerator,
    generateImage,
    renderImages,
    openImagesGallery,
    closeImagesGallery,
    clearGeneratedImages
} from './images.js';

// ============================================
// DOM Element References
// ============================================
export const messagesContainer = document.getElementById('messagesContainer');
export const messageInput = document.getElementById('messageInput');
export const sendBtn = document.getElementById('sendBtn');
export const historyList = document.getElementById('historyList');
export const favoritesList = document.getElementById('favoritesList');
export const archiveList = document.getElementById('archiveList');
export const projectsList = document.getElementById('projectsList');
export const fileInput = document.getElementById('fileInput');
export const filePreview = document.getElementById('filePreview');
export const fileActions = document.getElementById('fileActions');
export const modelSelect = document.getElementById('modelSelect');
export const settingsOverlay = document.getElementById('settingsOverlay');
export const fullHistoryToggle = document.getElementById('fullHistoryToggle');
export const stopBtn = document.getElementById('stopBtn');

// Global menu tracking
window.openMenuElement = null;

// ============================================
// Network Action Menu
// ============================================
function networkAction(e) {
    try {
        e.stopPropagation();
        closeHistoryMenu();
        const menu = document.createElement('div');
        menu.className = 'history-menu';

        const items = [
            { label: 'Port Scan', action: () => window.ParakleonTools?.portScan?.() },
            { label: 'Ping', action: () => window.ParakleonTools?.ping?.() },
            { label: 'DNS Lookup', action: () => window.ParakleonTools?.dnsLookup?.() },
            { label: 'IP Info', action: () => window.ParakleonTools?.ipInfo?.() },
        ];

        items.forEach(itm => {
            const it = document.createElement('div');
            it.className = 'history-menu-item';
            it.textContent = itm.label;
            it.onclick = () => { itm.action(); closeHistoryMenu(); };
            menu.appendChild(it);
        });

        const rect = e?.currentTarget?.getBoundingClientRect?.() || { top: 0, left: 0, bottom: 0 };
        const containerRect = document.body.getBoundingClientRect();
        const top = rect.bottom - containerRect.top + window.scrollY;
        const left = rect.left - containerRect.left + window.scrollX;
        menu.style.top = top + 'px';
        menu.style.left = left + 'px';

        document.body.appendChild(menu);
        window.openMenuElement = menu;
    } catch (err) {
        console.error('networkAction error', err);
    }
}

// ============================================
// Sidebar Hover/Toggle Behavior
// ============================================
function setupSidebarHover() {
    if (setupSidebarHover._attached) return; // prevent double-attach
    setupSidebarHover._attached = true;

    if (typeof window === 'undefined') return;

    const HOVER_ZONE = 50; // px from left edge to open
    const CLOSE_DELAY = 1200; // ms delay before closing
    const isTouchDevice = 'ontouchstart' in window;
    let closeTimer = null;

    const sidebar = document.querySelector('.sidebar');
    const hoverStrip = document.getElementById('hoverStrip');
    if (!sidebar) return;

    const clearCloseTimer = () => {
        if (closeTimer) {
            clearTimeout(closeTimer);
            closeTimer = null;
        }
    };

    function openSidebar() {
        clearCloseTimer();
        if (sidebar.classList.contains('hidden')) {
            sidebar.classList.remove('hidden');
            if (hoverStrip) hoverStrip.classList.add('hidden');
        }
    }

    function closeSidebar() {
        clearCloseTimer();
        if (!sidebar.classList.contains('hidden')) {
            sidebar.classList.add('hidden');
            if (hoverStrip) hoverStrip.classList.remove('hidden');
        }
    }

    if (!isTouchDevice) {
        // Desktop: hover logic
        document.addEventListener('mousemove', (e) => {
            const x = e.clientX;
            if (x <= HOVER_ZONE) {
                openSidebar();
            } else if (!sidebar.matches(':hover') &&
                       !(hoverStrip?.matches(':hover')) &&
                       !sidebar.classList.contains('hidden') &&
                       !closeTimer) {
                closeTimer = setTimeout(closeSidebar, CLOSE_DELAY);
            }
        });

        sidebar.addEventListener('mouseenter', () => { clearCloseTimer(); });
        sidebar.addEventListener('mouseleave', () => {
            clearCloseTimer();
            closeTimer = setTimeout(closeSidebar, CLOSE_DELAY);
        });

        if (hoverStrip) {
            hoverStrip.addEventListener('mouseenter', () => { openSidebar(); });
        }
    } else {
        // Touch: click to toggle
        if (hoverStrip) {
            hoverStrip.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                if (sidebar.classList.contains('hidden')) openSidebar();
                else closeSidebar();
            });
        }

        document.addEventListener('click', (e) => {
            if (!sidebar.contains(e.target) && !(hoverStrip?.contains(e.target))) {
                if (!sidebar.classList.contains('hidden')) closeSidebar();
            }
        });
    }

    if (hoverStrip) {
        hoverStrip.addEventListener('keydown', (ev) => {
            if (ev.key === 'Enter' || ev.key === ' ' || ev.key === 'Spacebar') {
                ev.preventDefault();
                openSidebar();
            } else if (ev.key === 'Escape') {
                ev.preventDefault();
                closeSidebar();
            }
        });
        if (!sidebar.classList.contains('hidden')) hoverStrip.classList.add('hidden');
    }

    // Global keyboard: Escape closes open panels
    document.addEventListener('keydown', (ev) => {
        if (ev.key === 'Escape') {
            const filesPanel = document.getElementById('filesPanel');
            if (filesPanel && !filesPanel.classList.contains('hidden')) {
                hideFilesPanel();
                ev.stopPropagation();
                return;
            }
            if (sidebar && !sidebar.classList.contains('hidden')) {
                closeSidebar();
                ev.stopPropagation();
            }
        }
    });
}

// ============================================
// DOMContentLoaded Event Handlers
// ============================================
document.addEventListener('DOMContentLoaded', () => {
    // Sidebar section toggles
    document.querySelectorAll('.sidebar-section-header.clickable').forEach(header => {
        header.addEventListener('click', () => {
            const section = header.nextElementSibling;
            if (section) section.classList.toggle('collapsed');
        });
    });

    // Sidebar hover strip
    const hoverStrip = document.getElementById('hoverStrip');
    const sidebar = document.querySelector('.sidebar');
    if (hoverStrip && sidebar) {
        hoverStrip.addEventListener('click', () => {
            sidebar.classList.toggle('hidden');
        });
    }

    // Files panel buttons
    const filesBtn = document.getElementById('filesBtn');
    if (filesBtn) filesBtn.onclick = showFilesPanel;
    const closeFilesBtn = document.getElementById('closeFilesBtn');
    if (closeFilesBtn) closeFilesBtn.onclick = hideFilesPanel;
    if (typeof initFilesPanelRefs === 'function') initFilesPanelRefs();

    // Projects panel buttons
    const projectsBtn = document.getElementById('projectsBtn');
    if (projectsBtn) projectsBtn.onclick = () => {
        document.getElementById('projectsPanel').classList.remove('hidden');
        renderProjects();
    };
    const closeProjectsBtn = document.getElementById('closeProjectsBtn');
    if (closeProjectsBtn) closeProjectsBtn.onclick = () => {
        document.getElementById('projectsPanel').classList.add('hidden');
    };

    // Settings button
    const settingsBtn = document.getElementById('settingsBtn');
    if (settingsBtn) settingsBtn.onclick = toggleSettings;

    // Images button
    const imagesBtn = document.getElementById('imagesBtn');
    if (imagesBtn) imagesBtn.onclick = () => {
        document.getElementById('imagesPanel').classList.remove('hidden');
        renderImages();
    };
    const closeImagesBtn = document.getElementById('closeImagesBtn');
    if (closeImagesBtn) closeImagesBtn.onclick = () => {
        document.getElementById('imagesPanel').classList.add('hidden');
    };

    // Network button
    const networkBtn = document.getElementById('networkBtn');
    if (networkBtn) networkBtn.onclick = networkAction;

    // Send message on Enter key
    if (messageInput) {
        messageInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        });
    }

    // Initialize the application
    init();
});

// ============================================
// Main Initialization Function
// ============================================
function init() {
    if (init._ran) return; // idempotent guard
    init._ran = true;

    // Initialize modules
    initModelSelector();
    renderProjects();
    renderHistory();
    hideFilesPanel();

    // Attach send button handler
    if (sendBtn) sendBtn.onclick = sendMessage;

    // Setup sidebar behavior
    setupSidebarHover();

    // Check backend availability
    checkBackend(false);

    console.log('[Parakleon] Initialized successfully');
}

// Make functions available globally for inline HTML handlers
window.toggleSection = toggleSection;
window.sendMessage = sendMessage;
window.networkAction = networkAction;
window.addMessage = addMessage;
window.renderHistory = renderHistory;

// Settings functions
window.toggleSettings = toggleSettings;
window.saveTemperature = saveTemperature;
window.saveMaxTokens = saveMaxTokens;
window.saveTopP = saveTopP;
window.saveFrequencyPenalty = saveFrequencyPenalty;
window.savePresencePenalty = savePresencePenalty;
window.saveEnterToSend = saveEnterToSend;
window.saveShowTimestamps = saveShowTimestamps;
window.saveApiKey = saveApiKey;

// Image generation functions
window.openImageGenerator = openImageGenerator;
window.closeImageGenerator = closeImageGenerator;
window.generateImage = generateImage;
window.openImagesGallery = openImagesGallery;
window.closeImagesGallery = closeImagesGallery;
window.clearGeneratedImages = clearGeneratedImages;

// Also make sure utils are globally available if needed by inline handlers
window.showToast = showToast;
