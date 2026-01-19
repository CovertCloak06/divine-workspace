/**
 * Files Panel Module
 * Simple file management panel for uploaded files
 */

import { showToast, escapeHtml } from '../utils/utils.js';

// DOM references
let filesPanel = null;
let filesListEl = null;

/**
 * Initialize files panel DOM references
 */
export function initFilesPanelRefs() {
    filesPanel = document.getElementById('filesPanel');
    filesListEl = document.getElementById('filesList');
}

/**
 * Show the files panel and load file list
 */
export function showFilesPanel() {
    if (!filesPanel) initFilesPanelRefs();
    if (filesPanel) {
        filesPanel.classList.remove('hidden');
        renderGlobalFilesList();
    }
}

/**
 * Hide the files panel
 */
export function hideFilesPanel() {
    if (!filesPanel) initFilesPanelRefs();
    if (filesPanel) {
        filesPanel.classList.add('hidden');
    }
}

/**
 * Format file size for display
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

/**
 * Render the list of uploaded files
 */
export async function renderGlobalFilesList() {
    if (!filesListEl) initFilesPanelRefs();
    if (!filesListEl) return;

    filesListEl.innerHTML = '<p style="color: #666; text-align: center; padding: 20px;">Loading files...</p>';

    try {
        const response = await fetch('/api/files/list');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        const files = data.files || [];

        filesListEl.innerHTML = '';

        if (files.length === 0) {
            filesListEl.innerHTML = '<p style="color: #999; text-align: center; padding: 20px;">No files uploaded yet.</p>';
            return;
        }

        files.forEach(file => {
            const item = document.createElement('div');
            item.className = 'file-item';
            item.style.cssText = 'display:flex;justify-content:space-between;align-items:center;padding:8px;margin-bottom:4px;background:rgba(0,255,255,0.05);border-radius:4px;';

            const isImage = file.filename.match(/\.(jpeg|jpg|gif|png|webp|svg)$/i);
            const icon = isImage ? '\uD83D\uDDBC\uFE0F' : '\uD83D\uDCC4';
            const size = formatFileSize(file.size);

            const nameSpan = document.createElement('span');
            nameSpan.innerHTML = `${icon} ${escapeHtml(file.filename)} <small style="color:#666">(${size})</small>`;

            const deleteBtn = document.createElement('button');
            deleteBtn.style.cssText = 'background:transparent;border:none;color:#ff4444;cursor:pointer;font-size:16px;';
            deleteBtn.textContent = '\u00D7';
            deleteBtn.onclick = () => deleteGlobalFile(file.id);

            item.appendChild(nameSpan);
            item.appendChild(deleteBtn);
            filesListEl.appendChild(item);
        });

    } catch (error) {
        console.error('Failed to load global files:', error);
        filesListEl.innerHTML = `<p style="color: #ff6b6b; text-align: center; padding: 20px;">Error loading files: ${error.message}</p>`;
    }
}

/**
 * Delete a file by ID
 */
export async function deleteGlobalFile(fileId) {
    if (!confirm('Are you sure you want to delete this file permanently? This cannot be undone.')) {
        return;
    }

    try {
        const response = await fetch(`/api/files/${fileId}`, {
            method: 'DELETE'
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
            throw new Error(errorData.error || `Server error: ${response.status}`);
        }

        showToast('File deleted successfully.', 3000, 'success');
        renderGlobalFilesList();

    } catch (error) {
        console.error('Failed to delete file:', error);
        showToast(`Failed to delete file: ${error.message}`, 5000, 'error');
    }
}
