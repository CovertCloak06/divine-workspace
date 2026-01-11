/**
 * Enhanced File Explorer Module
 * Modern file manager with tree view, drag-drop, preview, and search
 * Integrated into PKN - Non-module version
 */

// Utility functions (inline to avoid module dependencies)
function showToast(message, duration = 3000, type = 'info') {
    if (window.showToast) {
        window.showToast(message, duration, type);
    } else {
        console.log(`[${type.toUpperCase()}] ${message}`);
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

class FileExplorer {
    constructor() {
        this.filesPanel = null;
        this.filesListEl = null;
        this.breadcrumbEl = null;
        this.searchInput = null;

        // State
        this.currentLocation = 'uploads';
        this.currentPath = '/';
        this.pathHistory = [];
        this.selectedFiles = new Set();
        this.viewMode = 'grid'; // 'grid' or 'list'
        this.sortBy = 'name'; // 'name', 'date', 'size', 'type'
        this.sortOrder = 'asc';

        // Base paths
        this.LOCATION_PATHS = {
            sdcard: '/sdcard',
            home: '/data/data/com.termux/files/home',
            pkn: '/sdcard/pkn',
            uploads: 'uploads'
        };
    }

    init() {
        this.initDOMRefs();
        this.setupEventListeners();
        this.setupDragAndDrop();
        this.loadCurrentPath();
    }

    initDOMRefs() {
        this.filesPanel = document.getElementById('filesPanel');
        this.filesListEl = document.getElementById('filesList');
        this.breadcrumbEl = document.getElementById('fileBreadcrumb');
        this.searchInput = document.getElementById('fileSearch');
    }

    setupEventListeners() {
        // View mode toggle
        document.getElementById('toggleViewMode')?.addEventListener('click', () => {
            this.viewMode = this.viewMode === 'grid' ? 'list' : 'grid';
            this.loadCurrentPath();
        });

        // Sort controls
        document.getElementById('sortBy')?.addEventListener('change', (e) => {
            this.sortBy = e.target.value;
            this.loadCurrentPath();
        });

        // Search
        this.searchInput?.addEventListener('input', (e) => {
            this.filterFiles(e.target.value);
        });

        // Upload button
        document.getElementById('uploadFileBtn')?.addEventListener('click', () => {
            const input = document.createElement('input');
            input.type = 'file';
            input.multiple = true;
            input.onchange = (e) => this.uploadFiles(e.target.files);
            input.click();
        });

        // New folder
        document.getElementById('newFolderBtn')?.addEventListener('click', () => {
            this.createFolder();
        });

        // Refresh
        document.getElementById('refreshFilesBtn')?.addEventListener('click', () => {
            this.loadCurrentPath();
        });

        // Delete selected
        document.getElementById('deleteSelectedBtn')?.addEventListener('click', () => {
            this.deleteSelected();
        });

        // Location tabs
        document.querySelectorAll('.file-location-tab')?.forEach(tab => {
            tab.addEventListener('click', (e) => {
                this.switchLocation(e.target.dataset.location);
            });
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (this.filesPanel && !this.filesPanel.classList.contains('hidden')) {
                if (e.key === 'Delete') {
                    this.deleteSelected();
                } else if (e.ctrlKey && e.key === 'a') {
                    e.preventDefault();
                    this.selectAll();
                }
            }
        });
    }

    setupDragAndDrop() {
        if (!this.filesListEl) return;

        // Prevent default drag behaviors
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            this.filesListEl.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
            });
        });

        // Highlight drop zone
        ['dragenter', 'dragover'].forEach(eventName => {
            this.filesListEl.addEventListener(eventName, () => {
                this.filesListEl.classList.add('drag-over');
            });
        });

        ['dragleave', 'drop'].forEach(eventName => {
            this.filesListEl.addEventListener(eventName, () => {
                this.filesListEl.classList.remove('drag-over');
            });
        });

        // Handle drop
        this.filesListEl.addEventListener('drop', (e) => {
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                this.uploadFiles(files);
            }
        });
    }

    async loadCurrentPath() {
        this.showLoading(true);

        try {
            if (this.currentLocation === 'uploads') {
                await this.loadUploads();
            } else {
                await this.loadDirectory();
            }

            this.updateBreadcrumb();
        } catch (error) {
            console.error('Failed to load path:', error);
            showToast('Failed to load files: ' + error.message, 5000, 'error');
        } finally {
            this.showLoading(false);
        }
    }

    async loadUploads() {
        const response = await fetch('/api/files/list');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        this.renderFiles(data.files || [], 'uploads');
    }

    async loadDirectory() {
        const fullPath = this.LOCATION_PATHS[this.currentLocation] + this.currentPath;

        const response = await fetch('/api/files/browse', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: fullPath })
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ error: 'Server error' }));
            throw new Error(errorData.error || `HTTP ${response.status}`);
        }

        const data = await response.json();
        this.renderFiles(data.files || [], 'directory');
    }

    renderFiles(files, type) {
        this.filesListEl.innerHTML = '';

        if (files.length === 0) {
            this.showEmptyState();
            return;
        }

        // Sort files
        files = this.sortFiles(files);

        // Create container based on view mode
        const container = document.createElement('div');
        container.className = `files-container files-${this.viewMode}`;

        files.forEach(file => {
            const item = this.createFileItem(file, type);
            container.appendChild(item);
        });

        this.filesListEl.appendChild(container);
    }

    createFileItem(file, type) {
        const item = document.createElement('div');
        item.className = `file-item ${file.type || ''}`;
        item.dataset.fileId = file.id || file.name;
        item.dataset.fileName = file.name || file.filename;

        // Icon
        const icon = document.createElement('div');
        icon.className = 'file-icon';
        icon.textContent = this.getFileIcon(file);

        // Name
        const name = document.createElement('div');
        name.className = 'file-name';
        name.textContent = file.name || file.filename;
        name.title = file.name || file.filename;

        // Metadata
        const meta = document.createElement('div');
        meta.className = 'file-meta';

        if (file.size !== undefined) {
            meta.textContent = this.formatFileSize(file.size);
        }

        if (file.modified) {
            const date = new Date(file.modified * 1000);
            meta.textContent += ` • ${date.toLocaleDateString()}`;
        }

        // Create menu for files (not directories)
        let menu = null;
        if (type === 'directory' || type === 'uploads') {
            if (file.type !== 'directory') {
                menu = this.createFileMenu(file);
                item.appendChild(menu);
            }
        }

        // Click handler - show dropdown for files, navigate for directories
        item.addEventListener('click', (e) => {
            // Don't trigger if clicking on menu itself
            if (e.target.closest('.file-menu')) return;

            if (file.type === 'directory') {
                this.navigateToPath(this.currentPath + '/' + file.name);
            } else {
                // Show dropdown menu
                if (menu) {
                    this.closeAllMenus();
                    this.toggleFileMenu(menu, item);
                }
            }
        });

        // Double-click to open
        item.addEventListener('dblclick', () => {
            if (file.type !== 'directory') {
                this.viewFile(file);
            }
        });

        // Assemble item
        item.appendChild(icon);
        item.appendChild(name);
        if (this.viewMode === 'list') {
            item.appendChild(meta);
        }
        // Menu already appended above if it exists

        return item;
    }

    createFileMenu(file) {
        const menu = document.createElement('div');
        menu.className = 'file-menu';

        const actions = [
            { icon: '👁️', label: 'View', action: () => this.viewFile(file) },
            { icon: '⬇️', label: 'Download', action: () => this.downloadFile(file) },
            { icon: '✏️', label: 'Rename', action: () => this.renameFile(file) },
            { icon: '📋', label: 'Copy', action: () => this.copyFile(file) },
            { icon: '📁', label: 'Move', action: () => this.moveFile(file) },
            { icon: '🗑️', label: 'Delete', action: () => this.deleteFile(file), danger: true }
        ];

        actions.forEach(action => {
            const item = document.createElement('div');
            item.className = `file-menu-item${action.danger ? ' danger' : ''}`;

            const icon = document.createElement('span');
            icon.className = 'file-menu-icon';
            icon.textContent = action.icon;

            const label = document.createElement('span');
            label.textContent = action.label;

            item.appendChild(icon);
            item.appendChild(label);

            item.addEventListener('click', (e) => {
                e.stopPropagation();
                action.action();
                this.closeAllMenus();
            });

            menu.appendChild(item);
        });

        return menu;
    }

    toggleFileMenu(menu, fileItem) {
        // Close other menus
        this.closeAllMenus();

        // Toggle current menu
        menu.classList.toggle('show');

        // Close menu when clicking outside
        if (menu.classList.contains('show')) {
            setTimeout(() => {
                document.addEventListener('click', (e) => {
                    if (!e.target.closest('.file-menu') && !e.target.closest('.file-item')) {
                        this.closeAllMenus();
                    }
                }, { once: true });
            }, 0);
        }
    }

    closeAllMenus() {
        document.querySelectorAll('.file-menu.show').forEach(menu => {
            menu.classList.remove('show');
        });
    }

    createActionButton(icon, onClick) {
        const btn = document.createElement('button');
        btn.className = 'file-action-btn';
        btn.textContent = icon;
        btn.onclick = (e) => {
            e.stopPropagation();
            onClick();
        };
        return btn;
    }

    getFileIcon(file) {
        const type = file.type;
        const name = (file.name || file.filename || '').toLowerCase();

        if (type === 'directory') return '📁';
        if (name.match(/\.(jpg|jpeg|png|gif|svg|webp)$/)) return '🖼️';
        if (name.match(/\.(pdf)$/)) return '📄';
        if (name.match(/\.(mp4|avi|mov|mkv)$/)) return '🎬';
        if (name.match(/\.(mp3|wav|flac)$/)) return '🎵';
        if (name.match(/\.(zip|rar|7z|tar|gz)$/)) return '📦';
        if (name.match(/\.(py|js|html|css|json|xml)$/)) return '📝';
        if (name.match(/\.(exe|app|deb|apk)$/)) return '⚙️';

        return '📄';
    }

    sortFiles(files) {
        return files.sort((a, b) => {
            // Directories first
            if (a.type === 'directory' && b.type !== 'directory') return -1;
            if (a.type !== 'directory' && b.type === 'directory') return 1;

            let compareValue = 0;

            switch (this.sortBy) {
                case 'name':
                    compareValue = (a.name || a.filename).localeCompare(b.name || b.filename);
                    break;
                case 'size':
                    compareValue = (a.size || 0) - (b.size || 0);
                    break;
                case 'date':
                    compareValue = (a.modified || a.uploaded_at || 0) - (b.modified || b.uploaded_at || 0);
                    break;
                case 'type':
                    compareValue = (a.type || '').localeCompare(b.type || '');
                    break;
            }

            return this.sortOrder === 'asc' ? compareValue : -compareValue;
        });
    }

    toggleFileSelection(item) {
        const fileId = item.dataset.fileId;

        if (this.selectedFiles.has(fileId)) {
            this.selectedFiles.delete(fileId);
            item.classList.remove('selected');
        } else {
            this.selectedFiles.add(fileId);
            item.classList.add('selected');
        }

        this.updateSelectionCount();
    }

    selectAll() {
        document.querySelectorAll('.file-item').forEach(item => {
            const fileId = item.dataset.fileId;
            this.selectedFiles.add(fileId);
            item.classList.add('selected');
        });

        this.updateSelectionCount();
    }

    updateSelectionCount() {
        const countEl = document.getElementById('selectedCount');
        if (countEl) {
            countEl.textContent = this.selectedFiles.size > 0
                ? `${this.selectedFiles.size} selected`
                : '';
        }
    }

    async uploadFiles(fileList) {
        const formData = new FormData();

        Array.from(fileList).forEach(file => {
            formData.append('file', file);
        });

        showToast(`Uploading ${fileList.length} file(s)...`, 3000, 'info');

        try {
            // Upload files one by one
            for (const file of fileList) {
                const singleFormData = new FormData();
                singleFormData.append('file', file);

                const response = await fetch('/api/files/upload', {
                    method: 'POST',
                    body: singleFormData
                });

                if (!response.ok) {
                    throw new Error(`Failed to upload ${file.name}`);
                }
            }

            showToast('Files uploaded successfully!', 3000, 'success');
            this.loadCurrentPath();
        } catch (error) {
            console.error('Upload error:', error);
            showToast('Upload failed: ' + error.message, 5000, 'error');
        }
    }

    async viewFile(file) {
        // Create preview modal
        const modal = this.createPreviewModal(file);
        document.body.appendChild(modal);
    }

    createPreviewModal(file) {
        const overlay = document.createElement('div');
        overlay.className = 'file-preview-modal';
        overlay.onclick = (e) => {
            if (e.target === overlay) overlay.remove();
        };

        const modal = document.createElement('div');
        modal.className = 'preview-content';

        const header = document.createElement('div');
        header.className = 'preview-header';
        header.innerHTML = `
            <h3>${escapeHtml(file.name || file.filename)}</h3>
            <button class="close-btn" onclick="this.closest('.file-preview-modal').remove()">✕</button>
        `;

        const body = document.createElement('div');
        body.className = 'preview-body';

        // Load file preview based on type
        this.loadFilePreview(file, body);

        modal.appendChild(header);
        modal.appendChild(body);
        overlay.appendChild(modal);

        return overlay;
    }

    async loadFilePreview(file, container) {
        container.innerHTML = '<div class="loading">Loading preview...</div>';

        try {
            const response = await fetch(`/api/files/${file.id}`);
            if (!response.ok) throw new Error('Failed to load file');

            const blob = await response.blob();
            const url = URL.createObjectURL(blob);

            if (file.type?.startsWith('image/')) {
                container.innerHTML = `<img src="${url}" alt="${escapeHtml(file.name)}" style="max-width: 100%; max-height: 70vh;">`;
            } else if (file.type?.startsWith('text/') || file.name?.match(/\.(txt|log|md|json|js|py|html|css)$/)) {
                const text = await blob.text();
                container.innerHTML = `<pre style="max-height: 70vh; overflow: auto;">${escapeHtml(text)}</pre>`;
            } else {
                container.innerHTML = `<div>Preview not available. <a href="${url}" download="${file.name}">Download file</a></div>`;
            }
        } catch (error) {
            container.innerHTML = `<div class="error">Failed to load preview: ${error.message}</div>`;
        }
    }

    async downloadFile(file) {
        const response = await fetch(`/api/files/${file.id}`);
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);

        const a = document.createElement('a');
        a.href = url;
        a.download = file.name || file.filename;
        a.click();

        URL.revokeObjectURL(url);
    }

    async deleteFile(file) {
        if (!confirm(`Delete ${file.name || file.filename}?`)) return;

        try {
            const response = await fetch(`/api/files/${file.id}`, {
                method: 'DELETE'
            });

            if (!response.ok) throw new Error('Delete failed');

            showToast('File deleted', 3000, 'success');
            this.loadCurrentPath();
        } catch (error) {
            showToast('Delete failed: ' + error.message, 5000, 'error');
        }
    }

    async renameFile(file) {
        const newName = prompt(`Rename file:`, file.name || file.filename);
        if (!newName || newName === file.name) return;

        try {
            // For now, show message that rename is coming soon
            showToast('Rename functionality coming soon', 3000, 'info');
            // TODO: Implement rename API endpoint
        } catch (error) {
            showToast('Rename failed: ' + error.message, 5000, 'error');
        }
    }

    async copyFile(file) {
        try {
            // Store file info for paste operation
            this.clipboard = { file, operation: 'copy' };
            showToast(`Copied: ${file.name || file.filename}`, 2000, 'success');
        } catch (error) {
            showToast('Copy failed: ' + error.message, 5000, 'error');
        }
    }

    async moveFile(file) {
        try {
            // Store file info for paste operation
            this.clipboard = { file, operation: 'move' };
            showToast(`Cut: ${file.name || file.filename}`, 2000, 'success');
        } catch (error) {
            showToast('Move failed: ' + error.message, 5000, 'error');
        }
    }

    async deleteSelected() {
        if (this.selectedFiles.size === 0) return;
        if (!confirm(`Delete ${this.selectedFiles.size} file(s)?`)) return;

        // Delete all selected files
        for (const fileId of this.selectedFiles) {
            try {
                await fetch(`/api/files/${fileId}`, { method: 'DELETE' });
            } catch (e) {
                console.error('Error deleting:', fileId, e);
            }
        }

        this.selectedFiles.clear();
        showToast('Files deleted', 3000, 'success');
        this.loadCurrentPath();
    }

    async createFolder() {
        const name = prompt('Folder name:');
        if (!name) return;

        // Implementation depends on backend support
        showToast('Creating folder...', 2000, 'info');
    }

    switchLocation(location) {
        this.currentLocation = location;
        this.currentPath = '/';
        this.pathHistory = [];

        document.querySelectorAll('.file-location-tab').forEach(tab => {
            tab.classList.toggle('active', tab.dataset.location === location);
        });

        this.loadCurrentPath();
    }

    navigateToPath(path) {
        this.currentPath = path;
        this.loadCurrentPath();
    }

    updateBreadcrumb() {
        if (!this.breadcrumbEl) return;

        this.breadcrumbEl.innerHTML = '';

        const locationName = {
            sdcard: '📱 SD Card',
            home: '🏠 Home',
            pkn: '⚡ PKN',
            uploads: '📤 Uploads'
        }[this.currentLocation];

        const root = document.createElement('span');
        root.className = 'breadcrumb-item';
        root.textContent = locationName;
        root.onclick = () => this.navigateToPath('/');
        this.breadcrumbEl.appendChild(root);

        if (this.currentPath !== '/') {
            const parts = this.currentPath.split('/').filter(p => p);
            let currentPath = '';

            parts.forEach((part, i) => {
                currentPath += '/' + part;
                const pathCopy = currentPath;

                const sep = document.createElement('span');
                sep.textContent = ' / ';
                sep.className = 'breadcrumb-sep';

                const item = document.createElement('span');
                item.className = 'breadcrumb-item';
                item.textContent = part;
                item.onclick = () => this.navigateToPath(pathCopy);

                this.breadcrumbEl.appendChild(sep);
                this.breadcrumbEl.appendChild(item);
            });
        }
    }

    filterFiles(query) {
        const items = document.querySelectorAll('.file-item');
        const lowerQuery = query.toLowerCase();

        items.forEach(item => {
            const name = item.dataset.fileName.toLowerCase();
            item.style.display = name.includes(lowerQuery) ? '' : 'none';
        });
    }

    showLoading(show) {
        if (show) {
            this.filesListEl.innerHTML = '<div class="loading">Loading files...</div>';
        }
    }

    showEmptyState() {
        this.filesListEl.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">📂</div>
                <div class="empty-text">No files found</div>
                <div class="empty-hint">Drag and drop files here or click Upload</div>
            </div>
        `;
    }

    formatFileSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
        return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
    }
}

// Global instance and initialization
let fileExplorerInstance = null;

function initFileExplorer() {
    if (!fileExplorerInstance) {
        fileExplorerInstance = new FileExplorer();
        fileExplorerInstance.init();
    }
    return fileExplorerInstance;
}

// Global functions for backward compatibility with old files.js API
function showFilesPanel() {
    const explorer = initFileExplorer();
    explorer.filesPanel?.classList.remove('hidden');
    explorer.loadCurrentPath();
}

function hideFilesPanel() {
    const explorer = initFileExplorer();
    explorer.filesPanel?.classList.add('hidden');
}

function switchFileLocation(location) {
    const explorer = initFileExplorer();
    explorer.switchLocation(location);
}

function navigateToPath(path) {
    const explorer = initFileExplorer();
    explorer.navigateToPath(path);
}

function refreshCurrentPath() {
    const explorer = initFileExplorer();
    explorer.loadCurrentPath();
}

function createNewFolder() {
    const explorer = initFileExplorer();
    explorer.createFolder();
}

// Attach to window for global access
window.FileExplorer = FileExplorer;
window.initFileExplorer = initFileExplorer;
window.showFilesPanel = showFilesPanel;
window.hideFilesPanel = hideFilesPanel;
window.switchFileLocation = switchFileLocation;
window.navigateToPath = navigateToPath;
window.refreshCurrentPath = refreshCurrentPath;
window.createNewFolder = createNewFolder;

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initFileExplorer);
} else {
    initFileExplorer();
}
