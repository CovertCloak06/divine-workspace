/**
 * File Manager Module
 * Handles file uploads, preview, and metadata display
 */

export class FileManager {
    constructor() {
        this.files = [];
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadFiles();
    }

    setupEventListeners() {
        document.getElementById('uploadBtn').addEventListener('click', () => {
            document.getElementById('fileUpload').click();
        });

        document.getElementById('fileUpload').addEventListener('change', (e) => {
            this.handleFileUpload(e.target.files);
        });

        document.getElementById('refreshFiles').addEventListener('click', () => {
            this.loadFiles();
        });
    }

    handleFileUpload(fileList) {
        Array.from(fileList).forEach(file => {
            const fileData = {
                id: Date.now() + Math.random(),
                name: file.name,
                size: file.size,
                type: file.type,
                uploaded: new Date().toISOString(),
                file: file
            };

            this.files.push(fileData);
            this.readFileContent(fileData);
        });

        this.saveFiles();
        this.renderFilesList();
    }

    readFileContent(fileData) {
        const reader = new FileReader();

        reader.onload = (e) => {
            fileData.content = e.target.result;
            this.saveFiles();
        };

        // Read as text for code files, data URL for images
        if (fileData.type.startsWith('image/')) {
            reader.readAsDataURL(fileData.file);
        } else {
            reader.readAsText(fileData.file);
        }
    }

    renderFilesList() {
        const container = document.getElementById('filesList');
        container.innerHTML = '';

        if (this.files.length === 0) {
            container.innerHTML = '<div style="color: #888; padding: 20px; text-align: center;">No files uploaded yet</div>';
            return;
        }

        this.files.forEach(file => {
            const item = document.createElement('div');
            item.className = 'file-item';

            const info = document.createElement('div');
            info.innerHTML = `
                <div class="file-name">${this.escapeHtml(file.name)}</div>
                <div class="file-size">${this.formatFileSize(file.size)} • ${file.type || 'unknown'}</div>
            `;

            const actions = document.createElement('div');
            actions.style.display = 'flex';
            actions.style.gap = '8px';

            const viewBtn = this.createButton('👁️ View', () => this.viewFile(file));
            const deleteBtn = this.createButton('🗑️', () => this.deleteFile(file.id));
            deleteBtn.style.color = '#FF4444';

            actions.appendChild(viewBtn);
            actions.appendChild(deleteBtn);

            item.appendChild(info);
            item.appendChild(actions);
            container.appendChild(item);
        });
    }

    viewFile(file) {
        const modal = this.createModal(`File: ${file.name}`);
        const content = modal.querySelector('.modal-content');

        if (file.type.startsWith('image/')) {
            const img = document.createElement('img');
            img.src = file.content;
            img.style.maxWidth = '100%';
            img.style.maxHeight = '500px';
            content.appendChild(img);
        } else if (file.type.startsWith('text/') || file.type.includes('json') || file.type.includes('javascript')) {
            const pre = document.createElement('pre');
            pre.style.background = '#0d0d0d';
            pre.style.padding = '16px';
            pre.style.borderRadius = '8px';
            pre.style.overflow = 'auto';
            pre.style.maxHeight = '500px';
            pre.style.color = '#E0E0E0';
            pre.textContent = file.content;
            content.appendChild(pre);
        } else {
            content.innerHTML = `<p style="color: #888;">Preview not available for this file type</p>
                                 <p>Size: ${this.formatFileSize(file.size)}</p>
                                 <p>Type: ${file.type}</p>`;
        }

        document.body.appendChild(modal);
    }

    deleteFile(id) {
        if (confirm('Delete this file?')) {
            this.files = this.files.filter(f => f.id !== id);
            this.saveFiles();
            this.renderFilesList();
        }
    }

    createButton(text, onClick) {
        const btn = document.createElement('button');
        btn.textContent = text;
        btn.className = 'btn-sm';
        btn.onclick = onClick;
        return btn;
    }

    createModal(title) {
        const overlay = document.createElement('div');
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 10000;
        `;

        const modal = document.createElement('div');
        modal.style.cssText = `
            background: #1a1a1a;
            border: 2px solid #00FFFF;
            border-radius: 12px;
            max-width: 800px;
            max-height: 80vh;
            overflow: auto;
            padding: 24px;
        `;

        const header = document.createElement('div');
        header.style.cssText = `
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            border-bottom: 1px solid #333;
            padding-bottom: 12px;
        `;

        const titleEl = document.createElement('h3');
        titleEl.textContent = title;
        titleEl.style.color = '#00FFFF';

        const closeBtn = document.createElement('button');
        closeBtn.textContent = '✕';
        closeBtn.className = 'btn-sm';
        closeBtn.onclick = () => overlay.remove();

        header.appendChild(titleEl);
        header.appendChild(closeBtn);

        const content = document.createElement('div');
        content.className = 'modal-content';

        modal.appendChild(header);
        modal.appendChild(content);
        overlay.appendChild(modal);

        overlay.onclick = (e) => {
            if (e.target === overlay) overlay.remove();
        };

        return overlay;
    }

    formatFileSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    saveFiles() {
        // Save file metadata (not content) to localStorage
        const metadata = this.files.map(f => ({
            id: f.id,
            name: f.name,
            size: f.size,
            type: f.type,
            uploaded: f.uploaded
        }));

        localStorage.setItem('debugger_files', JSON.stringify(metadata));
    }

    loadFiles() {
        try {
            const saved = localStorage.getItem('debugger_files');
            if (saved) {
                const metadata = JSON.parse(saved);
                // Note: We can't restore actual file content from localStorage
                // This is just for demonstration
                this.renderFilesList();
            }
        } catch (e) {
            console.error('Error loading files:', e);
        }
    }
}

window.FileManager = FileManager;
