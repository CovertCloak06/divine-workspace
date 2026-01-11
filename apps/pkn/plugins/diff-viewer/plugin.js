/**
 * Code Diff Viewer Plugin
 * Side-by-side code comparison with syntax highlighting
 */

import { PluginBase } from '../../js/plugin-base.js';

export class DiffViewerPlugin extends PluginBase {
    constructor(manifest) {
        super(manifest);
        this.currentDiff = null;
        this.diffHistory = [];
    }

    async init() {
        await super.init();

        const defaults = {
            viewMode: 'split',
            showLineNumbers: true,
            contextLines: 3
        };
        this.loadSettings({ ...defaults, ...this.getSettings() });

        // Load diff history
        this.loadDiffHistory();

        this.injectCSS(this.getCSS());
    }

    async enable() {
        await super.enable();

        // Add diff viewer button to chat toolbar
        this.addDiffButton();

        // Subscribe to code messages for auto-detection
        this.subscribe('message:received', (data) => this.autoDetectDiff(data));

        // Make globally available
        window.diffViewer = this;

        console.log(`[${this.name}] Diff Viewer active`);
    }

    async disable() {
        await super.disable();
        this.removeDiffButton();
        this.hideDiffPanel();
    }

    /**
     * Add diff button to toolbar
     */
    addDiffButton() {
        const toolbar = document.querySelector('.chat-toolbar-right');
        if (!toolbar) return;

        const button = document.createElement('button');
        button.id = 'diffViewerBtn';
        button.className = 'chat-toolbar-btn';
        button.title = 'Compare Code';
        button.innerHTML = '<span>⚖️</span>';
        button.onclick = () => this.showDiffPanel();

        toolbar.appendChild(button);
    }

    /**
     * Remove diff button
     */
    removeDiffButton() {
        const button = document.getElementById('diffViewerBtn');
        if (button) button.remove();
    }

    /**
     * Show diff panel
     */
    showDiffPanel() {
        // Remove existing panel
        this.hideDiffPanel();

        const panel = document.createElement('div');
        panel.id = 'diffViewerPanel';
        panel.className = 'diff-viewer-panel';

        let html = `
            <div class="diff-panel-header">
                <div class="diff-panel-title">Code Diff Viewer</div>
                <button class="diff-panel-close" onclick="window.diffViewer.hideDiffPanel()">×</button>
            </div>
            <div class="diff-panel-toolbar">
                <button class="diff-toolbar-btn ${this.getSetting('viewMode') === 'split' ? 'active' : ''}"
                        onclick="window.diffViewer.setViewMode('split')">
                    Split View
                </button>
                <button class="diff-toolbar-btn ${this.getSetting('viewMode') === 'unified' ? 'active' : ''}"
                        onclick="window.diffViewer.setViewMode('unified')">
                    Unified View
                </button>
                <button class="diff-toolbar-btn" onclick="window.diffViewer.showDiffInput()">
                    + New Diff
                </button>
            </div>
            <div class="diff-panel-body">
        `;

        if (this.currentDiff) {
            html += this.renderDiff(this.currentDiff);
        } else {
            html += `
                <div class="diff-empty">
                    <div class="diff-empty-icon">⚖️</div>
                    <div class="diff-empty-text">No diff to display</div>
                    <button class="diff-btn primary" onclick="window.diffViewer.showDiffInput()">
                        Create New Diff
                    </button>
                </div>
            `;
        }

        // Diff history
        if (this.diffHistory.length > 0) {
            html += `
                <div class="diff-history">
                    <div class="diff-history-header">Recent Diffs</div>
                    <div class="diff-history-list">
            `;

            this.diffHistory.slice(-5).reverse().forEach((diff, idx) => {
                const actualIdx = this.diffHistory.length - 1 - idx;
                html += `
                    <div class="diff-history-item" onclick="window.diffViewer.loadDiff(${actualIdx})">
                        <div class="diff-history-title">${diff.title || 'Untitled Diff'}</div>
                        <div class="diff-history-stats">
                            <span class="stat-add">+${diff.stats.additions}</span>
                            <span class="stat-del">-${diff.stats.deletions}</span>
                            <span class="diff-history-date">${diff.date}</span>
                        </div>
                    </div>
                `;
            });

            html += `
                    </div>
                </div>
            `;
        }

        html += `
            </div>
        `;

        panel.innerHTML = html;
        document.body.appendChild(panel);

        setTimeout(() => panel.classList.add('visible'), 10);
    }

    /**
     * Hide diff panel
     */
    hideDiffPanel() {
        const panel = document.getElementById('diffViewerPanel');
        if (panel) {
            panel.classList.remove('visible');
            setTimeout(() => panel.remove(), 300);
        }
    }

    /**
     * Show diff input dialog
     */
    showDiffInput() {
        const inputHtml = `
            <div class="diff-input-dialog">
                <div class="diff-input-header">
                    <div>Create New Diff</div>
                    <button onclick="window.diffViewer.closeDiffInput()">×</button>
                </div>
                <div class="diff-input-body">
                    <div class="diff-input-section">
                        <label>Original Code</label>
                        <textarea id="diffOriginalInput" placeholder="Paste original code..."></textarea>
                    </div>
                    <div class="diff-input-section">
                        <label>Modified Code</label>
                        <textarea id="diffModifiedInput" placeholder="Paste modified code..."></textarea>
                    </div>
                    <div class="diff-input-actions">
                        <button class="diff-btn primary" onclick="window.diffViewer.generateDiff()">
                            Generate Diff
                        </button>
                        <button class="diff-btn" onclick="window.diffViewer.closeDiffInput()">
                            Cancel
                        </button>
                    </div>
                </div>
            </div>
        `;

        const dialog = document.createElement('div');
        dialog.id = 'diffInputDialog';
        dialog.className = 'diff-input-overlay';
        dialog.innerHTML = inputHtml;
        document.body.appendChild(dialog);

        setTimeout(() => dialog.classList.add('visible'), 10);
    }

    /**
     * Close diff input dialog
     */
    closeDiffInput() {
        const dialog = document.getElementById('diffInputDialog');
        if (dialog) {
            dialog.classList.remove('visible');
            setTimeout(() => dialog.remove(), 300);
        }
    }

    /**
     * Generate diff from inputs
     */
    generateDiff() {
        const originalInput = document.getElementById('diffOriginalInput');
        const modifiedInput = document.getElementById('diffModifiedInput');

        if (!originalInput || !modifiedInput) return;

        const original = originalInput.value;
        const modified = modifiedInput.value;

        if (!original.trim() || !modified.trim()) {
            this.showToast('Please provide both original and modified code', 3000, 'error');
            return;
        }

        const diff = this.computeDiff(original, modified);
        this.currentDiff = {
            timestamp: Date.now(),
            date: new Date().toLocaleDateString(),
            title: this.extractTitle(original, modified),
            original,
            modified,
            diff,
            stats: this.computeStats(diff)
        };

        this.diffHistory.push(this.currentDiff);
        this.saveDiffHistory();

        this.closeDiffInput();
        this.showDiffPanel();

        this.showToast('Diff generated successfully', 2000, 'success');
        this.emit('diff:created', { diff: this.currentDiff });
    }

    /**
     * Extract title from code
     */
    extractTitle(original, modified) {
        // Try to find a meaningful title
        const patterns = [
            /class\s+(\w+)/,
            /function\s+(\w+)/,
            /const\s+(\w+)/,
            /def\s+(\w+)/
        ];

        for (const pattern of patterns) {
            const match = modified.match(pattern);
            if (match) return `Changes to ${match[1]}`;
        }

        return `Code diff ${new Date().toLocaleTimeString()}`;
    }

    /**
     * Compute diff using Myers algorithm (simplified)
     */
    computeDiff(original, modified) {
        const originalLines = original.split('\n');
        const modifiedLines = modified.split('\n');

        const diff = [];
        const lcs = this.longestCommonSubsequence(originalLines, modifiedLines);

        let i = 0; // original index
        let j = 0; // modified index
        let k = 0; // lcs index

        while (i < originalLines.length || j < modifiedLines.length) {
            if (k < lcs.length && i < originalLines.length && originalLines[i] === lcs[k]) {
                // Common line
                diff.push({
                    type: 'unchanged',
                    oldLine: i + 1,
                    newLine: j + 1,
                    content: originalLines[i]
                });
                i++;
                j++;
                k++;
            } else if (k < lcs.length && j < modifiedLines.length && modifiedLines[j] === lcs[k]) {
                // Line added
                diff.push({
                    type: 'added',
                    oldLine: null,
                    newLine: j + 1,
                    content: modifiedLines[j]
                });
                j++;
            } else if (i < originalLines.length) {
                // Line deleted
                diff.push({
                    type: 'deleted',
                    oldLine: i + 1,
                    newLine: null,
                    content: originalLines[i]
                });
                i++;
            } else {
                // Line added (at end)
                diff.push({
                    type: 'added',
                    oldLine: null,
                    newLine: j + 1,
                    content: modifiedLines[j]
                });
                j++;
            }
        }

        return diff;
    }

    /**
     * Longest Common Subsequence algorithm
     */
    longestCommonSubsequence(arr1, arr2) {
        const m = arr1.length;
        const n = arr2.length;
        const dp = Array(m + 1).fill(0).map(() => Array(n + 1).fill(0));

        // Build LCS table
        for (let i = 1; i <= m; i++) {
            for (let j = 1; j <= n; j++) {
                if (arr1[i - 1] === arr2[j - 1]) {
                    dp[i][j] = dp[i - 1][j - 1] + 1;
                } else {
                    dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
                }
            }
        }

        // Backtrack to find LCS
        const lcs = [];
        let i = m, j = n;
        while (i > 0 && j > 0) {
            if (arr1[i - 1] === arr2[j - 1]) {
                lcs.unshift(arr1[i - 1]);
                i--;
                j--;
            } else if (dp[i - 1][j] > dp[i][j - 1]) {
                i--;
            } else {
                j--;
            }
        }

        return lcs;
    }

    /**
     * Compute diff statistics
     */
    computeStats(diff) {
        const stats = {
            additions: 0,
            deletions: 0,
            changes: 0
        };

        diff.forEach(line => {
            if (line.type === 'added') stats.additions++;
            if (line.type === 'deleted') stats.deletions++;
        });

        stats.changes = stats.additions + stats.deletions;

        return stats;
    }

    /**
     * Render diff
     */
    renderDiff(diffData) {
        const viewMode = this.getSetting('viewMode', 'split');
        const showLineNumbers = this.getSetting('showLineNumbers', true);

        let html = '<div class="diff-content">';

        html += `
            <div class="diff-title">${diffData.title}</div>
            <div class="diff-stats">
                <span class="stat-add">+${diffData.stats.additions}</span>
                <span class="stat-del">-${diffData.stats.deletions}</span>
                <span class="diff-date">${diffData.date}</span>
            </div>
        `;

        if (viewMode === 'split') {
            html += this.renderSplitView(diffData.diff, showLineNumbers);
        } else {
            html += this.renderUnifiedView(diffData.diff, showLineNumbers);
        }

        html += '</div>';
        return html;
    }

    /**
     * Render split (side-by-side) view
     */
    renderSplitView(diff, showLineNumbers) {
        let html = '<div class="diff-split-view">';
        html += '<div class="diff-pane diff-pane-left">';
        html += '<div class="diff-pane-header">Original</div>';

        diff.forEach(line => {
            if (line.type === 'added') return; // Skip added lines in original pane

            const lineClass = line.type === 'deleted' ? 'diff-line-deleted' : 'diff-line-unchanged';
            html += '<div class="diff-line ' + lineClass + '">';
            if (showLineNumbers) {
                html += `<span class="line-number">${line.oldLine || ''}</span>`;
            }
            html += `<span class="line-content">${this.escapeHtml(line.content)}</span>`;
            html += '</div>';
        });

        html += '</div>';
        html += '<div class="diff-pane diff-pane-right">';
        html += '<div class="diff-pane-header">Modified</div>';

        diff.forEach(line => {
            if (line.type === 'deleted') return; // Skip deleted lines in modified pane

            const lineClass = line.type === 'added' ? 'diff-line-added' : 'diff-line-unchanged';
            html += '<div class="diff-line ' + lineClass + '">';
            if (showLineNumbers) {
                html += `<span class="line-number">${line.newLine || ''}</span>`;
            }
            html += `<span class="line-content">${this.escapeHtml(line.content)}</span>`;
            html += '</div>';
        });

        html += '</div>';
        html += '</div>';
        return html;
    }

    /**
     * Render unified view
     */
    renderUnifiedView(diff, showLineNumbers) {
        let html = '<div class="diff-unified-view">';

        diff.forEach(line => {
            const lineClass = `diff-line-${line.type}`;
            const prefix = line.type === 'added' ? '+' : line.type === 'deleted' ? '-' : ' ';

            html += `<div class="diff-line ${lineClass}">`;
            if (showLineNumbers) {
                html += `<span class="line-number">${line.oldLine || ''}</span>`;
                html += `<span class="line-number">${line.newLine || ''}</span>`;
            }
            html += `<span class="line-prefix">${prefix}</span>`;
            html += `<span class="line-content">${this.escapeHtml(line.content)}</span>`;
            html += '</div>';
        });

        html += '</div>';
        return html;
    }

    /**
     * Escape HTML
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * Set view mode
     */
    setViewMode(mode) {
        this.updateSetting('viewMode', mode);
        this.showDiffPanel(); // Refresh
    }

    /**
     * Load diff from history
     */
    loadDiff(index) {
        if (index >= 0 && index < this.diffHistory.length) {
            this.currentDiff = this.diffHistory[index];
            this.showDiffPanel();
        }
    }

    /**
     * Auto-detect code diffs in messages
     */
    autoDetectDiff(data) {
        const content = data.content || data.message || '';

        // Detect unified diff format
        if (content.includes('---') && content.includes('+++') &&
            (content.includes('@@') || content.match(/^[-+]/m))) {
            this.showToast('Code diff detected! Click ⚖️ to view', 4000, 'info');
        }
    }

    /**
     * Load diff history
     */
    loadDiffHistory() {
        try {
            const saved = localStorage.getItem('pkn_diff_history');
            if (saved) {
                this.diffHistory = JSON.parse(saved);
            }
        } catch (error) {
            console.error(`[${this.name}] Error loading history:`, error);
        }
    }

    /**
     * Save diff history
     */
    saveDiffHistory() {
        try {
            // Keep last 10 diffs
            if (this.diffHistory.length > 10) {
                this.diffHistory = this.diffHistory.slice(-10);
            }
            localStorage.setItem('pkn_diff_history', JSON.stringify(this.diffHistory));
        } catch (error) {
            console.error(`[${this.name}] Error saving history:`, error);
        }
    }

    getCSS() {
        return `
            .diff-viewer-panel {
                position: fixed;
                top: 0;
                right: 0;
                width: 90%;
                max-width: 1200px;
                height: 100vh;
                background: rgba(0, 20, 20, 0.98);
                border-left: 1px solid var(--theme-primary);
                z-index: 10003;
                display: flex;
                flex-direction: column;
                opacity: 0;
                transform: translateX(100%);
                transition: all 0.3s ease;
                box-shadow: -4px 0 32px rgba(0, 255, 255, 0.2);
            }
            .diff-viewer-panel.visible {
                opacity: 1;
                transform: translateX(0);
            }
            .diff-panel-header {
                padding: 20px;
                border-bottom: 1px solid rgba(0, 255, 255, 0.2);
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .diff-panel-title {
                color: var(--theme-primary);
                font-size: 18px;
                font-weight: 700;
            }
            .diff-panel-close {
                background: transparent;
                border: none;
                color: var(--theme-primary);
                font-size: 32px;
                cursor: pointer;
                padding: 0;
                width: 32px;
                height: 32px;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .diff-panel-close:hover {
                background: rgba(0, 255, 255, 0.1);
                border-radius: 4px;
            }
            .diff-panel-toolbar {
                padding: 12px 20px;
                border-bottom: 1px solid rgba(0, 255, 255, 0.1);
                display: flex;
                gap: 8px;
            }
            .diff-toolbar-btn {
                padding: 8px 16px;
                background: rgba(0, 255, 255, 0.1);
                border: 1px solid rgba(0, 255, 255, 0.3);
                border-radius: 6px;
                color: var(--theme-primary);
                font-size: 13px;
                cursor: pointer;
                transition: all 0.2s;
            }
            .diff-toolbar-btn:hover, .diff-toolbar-btn.active {
                background: rgba(0, 255, 255, 0.2);
                border-color: var(--theme-primary);
            }
            .diff-panel-body {
                flex: 1;
                overflow-y: auto;
                padding: 16px;
            }
            .diff-empty {
                text-align: center;
                padding: 60px 20px;
            }
            .diff-empty-icon {
                font-size: 64px;
                margin-bottom: 16px;
                opacity: 0.5;
            }
            .diff-empty-text {
                color: #888;
                font-size: 16px;
                margin-bottom: 20px;
            }
            .diff-btn {
                padding: 10px 20px;
                background: rgba(0, 255, 255, 0.1);
                border: 1px solid rgba(0, 255, 255, 0.3);
                border-radius: 6px;
                color: var(--theme-primary);
                font-size: 13px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.2s;
            }
            .diff-btn:hover {
                background: rgba(0, 255, 255, 0.2);
                border-color: var(--theme-primary);
            }
            .diff-btn.primary {
                background: rgba(0, 255, 255, 0.2);
                border-color: var(--theme-primary);
            }
            .diff-content {
                background: rgba(0, 255, 255, 0.03);
                border: 1px solid rgba(0, 255, 255, 0.1);
                border-radius: 8px;
                padding: 16px;
            }
            .diff-title {
                color: var(--theme-primary);
                font-size: 18px;
                font-weight: 700;
                margin-bottom: 8px;
            }
            .diff-stats {
                margin-bottom: 16px;
                display: flex;
                gap: 12px;
                align-items: center;
            }
            .stat-add {
                color: #0f0;
                font-weight: 600;
            }
            .stat-del {
                color: #f00;
                font-weight: 600;
            }
            .diff-date {
                color: #888;
                font-size: 12px;
            }
            .diff-split-view {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 1px;
                background: rgba(0, 255, 255, 0.1);
                border: 1px solid rgba(0, 255, 255, 0.2);
                border-radius: 6px;
                overflow: hidden;
            }
            .diff-pane {
                background: rgba(0, 0, 0, 0.3);
                overflow-x: auto;
            }
            .diff-pane-header {
                background: rgba(0, 255, 255, 0.1);
                padding: 8px 12px;
                color: var(--theme-primary);
                font-size: 12px;
                font-weight: 700;
                border-bottom: 1px solid rgba(0, 255, 255, 0.2);
            }
            .diff-line {
                display: flex;
                font-family: 'Courier New', monospace;
                font-size: 12px;
                line-height: 1.5;
                min-height: 18px;
            }
            .diff-line-unchanged {
                background: transparent;
                color: #ddd;
            }
            .diff-line-added {
                background: rgba(0, 255, 0, 0.1);
                color: #0f0;
            }
            .diff-line-deleted {
                background: rgba(255, 0, 0, 0.1);
                color: #f00;
            }
            .line-number {
                display: inline-block;
                width: 50px;
                padding: 0 8px;
                text-align: right;
                color: #666;
                user-select: none;
                border-right: 1px solid rgba(0, 255, 255, 0.1);
            }
            .line-prefix {
                display: inline-block;
                width: 20px;
                text-align: center;
                user-select: none;
            }
            .line-content {
                flex: 1;
                padding: 0 8px;
                white-space: pre;
            }
            .diff-unified-view {
                background: rgba(0, 0, 0, 0.3);
                border: 1px solid rgba(0, 255, 255, 0.2);
                border-radius: 6px;
                overflow-x: auto;
                padding: 8px 0;
            }
            .diff-history {
                margin-top: 30px;
                padding-top: 20px;
                border-top: 2px solid rgba(0, 255, 255, 0.2);
            }
            .diff-history-header {
                color: var(--theme-primary);
                font-size: 16px;
                font-weight: 700;
                margin-bottom: 12px;
            }
            .diff-history-list {
                display: flex;
                flex-direction: column;
                gap: 8px;
            }
            .diff-history-item {
                background: rgba(0, 0, 0, 0.3);
                border: 1px solid rgba(0, 255, 255, 0.1);
                border-radius: 6px;
                padding: 10px;
                cursor: pointer;
                transition: all 0.2s;
            }
            .diff-history-item:hover {
                background: rgba(0, 255, 255, 0.1);
                border-color: rgba(0, 255, 255, 0.3);
                transform: translateX(4px);
            }
            .diff-history-title {
                color: #fff;
                font-size: 13px;
                font-weight: 600;
                margin-bottom: 4px;
            }
            .diff-history-stats {
                display: flex;
                gap: 12px;
                align-items: center;
                font-size: 11px;
            }
            .diff-history-date {
                color: #888;
            }
            .diff-input-overlay {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.8);
                z-index: 10004;
                display: flex;
                align-items: center;
                justify-content: center;
                opacity: 0;
                transition: opacity 0.3s ease;
            }
            .diff-input-overlay.visible {
                opacity: 1;
            }
            .diff-input-dialog {
                background: rgba(0, 20, 20, 0.98);
                border: 1px solid var(--theme-primary);
                border-radius: 12px;
                width: 90%;
                max-width: 800px;
                max-height: 80vh;
                display: flex;
                flex-direction: column;
                box-shadow: 0 8px 32px rgba(0, 255, 255, 0.3);
            }
            .diff-input-header {
                padding: 16px 20px;
                border-bottom: 1px solid rgba(0, 255, 255, 0.2);
                display: flex;
                justify-content: space-between;
                align-items: center;
                color: var(--theme-primary);
                font-size: 16px;
                font-weight: 700;
            }
            .diff-input-header button {
                background: transparent;
                border: none;
                color: var(--theme-primary);
                font-size: 32px;
                cursor: pointer;
                width: 32px;
                height: 32px;
            }
            .diff-input-body {
                padding: 20px;
                overflow-y: auto;
            }
            .diff-input-section {
                margin-bottom: 20px;
            }
            .diff-input-section label {
                display: block;
                color: var(--theme-primary);
                font-size: 13px;
                font-weight: 600;
                margin-bottom: 8px;
            }
            .diff-input-section textarea {
                width: 100%;
                height: 200px;
                background: rgba(0, 0, 0, 0.3);
                border: 1px solid rgba(0, 255, 255, 0.3);
                border-radius: 6px;
                color: #fff;
                padding: 12px;
                font-size: 13px;
                font-family: 'Courier New', monospace;
                resize: vertical;
            }
            .diff-input-section textarea:focus {
                outline: none;
                border-color: var(--theme-primary);
            }
            .diff-input-actions {
                display: flex;
                gap: 12px;
                margin-top: 20px;
            }
        `;
    }
}

export default DiffViewerPlugin;
