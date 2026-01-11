/**
 * Meeting Summarizer Plugin
 * Extract action items, decisions, and key points from meeting notes
 */

import { PluginBase } from '../../features/plugin-base.js';

export class MeetingSummarizerPlugin extends PluginBase {
    constructor(manifest) {
        super(manifest);
        this.meetingHistory = [];
        this.currentSummary = null;
    }

    async init() {
        await super.init();

        const defaults = {
            autoExtract: false,
            highlightActions: true
        };
        this.loadSettings({ ...defaults, ...this.getSettings() });

        // Load meeting history
        this.loadMeetingHistory();

        this.injectCSS(this.getCSS());
    }

    async enable() {
        await super.enable();

        // Add summarizer button to sidebar
        this.addSummarizerButton();

        // Subscribe to message events for auto-extraction
        if (this.getSetting('autoExtract', false)) {
            this.subscribe('message:sent', (data) => this.autoDetectMeeting(data));
        }

        // Make globally available
        window.meetingSummarizer = this;

        console.log(`[${this.name}] Meeting Summarizer active`);
    }

    async disable() {
        await super.disable();
        this.removeSummarizerButton();
        this.hideSummarizerPanel();
    }

    /**
     * Add summarizer button to sidebar
     */
    addSummarizerButton() {
        const sidebar = document.querySelector('.sidebar');
        if (!sidebar) return;

        const button = document.createElement('div');
        button.className = 'sidebar-section-header clickable';
        button.id = 'meetingSummarizerBtn';
        button.innerHTML = '<span>📋 Meeting Summarizer</span>';
        button.onclick = () => this.showSummarizerPanel();

        // Insert after OSINT section
        const osintSection = document.querySelector('.sidebar-section-header[onclick*="openOSINTTools"]');
        if (osintSection) {
            osintSection.parentNode.insertBefore(button, osintSection.nextSibling);
        }
    }

    /**
     * Remove summarizer button
     */
    removeSummarizerButton() {
        const button = document.getElementById('meetingSummarizerBtn');
        if (button) button.remove();
        this.hideSummarizerPanel();
    }

    /**
     * Show summarizer panel
     */
    showSummarizerPanel() {
        // Remove existing panel
        this.hideSummarizerPanel();

        const panel = document.createElement('div');
        panel.id = 'meetingSummarizerPanel';
        panel.className = 'meeting-summarizer-panel';

        let html = `
            <div class="summarizer-panel-header">
                <div class="summarizer-panel-title">Meeting Summarizer</div>
                <button class="summarizer-panel-close" onclick="window.meetingSummarizer.hideSummarizerPanel()">×</button>
            </div>
            <div class="summarizer-panel-body">
        `;

        // Input area
        html += `
            <div class="summarizer-input-section">
                <textarea id="meetingNotesInput" placeholder="Paste your meeting notes here..."></textarea>
                <div class="summarizer-actions">
                    <button class="summarizer-btn primary" onclick="window.meetingSummarizer.analyzeMeeting()">
                        📊 Analyze Meeting
                    </button>
                    <button class="summarizer-btn" onclick="window.meetingSummarizer.clearInput()">
                        Clear
                    </button>
                </div>
            </div>
        `;

        // Results area
        if (this.currentSummary) {
            html += this.renderSummary(this.currentSummary);
        } else {
            html += `
                <div class="summarizer-empty">
                    Paste meeting notes above and click "Analyze Meeting" to extract:
                    <ul>
                        <li>Action items with owners</li>
                        <li>Key decisions made</li>
                        <li>Attendees and topics</li>
                        <li>Important dates and deadlines</li>
                    </ul>
                </div>
            `;
        }

        // Meeting history
        if (this.meetingHistory.length > 0) {
            html += `
                <div class="summarizer-history">
                    <div class="history-header">Recent Meetings</div>
                    <div class="history-list">
            `;

            this.meetingHistory.slice(-5).reverse().forEach((meeting, idx) => {
                const actualIdx = this.meetingHistory.length - 1 - idx;
                html += `
                    <div class="history-item" onclick="window.meetingSummarizer.loadMeeting(${actualIdx})">
                        <div class="history-date">${meeting.date}</div>
                        <div class="history-preview">${meeting.title || 'Untitled Meeting'}</div>
                        <div class="history-stats">
                            ${meeting.actionItems?.length || 0} actions • ${meeting.decisions?.length || 0} decisions
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
     * Hide summarizer panel
     */
    hideSummarizerPanel() {
        const panel = document.getElementById('meetingSummarizerPanel');
        if (panel) {
            panel.classList.remove('visible');
            setTimeout(() => panel.remove(), 300);
        }
    }

    /**
     * Analyze meeting notes
     */
    async analyzeMeeting() {
        const input = document.getElementById('meetingNotesInput');
        if (!input || !input.value.trim()) {
            this.showToast('Please paste meeting notes first', 3000, 'error');
            return;
        }

        const notes = input.value.trim();
        this.showToast('Analyzing meeting...', 2000, 'info');

        // Extract components
        const summary = {
            timestamp: Date.now(),
            date: new Date().toLocaleDateString(),
            title: this.extractTitle(notes),
            attendees: this.extractAttendees(notes),
            actionItems: this.extractActionItems(notes),
            decisions: this.extractDecisions(notes),
            keyPoints: this.extractKeyPoints(notes),
            dates: this.extractDates(notes),
            rawNotes: notes
        };

        this.currentSummary = summary;

        // Add to history
        this.meetingHistory.push(summary);
        this.saveMeetingHistory();

        // Refresh panel
        this.showSummarizerPanel();

        this.showToast('Meeting analyzed successfully', 2000, 'success');
        this.emit('meeting:analyzed', { summary });
    }

    /**
     * Extract title from notes
     */
    extractTitle(notes) {
        const lines = notes.split('\n');
        const firstLine = lines[0].trim();

        // Check for common title patterns
        const titlePatterns = [
            /^#\s*(.+)/,           // Markdown heading
            /^Meeting:\s*(.+)/i,
            /^Subject:\s*(.+)/i,
            /^Re:\s*(.+)/i
        ];

        for (const pattern of titlePatterns) {
            const match = firstLine.match(pattern);
            if (match) return match[1].trim();
        }

        // Use first line if short enough
        if (firstLine.length < 60) {
            return firstLine;
        }

        return 'Untitled Meeting';
    }

    /**
     * Extract attendees
     */
    extractAttendees(notes) {
        const attendees = [];
        const patterns = [
            /Attendees?:\s*(.+)/i,
            /Participants?:\s*(.+)/i,
            /Present:\s*(.+)/i
        ];

        for (const pattern of patterns) {
            const match = notes.match(pattern);
            if (match) {
                const names = match[1].split(/[,;]/).map(n => n.trim()).filter(n => n.length > 0);
                attendees.push(...names);
                break;
            }
        }

        return [...new Set(attendees)]; // Remove duplicates
    }

    /**
     * Extract action items
     */
    extractActionItems(notes) {
        const items = [];
        const lines = notes.split('\n');

        const patterns = [
            /^[-*]\s*\[[ x]\]\s*(.+)/i,        // Checkbox items
            /^[-*]\s*TODO:\s*(.+)/i,           // TODO items
            /^[-*]\s*Action:\s*(.+)/i,         // Action: prefix
            /^(\w+)\s+will\s+(.+)/i,           // "John will do X"
            /^(\w+)\s+to\s+(.+)/i              // "John to do X"
        ];

        lines.forEach(line => {
            for (const pattern of patterns) {
                const match = line.match(pattern);
                if (match) {
                    const text = match[1] || `${match[1]} ${match[2]}`;
                    const owner = this.extractOwner(text);
                    items.push({
                        text: text.trim(),
                        owner: owner,
                        completed: line.includes('[x]')
                    });
                    break;
                }
            }
        });

        return items;
    }

    /**
     * Extract owner from action item
     */
    extractOwner(text) {
        const ownerPatterns = [
            /\((.+?)\)/,                // (John)
            /\[@(.+?)\]/,               // [@John]
            /^(\w+)\s+(?:will|to)\s+/, // John will/to
        ];

        for (const pattern of ownerPatterns) {
            const match = text.match(pattern);
            if (match) return match[1].trim();
        }

        return null;
    }

    /**
     * Extract decisions
     */
    extractDecisions(notes) {
        const decisions = [];
        const lines = notes.split('\n');

        const patterns = [
            /Decided:\s*(.+)/i,
            /Decision:\s*(.+)/i,
            /Agreed:\s*(.+)/i,
            /Resolved:\s*(.+)/i,
            /We will\s+(.+)/i
        ];

        lines.forEach(line => {
            for (const pattern of patterns) {
                const match = line.match(pattern);
                if (match) {
                    decisions.push(match[1].trim());
                    break;
                }
            }
        });

        return decisions;
    }

    /**
     * Extract key points
     */
    extractKeyPoints(notes) {
        const points = [];
        const lines = notes.split('\n');

        lines.forEach(line => {
            const trimmed = line.trim();
            // Bullet points or numbered lists
            if (/^[-*•]\s+/.test(trimmed) || /^\d+\.\s+/.test(trimmed)) {
                const text = trimmed.replace(/^[-*•]\s+/, '').replace(/^\d+\.\s+/, '');
                if (text.length > 10 && text.length < 200) {
                    points.push(text);
                }
            }
        });

        return points.slice(0, 10); // Limit to top 10
    }

    /**
     * Extract dates and deadlines
     */
    extractDates(notes) {
        const dates = [];
        const datePatterns = [
            /(\d{1,2}\/\d{1,2}\/\d{2,4})/g,    // MM/DD/YYYY
            /(\d{4}-\d{2}-\d{2})/g,             // YYYY-MM-DD
            /(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}/gi,
            /Deadline:\s*(.+?)(?:\n|$)/gi,
            /Due:\s*(.+?)(?:\n|$)/gi
        ];

        datePatterns.forEach(pattern => {
            const matches = notes.matchAll(pattern);
            for (const match of matches) {
                dates.push(match[1].trim());
            }
        });

        return [...new Set(dates)];
    }

    /**
     * Render summary
     */
    renderSummary(summary) {
        let html = '<div class="summarizer-results">';

        // Title
        html += `<div class="summary-title">${summary.title}</div>`;
        html += `<div class="summary-date">${summary.date}</div>`;

        // Attendees
        if (summary.attendees && summary.attendees.length > 0) {
            html += `
                <div class="summary-section">
                    <div class="section-header">👥 Attendees (${summary.attendees.length})</div>
                    <div class="attendee-list">
                        ${summary.attendees.map(a => `<span class="attendee-tag">${a}</span>`).join('')}
                    </div>
                </div>
            `;
        }

        // Action Items
        if (summary.actionItems && summary.actionItems.length > 0) {
            html += `
                <div class="summary-section">
                    <div class="section-header">✅ Action Items (${summary.actionItems.length})</div>
                    <div class="action-list">
            `;

            summary.actionItems.forEach((item, idx) => {
                const completedClass = item.completed ? 'completed' : '';
                html += `
                    <div class="action-item ${completedClass}">
                        <div class="action-text">${item.text}</div>
                        ${item.owner ? `<div class="action-owner">👤 ${item.owner}</div>` : ''}
                    </div>
                `;
            });

            html += `
                    </div>
                </div>
            `;
        }

        // Decisions
        if (summary.decisions && summary.decisions.length > 0) {
            html += `
                <div class="summary-section">
                    <div class="section-header">⚖️ Decisions (${summary.decisions.length})</div>
                    <div class="decision-list">
            `;

            summary.decisions.forEach(decision => {
                html += `<div class="decision-item">• ${decision}</div>`;
            });

            html += `
                    </div>
                </div>
            `;
        }

        // Key Points
        if (summary.keyPoints && summary.keyPoints.length > 0) {
            html += `
                <div class="summary-section">
                    <div class="section-header">💡 Key Points (${summary.keyPoints.length})</div>
                    <div class="keypoint-list">
            `;

            summary.keyPoints.forEach(point => {
                html += `<div class="keypoint-item">• ${point}</div>`;
            });

            html += `
                    </div>
                </div>
            `;
        }

        // Dates
        if (summary.dates && summary.dates.length > 0) {
            html += `
                <div class="summary-section">
                    <div class="section-header">📅 Important Dates</div>
                    <div class="date-list">
                        ${summary.dates.map(d => `<span class="date-tag">${d}</span>`).join('')}
                    </div>
                </div>
            `;
        }

        // Export button
        html += `
            <div class="summary-actions">
                <button class="summarizer-btn" onclick="window.meetingSummarizer.exportSummary()">
                    📤 Export Summary
                </button>
                <button class="summarizer-btn" onclick="window.meetingSummarizer.copyToClipboard()">
                    📋 Copy to Clipboard
                </button>
            </div>
        `;

        html += '</div>';
        return html;
    }

    /**
     * Clear input
     */
    clearInput() {
        const input = document.getElementById('meetingNotesInput');
        if (input) input.value = '';
        this.currentSummary = null;
        this.showSummarizerPanel();
    }

    /**
     * Load meeting from history
     */
    loadMeeting(index) {
        if (index >= 0 && index < this.meetingHistory.length) {
            this.currentSummary = this.meetingHistory[index];
            const input = document.getElementById('meetingNotesInput');
            if (input) input.value = this.currentSummary.rawNotes;
            this.showSummarizerPanel();
        }
    }

    /**
     * Export summary
     */
    exportSummary() {
        if (!this.currentSummary) {
            this.showToast('No summary to export', 2000, 'error');
            return;
        }

        const data = JSON.stringify(this.currentSummary, null, 2);
        const blob = new Blob([data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `meeting-summary-${this.currentSummary.timestamp}.json`;
        a.click();
        URL.revokeObjectURL(url);

        this.showToast('Summary exported', 2000, 'success');
    }

    /**
     * Copy to clipboard
     */
    copyToClipboard() {
        if (!this.currentSummary) {
            this.showToast('No summary to copy', 2000, 'error');
            return;
        }

        let text = `# ${this.currentSummary.title}\n`;
        text += `Date: ${this.currentSummary.date}\n\n`;

        if (this.currentSummary.attendees?.length > 0) {
            text += `## Attendees\n${this.currentSummary.attendees.join(', ')}\n\n`;
        }

        if (this.currentSummary.actionItems?.length > 0) {
            text += `## Action Items\n`;
            this.currentSummary.actionItems.forEach(item => {
                text += `- ${item.text}${item.owner ? ` (${item.owner})` : ''}\n`;
            });
            text += '\n';
        }

        if (this.currentSummary.decisions?.length > 0) {
            text += `## Decisions\n`;
            this.currentSummary.decisions.forEach(d => {
                text += `- ${d}\n`;
            });
            text += '\n';
        }

        navigator.clipboard.writeText(text).then(() => {
            this.showToast('Copied to clipboard', 2000, 'success');
        });
    }

    /**
     * Auto-detect meeting notes
     */
    autoDetectMeeting(data) {
        const text = data.message || data.content || '';

        // Detect if text looks like meeting notes
        const indicators = [
            /meeting/i,
            /attendees?:/i,
            /action items?:/i,
            /agenda:/i,
            /minutes:/i
        ];

        const hasIndicator = indicators.some(pattern => pattern.test(text));
        const hasMultipleLines = text.split('\n').length > 5;

        if (hasIndicator && hasMultipleLines) {
            this.showToast('Meeting notes detected! Click 📋 to summarize', 4000, 'info');
        }
    }

    /**
     * Load meeting history
     */
    loadMeetingHistory() {
        try {
            const saved = localStorage.getItem('pkn_meeting_history');
            if (saved) {
                this.meetingHistory = JSON.parse(saved);
            }
        } catch (error) {
            console.error(`[${this.name}] Error loading history:`, error);
        }
    }

    /**
     * Save meeting history
     */
    saveMeetingHistory() {
        try {
            // Keep last 20 meetings
            if (this.meetingHistory.length > 20) {
                this.meetingHistory = this.meetingHistory.slice(-20);
            }
            localStorage.setItem('pkn_meeting_history', JSON.stringify(this.meetingHistory));
        } catch (error) {
            console.error(`[${this.name}] Error saving history:`, error);
        }
    }

    getCSS() {
        return `
            .meeting-summarizer-panel {
                position: fixed;
                top: 0;
                right: 0;
                width: 600px;
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
            .meeting-summarizer-panel.visible {
                opacity: 1;
                transform: translateX(0);
            }
            .summarizer-panel-header {
                padding: 20px;
                border-bottom: 1px solid rgba(0, 255, 255, 0.2);
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .summarizer-panel-title {
                color: var(--theme-primary);
                font-size: 18px;
                font-weight: 700;
            }
            .summarizer-panel-close {
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
            .summarizer-panel-close:hover {
                background: rgba(0, 255, 255, 0.1);
                border-radius: 4px;
            }
            .summarizer-panel-body {
                flex: 1;
                overflow-y: auto;
                padding: 16px;
            }
            .summarizer-input-section {
                margin-bottom: 20px;
            }
            #meetingNotesInput {
                width: 100%;
                height: 200px;
                background: rgba(0, 0, 0, 0.3);
                border: 1px solid rgba(0, 255, 255, 0.3);
                border-radius: 8px;
                color: #fff;
                padding: 12px;
                font-size: 13px;
                font-family: 'Courier New', monospace;
                resize: vertical;
                margin-bottom: 12px;
            }
            #meetingNotesInput:focus {
                outline: none;
                border-color: var(--theme-primary);
            }
            .summarizer-actions {
                display: flex;
                gap: 8px;
            }
            .summarizer-btn {
                flex: 1;
                padding: 10px 16px;
                background: rgba(0, 255, 255, 0.1);
                border: 1px solid rgba(0, 255, 255, 0.3);
                border-radius: 6px;
                color: var(--theme-primary);
                font-size: 13px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.2s;
            }
            .summarizer-btn:hover {
                background: rgba(0, 255, 255, 0.2);
                border-color: var(--theme-primary);
            }
            .summarizer-btn.primary {
                background: rgba(0, 255, 255, 0.2);
                border-color: var(--theme-primary);
            }
            .summarizer-empty {
                color: #888;
                font-size: 13px;
                padding: 20px;
                text-align: center;
            }
            .summarizer-empty ul {
                text-align: left;
                margin-top: 12px;
                color: #aaa;
            }
            .summarizer-results {
                background: rgba(0, 255, 255, 0.03);
                border: 1px solid rgba(0, 255, 255, 0.1);
                border-radius: 8px;
                padding: 16px;
                margin-bottom: 20px;
            }
            .summary-title {
                color: var(--theme-primary);
                font-size: 18px;
                font-weight: 700;
                margin-bottom: 4px;
            }
            .summary-date {
                color: #888;
                font-size: 12px;
                margin-bottom: 16px;
            }
            .summary-section {
                margin-bottom: 20px;
            }
            .section-header {
                color: var(--theme-primary);
                font-size: 14px;
                font-weight: 700;
                margin-bottom: 8px;
                padding-bottom: 6px;
                border-bottom: 1px solid rgba(0, 255, 255, 0.2);
            }
            .attendee-list {
                display: flex;
                flex-wrap: wrap;
                gap: 6px;
                margin-top: 8px;
            }
            .attendee-tag {
                background: rgba(0, 255, 255, 0.1);
                border: 1px solid rgba(0, 255, 255, 0.3);
                border-radius: 4px;
                padding: 4px 8px;
                color: #fff;
                font-size: 12px;
            }
            .action-list {
                margin-top: 8px;
            }
            .action-item {
                background: rgba(0, 0, 0, 0.3);
                border-left: 3px solid var(--theme-primary);
                border-radius: 4px;
                padding: 10px;
                margin-bottom: 8px;
            }
            .action-item.completed {
                opacity: 0.5;
                border-left-color: #0f0;
            }
            .action-text {
                color: #fff;
                font-size: 13px;
                margin-bottom: 4px;
            }
            .action-owner {
                color: #888;
                font-size: 11px;
            }
            .decision-list, .keypoint-list {
                margin-top: 8px;
            }
            .decision-item, .keypoint-item {
                color: #ddd;
                font-size: 13px;
                margin-bottom: 6px;
                padding-left: 8px;
            }
            .date-list {
                display: flex;
                flex-wrap: wrap;
                gap: 6px;
                margin-top: 8px;
            }
            .date-tag {
                background: rgba(255, 165, 0, 0.1);
                border: 1px solid rgba(255, 165, 0, 0.3);
                border-radius: 4px;
                padding: 4px 8px;
                color: #ffa500;
                font-size: 12px;
            }
            .summary-actions {
                display: flex;
                gap: 8px;
                margin-top: 16px;
                padding-top: 16px;
                border-top: 1px solid rgba(0, 255, 255, 0.1);
            }
            .summarizer-history {
                margin-top: 30px;
                padding-top: 20px;
                border-top: 2px solid rgba(0, 255, 255, 0.2);
            }
            .history-header {
                color: var(--theme-primary);
                font-size: 16px;
                font-weight: 700;
                margin-bottom: 12px;
            }
            .history-list {
                display: flex;
                flex-direction: column;
                gap: 8px;
            }
            .history-item {
                background: rgba(0, 0, 0, 0.3);
                border: 1px solid rgba(0, 255, 255, 0.1);
                border-radius: 6px;
                padding: 10px;
                cursor: pointer;
                transition: all 0.2s;
            }
            .history-item:hover {
                background: rgba(0, 255, 255, 0.1);
                border-color: rgba(0, 255, 255, 0.3);
                transform: translateX(4px);
            }
            .history-date {
                color: #888;
                font-size: 11px;
                margin-bottom: 4px;
            }
            .history-preview {
                color: #fff;
                font-size: 13px;
                font-weight: 600;
                margin-bottom: 4px;
            }
            .history-stats {
                color: #aaa;
                font-size: 11px;
            }
        `;
    }
}

export default MeetingSummarizerPlugin;
