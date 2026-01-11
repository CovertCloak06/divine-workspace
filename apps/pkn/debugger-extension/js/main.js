/**
 * Main Module
 * Initializes all debugger app modules and handles global UI
 */

import { GUIEditor } from './gui-editor.js';
import { FileManager } from './file-manager.js';
import { ConsoleLogger } from './console.js';
import { StateManager } from './state.js';

class DebuggerApp {
    constructor() {
        this.guiEditor = null;
        this.fileManager = null;
        this.console = null;
        this.stateManager = null;

        this.init();
    }

    init() {
        console.info('🐞 Debugger App starting...');

        // Initialize all modules
        this.guiEditor = new GUIEditor();
        this.fileManager = new FileManager();
        this.console = new ConsoleLogger();
        this.stateManager = new StateManager();

        // Setup global UI controls
        this.setupPanelToggles();
        this.setupTabs();
        this.setupResetButton();

        console.info('✅ Debugger App ready!');
        console.log('Use the panels to inspect and modify UI elements');
    }

    setupPanelToggles() {
        document.querySelectorAll('.panel-toggle').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const panel = e.target.dataset.panel;
                const panelEl = document.querySelector(`.panel-${panel}`);

                if (panelEl) {
                    const content = panelEl.querySelector('.panel-content');
                    const isHidden = content.style.display === 'none';

                    content.style.display = isHidden ? '' : 'none';
                    btn.textContent = isHidden ? '−' : '+';
                }
            });
        });

        // Toggle all panels button
        document.getElementById('togglePanels').addEventListener('click', () => {
            const allPanels = document.querySelectorAll('.panel-content');
            const firstPanel = allPanels[0];
            const shouldShow = firstPanel.style.display === 'none';

            allPanels.forEach(panel => {
                panel.style.display = shouldShow ? '' : 'none';
            });

            document.querySelectorAll('.panel-toggle').forEach(btn => {
                btn.textContent = shouldShow ? '−' : '+';
            });
        });
    }

    setupTabs() {
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                const tabName = e.target.dataset.tab;

                // Remove active class from all tabs and panels
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));

                // Add active class to clicked tab and corresponding panel
                e.target.classList.add('active');
                document.getElementById(`${tabName}Tab`).classList.add('active');
            });
        });
    }

    setupResetButton() {
        document.getElementById('resetAll').addEventListener('click', () => {
            if (confirm('Reset all changes and clear all data? This will:\n- Reset all style changes\n- Clear console\n- Remove all files\n\nContinue?')) {
                this.guiEditor.resetStyles();
                this.console.clear();
                this.fileManager.files = [];
                this.fileManager.renderFilesList();
                this.stateManager.history = [];
                this.stateManager.render();

                console.info('🔄 Debugger App reset to initial state');
            }
        });
    }
}

// Initialize app when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.debuggerApp = new DebuggerApp();
    });
} else {
    window.debuggerApp = new DebuggerApp();
}

export default DebuggerApp;
