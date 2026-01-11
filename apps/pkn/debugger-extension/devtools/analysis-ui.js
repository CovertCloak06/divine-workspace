/**
 * Code Analysis UI Handler
 * Connects code-analyzer.js to the DevTools panel interface
 * ref:code-analyzer.js, panel.html (analysisTab)
 */

class AnalysisUI {
    constructor() {
        this.analyzer = new window.CodeAnalyzer();  // Create analyzer instance | ref:code-analyzer.js
        this.showExplanations = false;  // Toggle for learning mode explanations
        this.init();  // Initialize event listeners
    }

    /**
     * Initialize event listeners for analysis buttons
     */
    init() {
        // Main analysis button | Runs all checks
        document.getElementById('runAnalysis')?.addEventListener('click', () => this.runFullAnalysis());

        // Individual check buttons | Run specific analysis
        document.getElementById('checkDuplicates')?.addEventListener('click', () => this.checkDuplicates());
        document.getElementById('checkScopes')?.addEventListener('click', () => this.checkScopes());
        document.getElementById('checkSelectors')?.addEventListener('click', () => this.checkSelectors());

        // Learning mode toggle | Show/hide detailed explanations
        document.getElementById('toggleExplanations')?.addEventListener('click', () => this.toggleExplanations());

        // Interactive tutorial launcher | Opens hands-on learning system | ref:interactive-tutorial.js
        document.getElementById('startTutorial')?.addEventListener('click', () => this.launchTutorial());
    }

    /**
     * Launch interactive tutorial system
     */
    launchTutorial() {
        // Create tutorial instance if it doesn't exist | ref:interactive-tutorial.js
        if (!window.tutorialInstance) {
            window.tutorialInstance = new window.InteractiveTutorial();
        }

        // Show lesson selector menu | Allows user to choose which lesson to start
        window.tutorialInstance.showLessonSelector();
    }

    /**
     * Run all analysis checks
     */
    async runFullAnalysis() {
        const url = document.getElementById('projectUrl').value;  // Get project URL from input
        const output = document.getElementById('analysisOutput');

        try {
            output.innerHTML = '<div style="color: #0FF; padding: 20px; text-align: center;">🔄 Loading project files...</div>';

            // Load project files from server | Fetches JS/HTML/CSS files
            const fileCount = await this.analyzer.loadProjectFiles(url);

            output.innerHTML = '<div style="color: #0FF; padding: 20px; text-align: center;">⚙️ Analyzing codebase...</div>';

            // Run all analysis checks | Returns {duplicateFunctions, scopeMismatches, missingSelectors}
            const results = await this.analyzer.analyzeAll();

            // Display results with visual formatting
            this.displayResults(results, fileCount);

        } catch (error) {
            output.innerHTML = `
                <div style="color: #F33; padding: 20px; text-align: center;">
                    <div style="font-size: 36px; margin-bottom: 10px;">❌</div>
                    <div>Error loading project:</div>
                    <div style="font-size: 12px; margin-top: 10px; color: #F99;">${error.message}</div>
                    <div style="font-size: 11px; margin-top: 10px; color: #888;">Make sure PKN server is running at ${url}</div>
                </div>
            `;
        }
    }

    /**
     * Check for duplicate functions only
     */
    async checkDuplicates() {
        await this.runSingleCheck('duplicates', 'Duplicate Functions', () => this.analyzer.findDuplicateFunctions());
    }

    /**
     * Check for scope mismatches only
     */
    async checkScopes() {
        await this.runSingleCheck('scopes', 'Scope Mismatches', () => this.analyzer.findScopeMismatches());
    }

    /**
     * Check for missing selectors only
     */
    async checkSelectors() {
        await this.runSingleCheck('selectors', 'Missing Selectors', () => this.analyzer.findMissingSelectors());
    }

    /**
     * Run a single analysis check
     */
    async runSingleCheck(type, title, checkFunc) {
        const url = document.getElementById('projectUrl').value;
        const output = document.getElementById('analysisOutput');

        try {
            output.innerHTML = '<div style="color: #0FF; padding: 20px; text-align: center;">🔄 Loading files...</div>';

            // Load files if not already loaded
            if (Object.keys(this.analyzer.files).length === 0) {
                await this.analyzer.loadProjectFiles(url);
            }

            output.innerHTML = `<div style="color: #0FF; padding: 20px; text-align: center;">⚙️ Checking ${title.toLowerCase()}...</div>`;

            // Run specific check
            const results = checkFunc();

            // Display single check results
            this.displaySingleCheck(type, title, results);

        } catch (error) {
            output.innerHTML = `<div style="color: #F33; padding: 20px; text-align: center;">❌ Error: ${error.message}</div>`;
        }
    }

    /**
     * Display results from full analysis
     */
    displayResults(results, fileCount) {
        const output = document.getElementById('analysisOutput');

        const dupCount = Object.keys(results.duplicateFunctions).length;
        const scopeCount = Object.keys(results.scopeMismatches).length;
        const selectorCount = Object.keys(results.missingSelectors.ids).length + Object.keys(results.missingSelectors.classes).length;

        let html = `
            <div style="padding: 10px; border-bottom: 1px solid #333; background: #1a1a1a;">
                <div style="color: #0FF; font-weight: bold; font-size: 16px;">📊 Analysis Complete</div>
                <div style="color: #888; font-size: 12px; margin-top: 5px;">Analyzed ${fileCount} files</div>
            </div>
        `;

        // Summary boxes
        html += '<div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; padding: 15px; background: #0a0a0a;">';

        html += this.createSummaryBox('📋', 'Duplicate Functions', dupCount, dupCount > 0 ? '#F80' : '#0F0');
        html += this.createSummaryBox('🔄', 'Scope Mismatches', scopeCount, scopeCount > 0 ? '#F80' : '#0F0');
        html += this.createSummaryBox('🎯', 'Missing Selectors', selectorCount, selectorCount > 0 ? '#F80' : '#0F0');

        html += '</div>';

        // Detailed results for each check
        if (dupCount > 0) {
            html += this.formatDuplicates(results.duplicateFunctions);
        }
        if (scopeCount > 0) {
            html += this.formatScopeMismatches(results.scopeMismatches);
        }
        if (selectorCount > 0) {
            html += this.formatMissingSelectors(results.missingSelectors);
        }

        if (dupCount === 0 && scopeCount === 0 && selectorCount === 0) {
            html += `
                <div style="text-align: center; padding: 40px; color: #0F0;">
                    <div style="font-size: 48px; margin-bottom: 10px;">✅</div>
                    <div style="font-size: 18px; font-weight: bold;">All Checks Passed!</div>
                    <div style="font-size: 13px; margin-top: 10px; color: #888;">Your codebase is clean 🎉</div>
                </div>
            `;
        }

        output.innerHTML = html;
    }

    /**
     * Create summary box for dashboard
     */
    createSummaryBox(icon, title, count, color) {
        return `
            <div style="padding: 15px; background: #111; border: 1px solid ${color}40; border-radius: 6px; text-align: center;">
                <div style="font-size: 32px; margin-bottom: 5px;">${icon}</div>
                <div style="font-size: 24px; color: ${color}; font-weight: bold;">${count}</div>
                <div style="font-size: 11px; color: #888; margin-top: 5px;">${title}</div>
            </div>
        `;
    }

    /**
     * Format duplicate functions for display
     */
    formatDuplicates(duplicates) {
        let html = `
            <div style="margin-top: 20px; padding: 15px; background: #1a0a00; border-left: 4px solid #F80;">
                <div style="color: #F80; font-weight: bold; margin-bottom: 10px;">📋 Duplicate Functions (${Object.keys(duplicates).length})</div>
        `;

        if (this.showExplanations) {
            html += `
                <div style="padding: 10px; background: #0a0a0a; border-radius: 4px; margin-bottom: 15px; font-size: 12px; color: #999;">
                    <strong style="color: #F80;">Why this matters:</strong> When the same function exists in multiple files, updating one version doesn't update the other. This causes bugs when you fix an issue in one place but it still happens in another.
                    <div style="margin-top: 8px;"><strong style="color: #F80;">How to fix:</strong> Keep only ONE version of the function (preferably in a module), then import it where needed.</div>
                </div>
            `;
        }

        for (const [funcName, locations] of Object.entries(duplicates)) {
            html += `<div style="margin-bottom: 15px; padding: 10px; background: #0a0a0a; border-radius: 4px;">`;
            html += `<div style="color: #FFF; font-weight: bold; margin-bottom: 5px;">🔴 ${funcName}()</div>`;

            for (const loc of locations) {
                html += `<div style="color: #888; font-size: 12px; margin-left: 15px;">• ${loc.file}:${loc.line}</div>`;
                html += `<div style="color: #555; font-size: 11px; margin-left: 30px; font-family: monospace;">${loc.code}</div>`;
            }

            html += `</div>`;
        }

        html += '</div>';
        return html;
    }

    /**
     * Format scope mismatches for display
     */
    formatScopeMismatches(mismatches) {
        let html = `
            <div style="margin-top: 20px; padding: 15px; background: #1a1a00; border-left: 4px solid #FF0;">
                <div style="color: #FF0; font-weight: bold; margin-bottom: 10px;">🔄 Scope Mismatches (${Object.keys(mismatches).length})</div>
        `;

        if (this.showExplanations) {
            html += `
                <div style="padding: 10px; background: #0a0a0a; border-radius: 4px; margin-bottom: 15px; font-size: 12px; color: #999;">
                    <strong style="color: #FF0;">Why this matters:</strong> Using a variable as both LOCAL and window.variable creates TWO separate variables. Changes to one won't affect the other, causing state sync bugs.
                    <div style="margin-top: 8px;"><strong style="color: #FF0;">How to fix:</strong> Be consistent - use EITHER <code>let myVar</code> OR <code>window.myVar</code> everywhere, not both.</div>
                </div>
            `;
        }

        for (const [varName, usage] of Object.entries(mismatches)) {
            html += `<div style="margin-bottom: 15px; padding: 10px; background: #0a0a0a; border-radius: 4px;">`;
            html += `<div style="color: #FFF; font-weight: bold; margin-bottom: 5px;">🔴 ${varName}</div>`;

            if (usage.local.length > 0) {
                html += `<div style="color: #888; font-size: 12px; margin-left: 15px; margin-top: 5px;">Used as LOCAL in:</div>`;
                usage.local.forEach(file => {
                    html += `<div style="color: #666; font-size: 11px; margin-left: 30px;">• ${file}</div>`;
                });
            }

            if (usage.window.length > 0) {
                html += `<div style="color: #888; font-size: 12px; margin-left: 15px; margin-top: 5px;">Used as WINDOW.${varName} in:</div>`;
                usage.window.forEach(file => {
                    html += `<div style="color: #666; font-size: 11px; margin-left: 30px;">• ${file}</div>`;
                });
            }

            html += `</div>`;
        }

        html += '</div>';
        return html;
    }

    /**
     * Format missing selectors for display
     */
    formatMissingSelectors(selectors) {
        const idCount = Object.keys(selectors.ids).length;
        const classCount = Object.keys(selectors.classes).length;

        let html = `
            <div style="margin-top: 20px; padding: 15px; background: #001a1a; border-left: 4px solid #0FF;">
                <div style="color: #0FF; font-weight: bold; margin-bottom: 10px;">🎯 Missing Selectors (${idCount + classCount})</div>
        `;

        if (this.showExplanations) {
            html += `
                <div style="padding: 10px; background: #0a0a0a; border-radius: 4px; margin-bottom: 15px; font-size: 12px; color: #999;">
                    <strong style="color: #0FF;">Why this matters:</strong> Trying to access an element that doesn't exist returns NULL, causing "cannot read property of null" errors.
                    <div style="margin-top: 8px;"><strong style="color: #0FF;">How to fix:</strong> Either add the missing element to your HTML/CSS, or remove the dead JavaScript code that references it.</div>
                </div>
            `;
        }

        if (idCount > 0) {
            html += `<div style="margin-bottom: 10px; color: #888; font-weight: bold;">Missing IDs (${idCount}):</div>`;
            for (const [id, locations] of Object.entries(selectors.ids)) {
                html += `<div style="margin-bottom: 10px; padding: 8px; background: #0a0a0a; border-radius: 4px;">`;
                html += `<div style="color: #FFF; font-size: 13px; margin-bottom: 3px;">#${id}</div>`;
                locations.forEach(loc => {
                    html += `<div style="color: #666; font-size: 11px; margin-left: 15px;">• ${loc.file}:${loc.line}</div>`;
                });
                html += `</div>`;
            }
        }

        if (classCount > 0) {
            html += `<div style="margin-bottom: 10px; margin-top: 15px; color: #888; font-weight: bold;">Missing Classes (${classCount}):</div>`;
            for (const [className, locations] of Object.entries(selectors.classes)) {
                html += `<div style="margin-bottom: 10px; padding: 8px; background: #0a0a0a; border-radius: 4px;">`;
                html += `<div style="color: #FFF; font-size: 13px; margin-bottom: 3px;">.${className}</div>`;
                locations.forEach(loc => {
                    html += `<div style="color: #666; font-size: 11px; margin-left: 15px;">• ${loc.file}:${loc.line}</div>`;
                });
                html += `</div>`;
            }
        }

        html += '</div>';
        return html;
    }

    /**
     * Display single check results
     */
    displaySingleCheck(type, title, results) {
        const output = document.getElementById('analysisOutput');
        let html = `<div style="padding: 10px; border-bottom: 1px solid #333; background: #1a1a1a; color: #0FF; font-weight: bold;">${title}</div>`;

        if (type === 'duplicates') {
            const count = Object.keys(results).length;
            if (count > 0) {
                html += this.formatDuplicates(results);
            } else {
                html += '<div style="padding: 40px; text-align: center; color: #0F0;">✅ No duplicate functions found!</div>';
            }
        } else if (type === 'scopes') {
            const count = Object.keys(results).length;
            if (count > 0) {
                html += this.formatScopeMismatches(results);
            } else {
                html += '<div style="padding: 40px; text-align: center; color: #0F0;">✅ No scope mismatches found!</div>';
            }
        } else if (type === 'selectors') {
            const count = Object.keys(results.ids).length + Object.keys(results.classes).length;
            if (count > 0) {
                html += this.formatMissingSelectors(results);
            } else {
                html += '<div style="padding: 40px; text-align: center; color: #0F0;">✅ All selectors found in HTML/CSS!</div>';
            }
        }

        output.innerHTML = html;
    }

    /**
     * Toggle detailed explanations (learning mode)
     */
    toggleExplanations() {
        this.showExplanations = !this.showExplanations;
        const btn = document.getElementById('toggleExplanations');

        if (this.showExplanations) {
            btn.textContent = '📖 Hide Detailed Explanations';
            btn.style.background = '#00FFFF';
            btn.style.color = '#000';
        } else {
            btn.textContent = '📖 Show Detailed Explanations';
            btn.style.background = '#004d4d';
            btn.style.color = '#00FFFF';
        }

        // Re-run last analysis to show/hide explanations
        // (In a real implementation, you'd cache the last results)
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => new AnalysisUI());
} else {
    new AnalysisUI();
}
