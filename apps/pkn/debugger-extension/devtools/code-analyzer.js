/**
 * Code Analysis Tools - JavaScript versions for browser execution
 * Analyzes PKN codebase for common issues without requiring Python/terminal
 * ref:CLAUDE.md (Code Documentation Standard), analyze_*.py
 */

class CodeAnalyzer {
    constructor() {
        this.projectUrl = null;  // Base URL of project being analyzed | Set when loading files
        this.files = {};  // Map of filename -> file content | Cached for analysis
    }

    /**
     * Load project files from server
     * @param {string} baseUrl - Base URL of project (e.g., http://localhost:8010)
     */
    async loadProjectFiles(baseUrl) {
        this.projectUrl = baseUrl;  // Store base URL for file loading | ref:analyzeProject()
        this.files = {};  // Reset file cache

        try {
            // List of files to analyze | Core PKN files
            const filesToLoad = [
                'app.js',
                'js/main.js',
                'js/chat.js',
                'js/utils.js',
                'js/models.js',
                'js/projects.js',
                'js/settings.js',
                'js/images.js',
                'pkn.html',
                'css/main.css',
            ];

            // Load all files in parallel | Uses fetch API
            const promises = filesToLoad.map(async (file) => {
                try {
                    const response = await fetch(`${baseUrl}/${file}`);
                    if (response.ok) {
                        this.files[file] = await response.text();  // Store file content
                    }
                } catch (e) {
                    console.warn(`Could not load ${file}:`, e);  // Non-critical - continue with other files
                }
            });

            await Promise.all(promises);  // Wait for all files to load
            return Object.keys(this.files).length;  // Return count of loaded files
        } catch (error) {
            console.error('Error loading project files:', error);
            throw error;
        }
    }

    /**
     * Find duplicate function definitions across files
     * ref:analyze_duplicate_functions.py
     */
    findDuplicateFunctions() {
        const functions = {};  // Map function name -> array of {file, line, code}

        // Regex patterns for function definitions | Matches various JS function syntaxes
        const patterns = [
            /^\s*function\s+(\w+)\s*\(/,  // function name()
            /^\s*const\s+(\w+)\s*=\s*(?:async\s*)?\(/,  // const name = async ()
            /^\s*(?:export\s+)?function\s+(\w+)\s*\(/,  // export function name()
            /^\s*(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s*)?\(/,  // export const name = async ()
            /^\s*async\s+function\s+(\w+)\s*\(/,  // async function name()
        ];

        // Common function names that are EXPECTED to appear multiple times | Skip these
        const skipNames = ['init', 'render', 'show', 'hide', 'toggle', 'setup', 'update', 'reset'];

        // Scan each JavaScript file | Extract function definitions
        for (const [filename, content] of Object.entries(this.files)) {
            if (!filename.endsWith('.js')) continue;  // Only analyze JS files

            const lines = content.split('\n');
            lines.forEach((line, lineNum) => {
                for (const pattern of patterns) {
                    const match = line.match(pattern);
                    if (match) {
                        const funcName = match[1];
                        if (!skipNames.includes(funcName)) {  // Skip common names
                            if (!functions[funcName]) functions[funcName] = [];
                            functions[funcName].push({
                                file: filename,
                                line: lineNum + 1,
                                code: line.trim()
                            });
                        }
                        break;  // Only match first pattern per line
                    }
                }
            });
        }

        // Filter to only duplicates | Function appears in 2+ locations
        const duplicates = {};
        for (const [funcName, locations] of Object.entries(functions)) {
            if (locations.length > 1) {
                duplicates[funcName] = locations;
            }
        }

        return duplicates;  // Returns map of function name -> locations array
    }

    /**
     * Find scope mismatches (local vs window.variable)
     * ref:analyze_scope_mismatches.py
     */
    findScopeMismatches() {
        const localUsage = {};  // Map var name -> array of files using local
        const windowUsage = {};  // Map var name -> array of files using window.var

        // Scan each JavaScript file | Look for variable declarations and window usage
        for (const [filename, content] of Object.entries(this.files)) {
            if (!filename.endsWith('.js')) continue;

            // Find window.variableName usage | Matches window.foo, window['foo']
            const windowMatches = content.matchAll(/window\.(\w+)/g);
            for (const match of windowMatches) {
                const varName = match[1];
                if (!windowUsage[varName]) windowUsage[varName] = [];
                if (!windowUsage[varName].includes(filename)) {
                    windowUsage[varName].push(filename);
                }
            }

            // Find local variable declarations | let, const, var
            const lines = content.split('\n');
            const localPatterns = [
                /(?:let|const|var)\s+(\w+)\s*=/,  // Declaration with assignment
                /^\s*(\w+)\s*=(?!=)/,  // Assignment at line start (not ==)
            ];

            lines.forEach(line => {
                for (const pattern of localPatterns) {
                    const matches = line.matchAll(pattern);
                    for (const match of matches) {
                        const varName = match[1];
                        // Only track if this var is also used as window.var somewhere
                        if (windowUsage[varName]) {
                            if (!localUsage[varName]) localUsage[varName] = [];
                            if (!localUsage[varName].includes(filename)) {
                                localUsage[varName].push(filename);
                            }
                        }
                    }
                }
            });
        }

        // Find mismatches | Variable used as both local and window.var
        const mismatches = {};
        const allVars = new Set([...Object.keys(localUsage), ...Object.keys(windowUsage)]);

        for (const varName of allVars) {
            const localFiles = localUsage[varName] || [];
            const windowFiles = windowUsage[varName] || [];

            if (localFiles.length > 0 && windowFiles.length > 0) {
                mismatches[varName] = {
                    local: localFiles,
                    window: windowFiles
                };
            }
        }

        return mismatches;  // Returns map of var name -> {local: files[], window: files[]}
    }

    /**
     * Find missing CSS selectors referenced in JavaScript
     * ref:analyze_missing_selectors.py
     */
    findMissingSelectors() {
        const definedIds = new Set();  // IDs defined in HTML/CSS
        const definedClasses = new Set();  // Classes defined in HTML/CSS

        // Extract IDs and classes from HTML | id="foo", class="bar baz"
        for (const [filename, content] of Object.entries(this.files)) {
            if (filename.endsWith('.html')) {
                // Find all id="..." attributes
                const idMatches = content.matchAll(/id=["']([^"']+)["']/g);
                for (const match of idMatches) {
                    definedIds.add(match[1]);
                }

                // Find all class="..." attributes | May have multiple classes
                const classMatches = content.matchAll(/class=["']([^"']+)["']/g);
                for (const match of classMatches) {
                    const classes = match[1].split(/\s+/);  // Split on whitespace
                    classes.forEach(cls => definedClasses.add(cls));
                }
            }

            if (filename.endsWith('.css')) {
                // Find all .className selectors in CSS
                const classMatches = content.matchAll(/\.([a-zA-Z][\w-]*)/g);
                for (const match of classMatches) {
                    definedClasses.add(match[1]);
                }

                // Find all #idName selectors in CSS
                const idMatches = content.matchAll(/#([a-zA-Z][\w-]*)/g);
                for (const match of idMatches) {
                    definedIds.add(match[1]);
                }
            }
        }

        // Find selectors used in JavaScript | getElementById, querySelector, classList
        const usedIds = {};  // id -> array of {file, line}
        const usedClasses = {};  // class -> array of {file, line}

        for (const [filename, content] of Object.entries(this.files)) {
            if (!filename.endsWith('.js')) continue;

            const lines = content.split('\n');
            lines.forEach((line, lineNum) => {
                // getElementById('foo')
                const getByIdMatches = line.matchAll(/getElementById\(["']([^"']+)["']\)/g);
                for (const match of getByIdMatches) {
                    const idName = match[1];
                    if (!usedIds[idName]) usedIds[idName] = [];
                    usedIds[idName].push({ file: filename, line: lineNum + 1 });
                }

                // querySelector('#foo'), querySelectorAll('#foo')
                const qsIdMatches = line.matchAll(/querySelector(?:All)?\(["']#([^"']+)["']\)/g);
                for (const match of qsIdMatches) {
                    const idName = match[1];
                    if (!usedIds[idName]) usedIds[idName] = [];
                    usedIds[idName].push({ file: filename, line: lineNum + 1 });
                }

                // classList.add('foo'), classList.remove('foo'), etc
                const classListMatches = line.matchAll(/classList\.(?:add|remove|toggle|contains)\(["']([^"']+)["']\)/g);
                for (const match of classListMatches) {
                    const className = match[1];
                    if (!usedClasses[className]) usedClasses[className] = [];
                    usedClasses[className].push({ file: filename, line: lineNum + 1 });
                }

                // querySelector('.foo'), querySelectorAll('.foo')
                const qsClassMatches = line.matchAll(/querySelector(?:All)?\(["']\.([^"']+)["']\)/g);
                for (const match of qsClassMatches) {
                    const className = match[1];
                    if (!usedClasses[className]) usedClasses[className] = [];
                    usedClasses[className].push({ file: filename, line: lineNum + 1 });
                }
            });
        }

        // Find missing IDs and classes | Used in JS but not defined in HTML/CSS
        const missingIds = {};
        for (const [idName, locations] of Object.entries(usedIds)) {
            if (!definedIds.has(idName)) {
                missingIds[idName] = locations;
            }
        }

        const missingClasses = {};
        for (const [className, locations] of Object.entries(usedClasses)) {
            if (!definedClasses.has(className)) {
                missingClasses[className] = locations;
            }
        }

        return { ids: missingIds, classes: missingClasses };  // Returns missing selectors with locations
    }

    /**
     * Run all analysis checks
     * ref:run_all_checks.py
     */
    async analyzeAll() {
        const results = {
            duplicateFunctions: this.findDuplicateFunctions(),  // Map of function -> locations
            scopeMismatches: this.findScopeMismatches(),  // Map of variable -> {local, window}
            missingSelectors: this.findMissingSelectors(),  // {ids, classes} missing
            filesLoaded: Object.keys(this.files).length  // Count of files analyzed
        };

        return results;  // Return all analysis results for UI display
    }
}

// Export for use in panel.js | ref:panel.js
window.CodeAnalyzer = CodeAnalyzer;
