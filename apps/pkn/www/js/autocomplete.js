/**
 * Code Autocomplete Widget for PKN
 * Provides intelligent code suggestions while typing
 */

class AutocompleteWidget {
    constructor(inputElement, options = {}) {
        this.input = inputElement;
        this.options = {
            minChars: 2,                    // Minimum characters before showing suggestions
            maxSuggestions: 10,              // Maximum suggestions to show
            debounceMs: 300,                // Delay before fetching suggestions
            apiUrl: '/api/autocomplete',    // Autocomplete API endpoint
            enabled: true,                  // Enable/disable autocomplete
            ...options
        };

        this.suggestionBox = null;
        this.suggestions = [];
        this.selectedIndex = -1;
        this.debounceTimer = null;
        this.currentPrefix = '';

        this.init();
    }

    init() {
        // Create suggestion box
        this.createSuggestionBox();

        // Attach event listeners
        this.input.addEventListener('input', (e) => this.onInput(e));
        this.input.addEventListener('keydown', (e) => this.onKeyDown(e));
        this.input.addEventListener('blur', () => this.hideSuggestions());

        // Prevent blur when clicking on suggestions
        this.suggestionBox.addEventListener('mousedown', (e) => e.preventDefault());
    }

    createSuggestionBox() {
        this.suggestionBox = document.createElement('div');
        this.suggestionBox.className = 'autocomplete-suggestions';
        const themeColor = getComputedStyle(document.documentElement).getPropertyValue('--theme-primary').trim() || '#00ffff';
        const themeGlow = getComputedStyle(document.documentElement).getPropertyValue('--theme-primary-glow').trim() || 'rgba(0, 255, 255, 0.2)';
        this.suggestionBox.style.cssText = `
            position: absolute;
            display: none;
            background: #1e1e1e;
            border: 1px solid ${themeColor};
            border-radius: 4px;
            max-height: 300px;
            overflow-y: auto;
            z-index: 10000;
            box-shadow: 0 4px 12px ${themeGlow};
            font-family: 'Courier New', monospace;
            font-size: 13px;
        `;

        // Position relative to input
        document.body.appendChild(this.suggestionBox);
    }

    onInput(e) {
        if (!this.options.enabled) return;

        clearTimeout(this.debounceTimer);

        const cursorPos = this.input.selectionStart;
        const textBefore = this.input.value.substring(0, cursorPos);

        // Extract the word being typed (prefix)
        const match = textBefore.match(/(\w+)$/);
        const prefix = match ? match[1] : '';

        if (prefix.length >= this.options.minChars) {
            this.currentPrefix = prefix;
            this.debounceTimer = setTimeout(() => {
                this.fetchSuggestions(prefix);
            }, this.options.debounceMs);
        } else {
            this.hideSuggestions();
        }
    }

    onKeyDown(e) {
        if (!this.suggestionBox || this.suggestionBox.style.display === 'none') {
            return;
        }

        switch (e.key) {
            case 'ArrowDown':
                e.preventDefault();
                this.selectNext();
                break;
            case 'ArrowUp':
                e.preventDefault();
                this.selectPrevious();
                break;
            case 'Enter':
            case 'Tab':
                if (this.selectedIndex >= 0) {
                    e.preventDefault();
                    this.applySuggestion(this.suggestions[this.selectedIndex]);
                }
                break;
            case 'Escape':
                e.preventDefault();
                this.hideSuggestions();
                break;
        }
    }

    async fetchSuggestions(prefix) {
        try {
            const response = await fetch(this.options.apiUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    prefix: prefix,
                    file_path: '', // Could be set based on current file context
                    context_line: this.input.value
                })
            });

            const data = await response.json();

            if (data.status === 'success' && data.completions && data.completions.length > 0) {
                this.suggestions = data.completions.slice(0, this.options.maxSuggestions);
                this.showSuggestions();
            } else {
                this.hideSuggestions();
            }
        } catch (error) {
            console.error('Autocomplete error:', error);
            this.hideSuggestions();
        }
    }

    showSuggestions() {
        if (this.suggestions.length === 0) {
            this.hideSuggestions();
            return;
        }

        // Position the suggestion box
        const rect = this.input.getBoundingClientRect();
        this.suggestionBox.style.left = rect.left + 'px';
        this.suggestionBox.style.top = (rect.bottom + 2) + 'px';
        this.suggestionBox.style.minWidth = rect.width + 'px';

        // Render suggestions
        this.suggestionBox.innerHTML = '';
        this.suggestions.forEach((suggestion, index) => {
            const item = document.createElement('div');
            item.className = 'autocomplete-item';
            item.style.cssText = `
                padding: 6px 12px;
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: space-between;
                transition: background 0.1s;
            `;

            // Create suggestion content
            const textSpan = document.createElement('span');
            textSpan.textContent = suggestion.text;
            const themeColor = getComputedStyle(document.documentElement).getPropertyValue('--theme-primary').trim() || '#00ffff';
            textSpan.style.color = themeColor;
            textSpan.style.fontWeight = 'bold';

            const typeSpan = document.createElement('span');
            typeSpan.textContent = this.getTypeIcon(suggestion.type);
            typeSpan.style.cssText = 'opacity: 0.6; font-size: 11px; margin-left: 8px;';

            item.appendChild(textSpan);
            item.appendChild(typeSpan);

            // Add detail if available
            if (suggestion.detail) {
                const detailDiv = document.createElement('div');
                detailDiv.textContent = suggestion.detail;
                detailDiv.style.cssText = 'font-size: 11px; opacity: 0.5; margin-top: 2px;';
                item.appendChild(detailDiv);
            }

            // Hover and click handlers
            item.addEventListener('mouseenter', () => {
                this.selectedIndex = index;
                this.updateSelection();
            });

            item.addEventListener('click', () => {
                this.applySuggestion(suggestion);
            });

            this.suggestionBox.appendChild(item);
        });

        this.suggestionBox.style.display = 'block';
        this.selectedIndex = 0;
        this.updateSelection();
    }

    hideSuggestions() {
        if (this.suggestionBox) {
            this.suggestionBox.style.display = 'none';
            this.suggestions = [];
            this.selectedIndex = -1;
        }
    }

    selectNext() {
        this.selectedIndex = (this.selectedIndex + 1) % this.suggestions.length;
        this.updateSelection();
    }

    selectPrevious() {
        this.selectedIndex = this.selectedIndex <= 0
            ? this.suggestions.length - 1
            : this.selectedIndex - 1;
        this.updateSelection();
    }

    updateSelection() {
        const themeColor = getComputedStyle(document.documentElement).getPropertyValue('--theme-primary').trim() || '#00ffff';
        const themeGlow = getComputedStyle(document.documentElement).getPropertyValue('--theme-primary-glow').trim() || 'rgba(0, 255, 255, 0.2)';
        const items = this.suggestionBox.querySelectorAll('.autocomplete-item');
        items.forEach((item, index) => {
            if (index === this.selectedIndex) {
                item.style.background = themeGlow;
                item.style.borderLeft = `3px solid ${themeColor}`;
                item.scrollIntoView({ block: 'nearest' });
            } else {
                item.style.background = 'transparent';
                item.style.borderLeft = 'none';
            }
        });
    }

    applySuggestion(suggestion) {
        const cursorPos = this.input.selectionStart;
        const textBefore = this.input.value.substring(0, cursorPos);
        const textAfter = this.input.value.substring(cursorPos);

        // Replace the current prefix with the suggestion
        const beforePrefix = textBefore.substring(0, textBefore.length - this.currentPrefix.length);
        this.input.value = beforePrefix + suggestion.text + textAfter;

        // Move cursor to end of inserted text
        const newCursorPos = beforePrefix.length + suggestion.text.length;
        this.input.selectionStart = newCursorPos;
        this.input.selectionEnd = newCursorPos;

        this.hideSuggestions();
        this.input.focus();

        // Trigger input event for any listeners
        this.input.dispatchEvent(new Event('input', { bubbles: true }));
    }

    getTypeIcon(type) {
        const icons = {
            'function': '𝑓()',
            'class': 'ℂ',
            'variable': '𝑥',
            'constant': 'K',
            'keyword': '⚡',
            'id': '#',
            'method': 'm()',
        };
        return icons[type] || '•';
    }

    enable() {
        this.options.enabled = true;
    }

    disable() {
        this.options.enabled = false;
        this.hideSuggestions();
    }

    destroy() {
        if (this.suggestionBox && this.suggestionBox.parentNode) {
            this.suggestionBox.parentNode.removeChild(this.suggestionBox);
        }
        clearTimeout(this.debounceTimer);
    }
}

// Simple autocomplete initialization for PKN
function initAutocomplete() {
    const messageInput = document.getElementById('messageInput');
    if (messageInput) {
        window.pknAutocomplete = new AutocompleteWidget(messageInput, {
            minChars: 3,
            maxSuggestions: 8,
            debounceMs: 400,
        });
        console.log('[Autocomplete] Initialized successfully');
    }
}

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAutocomplete);
} else {
    initAutocomplete();
}

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { AutocompleteWidget, initAutocomplete };
}
