/**
 * GUI Editor Module - Visual Style Editor
 * Core functionality for inspecting and modifying element styles in real-time
 */

export class GUIEditor {
    constructor() {
        this.targetFrame = document.getElementById('targetFrame');
        this.selectedElement = null;
        this.originalStyles = new Map();
        this.currentTheme = {};
        this.pickMode = false;

        this.init();
    }

    init() {
        this.setupEventListeners();
        this.populateElementSelector();

        // Wait for iframe to load
        this.targetFrame.addEventListener('load', () => {
            this.populateElementSelector();
            this.setupIframeListeners();
        });
    }

    setupEventListeners() {
        // Element Selector
        document.getElementById('elementSelector').addEventListener('change', (e) => {
            this.selectElementBySelector(e.target.value);
        });

        // Pick Element Mode
        document.getElementById('pickElement').addEventListener('click', () => {
            this.togglePickMode();
        });

        // Quick Actions
        document.getElementById('hideElement').addEventListener('click', () => {
            if (this.selectedElement) {
                this.selectedElement.style.display = 'none';
            }
        });

        document.getElementById('showElement').addEventListener('click', () => {
            if (this.selectedElement) {
                this.selectedElement.style.display = '';
            }
        });

        document.getElementById('highlightElement').addEventListener('click', () => {
            this.highlightElement();
        });

        // Layout Controls
        this.setupRangeControl('width', (value) => {
            if (this.selectedElement) {
                this.selectedElement.style.width = value ? `${value}px` : '';
                document.getElementById('widthValue').value = value || 'auto';
            }
        });

        this.setupRangeControl('height', (value) => {
            if (this.selectedElement) {
                this.selectedElement.style.height = value ? `${value}px` : '';
                document.getElementById('heightValue').value = value || 'auto';
            }
        });

        this.setupRangeControl('padding', (value) => {
            if (this.selectedElement) {
                this.selectedElement.style.padding = `${value}px`;
                document.getElementById('paddingValue').textContent = `${value}px`;
            }
        });

        this.setupRangeControl('margin', (value) => {
            if (this.selectedElement) {
                this.selectedElement.style.margin = `${value}px`;
                document.getElementById('marginValue').textContent = `${value}px`;
            }
        });

        // Appearance Controls
        document.getElementById('bgColor').addEventListener('input', (e) => {
            if (this.selectedElement) {
                this.selectedElement.style.backgroundColor = e.target.value;
            }
        });

        document.getElementById('textColor').addEventListener('input', (e) => {
            if (this.selectedElement) {
                this.selectedElement.style.color = e.target.value;
            }
        });

        this.setupRangeControl('borderRadius', (value) => {
            if (this.selectedElement) {
                this.selectedElement.style.borderRadius = `${value}px`;
                document.getElementById('borderRadiusValue').textContent = `${value}px`;
            }
        });

        this.setupRangeControl('opacity', (value) => {
            if (this.selectedElement) {
                this.selectedElement.style.opacity = value / 100;
                document.getElementById('opacityValue').textContent = `${value}%`;
            }
        });

        document.getElementById('zIndex').addEventListener('input', (e) => {
            if (this.selectedElement) {
                this.selectedElement.style.zIndex = e.target.value;
            }
        });

        // Typography Controls
        this.setupRangeControl('fontSize', (value) => {
            if (this.selectedElement) {
                this.selectedElement.style.fontSize = `${value}px`;
                document.getElementById('fontSizeValue').textContent = `${value}px`;
            }
        });

        document.getElementById('fontFamily').addEventListener('change', (e) => {
            if (this.selectedElement) {
                this.selectedElement.style.fontFamily = e.target.value;
            }
        });

        document.getElementById('fontWeight').addEventListener('change', (e) => {
            if (this.selectedElement) {
                this.selectedElement.style.fontWeight = e.target.value;
            }
        });

        // Theme Management
        document.getElementById('saveTheme').addEventListener('click', () => this.saveTheme());
        document.getElementById('loadTheme').addEventListener('click', () => this.loadTheme());
        document.getElementById('exportCSS').addEventListener('click', () => this.exportCSS());
        document.getElementById('resetStyles').addEventListener('click', () => this.resetStyles());
    }

    setupRangeControl(id, callback) {
        const input = document.getElementById(id);
        if (input) {
            input.addEventListener('input', (e) => callback(e.target.value));
        }
    }

    populateElementSelector() {
        try {
            const iframeDoc = this.targetFrame.contentDocument || this.targetFrame.contentWindow.document;
            const elements = iframeDoc.querySelectorAll('*');
            const selector = document.getElementById('elementSelector');

            selector.innerHTML = '<option value="">Select element...</option>';

            elements.forEach((el, index) => {
                const tagName = el.tagName.toLowerCase();
                const className = el.className ? `.${el.className.split(' ').join('.')}` : '';
                const id = el.id ? `#${el.id}` : '';
                const label = `${tagName}${id}${className}`;

                const option = document.createElement('option');
                option.value = index;
                option.textContent = label.length > 50 ? label.substring(0, 50) + '...' : label;
                option.dataset.element = index;
                selector.appendChild(option);
            });
        } catch (e) {
            console.warn('Cannot access iframe content (cross-origin restriction):', e);
        }
    }

    selectElementBySelector(index) {
        if (!index) return;

        try {
            const iframeDoc = this.targetFrame.contentDocument || this.targetFrame.contentWindow.document;
            const elements = iframeDoc.querySelectorAll('*');
            this.selectElement(elements[index]);
        } catch (e) {
            console.error('Error selecting element:', e);
        }
    }

    selectElement(element) {
        if (!element) return;

        // Remove previous highlight
        if (this.selectedElement) {
            this.selectedElement.style.outline = '';
        }

        this.selectedElement = element;

        // Store original styles if not already stored
        if (!this.originalStyles.has(element)) {
            this.originalStyles.set(element, element.style.cssText);
        }

        // Highlight selected element
        element.style.outline = '2px solid #00FFFF';

        // Update info panel
        this.updateElementInfo(element);

        // Update controls with current values
        this.updateControlsFromElement(element);
    }

    updateElementInfo(element) {
        const info = document.getElementById('elementInfo');
        const tagName = element.tagName.toLowerCase();
        const className = element.className || 'none';
        const id = element.id || 'none';

        const computed = window.getComputedStyle(element);

        info.innerHTML = `
            <div style="margin-bottom: 8px;"><strong>Tag:</strong> ${tagName}</div>
            <div style="margin-bottom: 8px;"><strong>ID:</strong> ${id}</div>
            <div style="margin-bottom: 8px;"><strong>Class:</strong> ${className}</div>
            <div style="margin-bottom: 8px;"><strong>Display:</strong> ${computed.display}</div>
            <div><strong>Position:</strong> ${computed.position}</div>
        `;
    }

    updateControlsFromElement(element) {
        const computed = window.getComputedStyle(element);

        // Width/Height
        const width = parseInt(computed.width);
        const height = parseInt(computed.height);
        if (!isNaN(width)) {
            document.getElementById('width').value = width;
            document.getElementById('widthValue').value = width;
        }
        if (!isNaN(height)) {
            document.getElementById('height').value = height;
            document.getElementById('heightValue').value = height;
        }

        // Colors
        document.getElementById('bgColor').value = this.rgbToHex(computed.backgroundColor) || '#111111';
        document.getElementById('textColor').value = this.rgbToHex(computed.color) || '#00FFFF';

        // Border Radius
        const borderRadius = parseInt(computed.borderRadius);
        if (!isNaN(borderRadius)) {
            document.getElementById('borderRadius').value = borderRadius;
            document.getElementById('borderRadiusValue').textContent = `${borderRadius}px`;
        }

        // Opacity
        const opacity = Math.round(parseFloat(computed.opacity) * 100);
        document.getElementById('opacity').value = opacity;
        document.getElementById('opacityValue').textContent = `${opacity}%`;

        // Z-Index
        document.getElementById('zIndex').value = computed.zIndex === 'auto' ? 0 : computed.zIndex;

        // Font Size
        const fontSize = parseInt(computed.fontSize);
        if (!isNaN(fontSize)) {
            document.getElementById('fontSize').value = fontSize;
            document.getElementById('fontSizeValue').textContent = `${fontSize}px`;
        }
    }

    rgbToHex(rgb) {
        if (!rgb || rgb === 'transparent') return null;

        const match = rgb.match(/^rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*[\d.]+)?\)$/);
        if (!match) return null;

        const r = parseInt(match[1]).toString(16).padStart(2, '0');
        const g = parseInt(match[2]).toString(16).padStart(2, '0');
        const b = parseInt(match[3]).toString(16).padStart(2, '0');

        return `#${r}${g}${b}`;
    }

    togglePickMode() {
        this.pickMode = !this.pickMode;
        const btn = document.getElementById('pickElement');

        if (this.pickMode) {
            btn.textContent = '🎯 Picking... (Click element)';
            btn.style.background = '#00FFFF';
            btn.style.color = '#0d0d0d';
        } else {
            btn.textContent = '👆 Pick Element (Click Mode)';
            btn.style.background = '';
            btn.style.color = '';
        }
    }

    setupIframeListeners() {
        try {
            const iframeDoc = this.targetFrame.contentDocument || this.targetFrame.contentWindow.document;

            iframeDoc.addEventListener('click', (e) => {
                if (this.pickMode) {
                    e.preventDefault();
                    e.stopPropagation();
                    this.selectElement(e.target);
                    this.togglePickMode();
                }
            }, true);
        } catch (e) {
            console.warn('Cannot add iframe listeners (cross-origin):', e);
        }
    }

    highlightElement() {
        if (!this.selectedElement) return;

        const originalOutline = this.selectedElement.style.outline;
        const originalBackground = this.selectedElement.style.backgroundColor;

        this.selectedElement.style.outline = '4px solid #00FFFF';
        this.selectedElement.style.backgroundColor = 'rgba(0, 255, 255, 0.2)';

        setTimeout(() => {
            this.selectedElement.style.outline = originalOutline;
            this.selectedElement.style.backgroundColor = originalBackground;
        }, 1000);
    }

    saveTheme() {
        const theme = {
            timestamp: Date.now(),
            styles: {}
        };

        // Collect all modified styles
        this.originalStyles.forEach((originalStyle, element) => {
            const selector = this.getElementSelector(element);
            theme.styles[selector] = element.style.cssText;
        });

        // Save to localStorage
        localStorage.setItem('debugger_theme', JSON.stringify(theme));

        // Download as JSON
        const blob = new Blob([JSON.stringify(theme, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `theme_${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);

        console.log('Theme saved successfully!');
    }

    loadTheme() {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = '.json';

        input.onchange = (e) => {
            const file = e.target.files[0];
            const reader = new FileReader();

            reader.onload = (event) => {
                try {
                    const theme = JSON.parse(event.target.result);
                    this.applyTheme(theme);
                    console.log('Theme loaded successfully!');
                } catch (error) {
                    console.error('Error loading theme:', error);
                }
            };

            reader.readAsText(file);
        };

        input.click();
    }

    applyTheme(theme) {
        try {
            const iframeDoc = this.targetFrame.contentDocument || this.targetFrame.contentWindow.document;

            Object.entries(theme.styles).forEach(([selector, styles]) => {
                const element = iframeDoc.querySelector(selector);
                if (element) {
                    element.style.cssText = styles;
                }
            });
        } catch (e) {
            console.error('Error applying theme:', e);
        }
    }

    exportCSS() {
        let css = '/* Generated CSS from Debugger App */\n\n';

        this.originalStyles.forEach((originalStyle, element) => {
            const selector = this.getElementSelector(element);
            const styles = element.style.cssText;

            if (styles) {
                css += `${selector} {\n`;
                styles.split(';').forEach(rule => {
                    const trimmed = rule.trim();
                    if (trimmed) {
                        css += `    ${trimmed};\n`;
                    }
                });
                css += '}\n\n';
            }
        });

        // Download CSS
        const blob = new Blob([css], { type: 'text/css' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `styles_${Date.now()}.css`;
        a.click();
        URL.revokeObjectURL(url);

        console.log('CSS exported successfully!');
    }

    resetStyles() {
        if (!confirm('Reset all style changes? This cannot be undone.')) return;

        this.originalStyles.forEach((originalStyle, element) => {
            element.style.cssText = originalStyle;
        });

        this.originalStyles.clear();
        this.selectedElement = null;

        document.getElementById('elementInfo').innerHTML = '<span class="text-muted">No element selected</span>';
        document.getElementById('elementSelector').value = '';

        console.log('Styles reset to original state');
    }

    getElementSelector(element) {
        if (element.id) return `#${element.id}`;
        if (element.className) return `.${element.className.split(' ').join('.')}`;
        return element.tagName.toLowerCase();
    }
}

// Initialize when module loads
window.GUIEditor = GUIEditor;
