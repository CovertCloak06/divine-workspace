// Dev Labs Universal Debugger v2.0
// Glass-styled, draggable, resizable, collapsible debugger
// Usage: Add as bookmarklet or load script on any page

(function() {
    'use strict';

    // Prevent multiple instances
    if (window.DevLabsDebugger) {
        window.DevLabsDebugger.toggle();
        return;
    }

    window.DevLabsDebugger = {
        isOpen: false,
        isCollapsed: false,
        selectedElement: null,
        isPickingElement: false,
        theme: 'cyan',
        changes: {},

        // Dragging state
        isDragging: false,
        dragStartX: 0,
        dragStartY: 0,
        panelStartX: 0,
        panelStartY: 0,

        // Resizing state
        isResizing: false,
        resizeStartX: 0,
        resizeStartY: 0,
        startWidth: 0,
        startHeight: 0,

        init() {
            console.log('🔧 Dev Labs Debugger v2.0 loading...');
            this.injectStyles();
            this.createPanel();
            this.show();
            console.log('✅ Dev Labs Debugger ready!');
        },

        injectStyles() {
            if (document.getElementById('devlabs-debugger-styles')) return;

            const style = document.createElement('style');
            style.id = 'devlabs-debugger-styles';
            style.textContent = `
                /* Dev Labs Debugger v2.0 - Glass Style */
                #devlabs-panel {
                    position: fixed !important;
                    top: 100px !important;
                    right: 20px !important;
                    width: 380px !important;
                    max-height: 600px !important;
                    background: rgba(0, 0, 0, 0.9) !important;
                    backdrop-filter: blur(10px) !important;
                    border: 1px solid #0ff !important;
                    border-radius: 8px !important;
                    box-shadow: 0 0 30px rgba(0, 255, 255, 0.3) !important;
                    z-index: 999999 !important;
                    display: none !important;
                    flex-direction: column !important;
                    font-family: 'Courier New', monospace !important;
                    resize: none !important;
                    overflow: hidden !important;
                }
                #devlabs-panel.show {
                    display: flex !important;
                }
                #devlabs-panel.collapsed {
                    max-height: 50px !important;
                    overflow: hidden !important;
                }
                .devlabs-header {
                    padding: 12px 15px !important;
                    background: rgba(0, 255, 255, 0.1) !important;
                    color: #0ff !important;
                    display: flex !important;
                    justify-content: space-between !important;
                    align-items: center !important;
                    border-bottom: 1px solid rgba(0, 255, 255, 0.3) !important;
                    cursor: move !important;
                    user-select: none !important;
                    flex-shrink: 0 !important;
                }
                .devlabs-title {
                    font-weight: 600 !important;
                    font-size: 14px !important;
                    color: #0ff !important;
                }
                .devlabs-controls {
                    display: flex !important;
                    gap: 10px !important;
                }
                .devlabs-btn {
                    background: transparent !important;
                    border: none !important;
                    color: #0ff !important;
                    cursor: pointer !important;
                    font-size: 16px !important;
                    transition: all 0.2s !important;
                    padding: 0 !important;
                    line-height: 1 !important;
                }
                .devlabs-btn:hover {
                    transform: scale(1.2) !important;
                    color: #fff !important;
                }
                .devlabs-body {
                    padding: 15px !important;
                    overflow-y: auto !important;
                    flex: 1 !important;
                    color: #E0E0E0 !important;
                }
                .devlabs-body::-webkit-scrollbar {
                    width: 8px !important;
                }
                .devlabs-body::-webkit-scrollbar-track {
                    background: rgba(0, 255, 255, 0.1) !important;
                    border-radius: 4px !important;
                }
                .devlabs-body::-webkit-scrollbar-thumb {
                    background: rgba(0, 255, 255, 0.3) !important;
                    border-radius: 4px !important;
                }
                .devlabs-body::-webkit-scrollbar-thumb:hover {
                    background: rgba(0, 255, 255, 0.5) !important;
                }
                .devlabs-section {
                    margin-bottom: 15px !important;
                }
                .devlabs-label {
                    display: block !important;
                    color: #0ff !important;
                    font-size: 11px !important;
                    margin-bottom: 6px !important;
                    font-weight: 600 !important;
                }
                .devlabs-input, .devlabs-select {
                    width: 100% !important;
                    padding: 8px !important;
                    background: rgba(0, 255, 255, 0.05) !important;
                    border: 1px solid rgba(0, 255, 255, 0.3) !important;
                    border-radius: 4px !important;
                    color: #fff !important;
                    font-family: 'Courier New', monospace !important;
                    font-size: 12px !important;
                    box-sizing: border-box !important;
                }
                .devlabs-input:focus, .devlabs-select:focus {
                    outline: none !important;
                    border-color: #0ff !important;
                    box-shadow: 0 0 5px rgba(0, 255, 255, 0.3) !important;
                }
                .devlabs-button {
                    width: 100% !important;
                    padding: 10px !important;
                    background: rgba(0, 255, 255, 0.1) !important;
                    border: 1px solid #0ff !important;
                    border-radius: 6px !important;
                    color: #0ff !important;
                    cursor: pointer !important;
                    font-family: 'Courier New', monospace !important;
                    font-weight: 600 !important;
                    transition: all 0.3s !important;
                    font-size: 12px !important;
                }
                .devlabs-button:hover {
                    background: rgba(0, 255, 255, 0.2) !important;
                    box-shadow: 0 0 10px rgba(0, 255, 255, 0.4) !important;
                }
                .devlabs-button.active {
                    background: #0ff !important;
                    color: #000 !important;
                }
                .devlabs-element-info {
                    background: rgba(0, 255, 255, 0.05) !important;
                    padding: 10px !important;
                    border-radius: 4px !important;
                    border: 1px solid rgba(0, 255, 255, 0.2) !important;
                    margin-top: 8px !important;
                    font-size: 11px !important;
                    line-height: 1.6 !important;
                }
                *[data-devlabs-highlight] {
                    outline: 2px solid #0ff !important;
                    outline-offset: 2px !important;
                    box-shadow: 0 0 10px rgba(0, 255, 255, 0.5) !important;
                }
                .devlabs-resize-handle {
                    position: absolute !important;
                    bottom: 0 !important;
                    right: 0 !important;
                    width: 20px !important;
                    height: 20px !important;
                    cursor: nwse-resize !important;
                    z-index: 10 !important;
                }
                .devlabs-resize-handle::after {
                    content: '' !important;
                    position: absolute !important;
                    bottom: 2px !important;
                    right: 2px !important;
                    width: 0 !important;
                    height: 0 !important;
                    border-style: solid !important;
                    border-width: 0 0 12px 12px !important;
                    border-color: transparent transparent rgba(0, 255, 255, 0.4) transparent !important;
                }
                input[type="range"] {
                    -webkit-appearance: none !important;
                    appearance: none !important;
                    height: 6px !important;
                    background: rgba(0, 255, 255, 0.2) !important;
                    border-radius: 3px !important;
                    outline: none !important;
                }
                input[type="range"]::-webkit-slider-thumb {
                    -webkit-appearance: none !important;
                    appearance: none !important;
                    width: 16px !important;
                    height: 16px !important;
                    background: #0ff !important;
                    cursor: pointer !important;
                    border-radius: 50% !important;
                }
                input[type="range"]::-moz-range-thumb {
                    width: 16px !important;
                    height: 16px !important;
                    background: #0ff !important;
                    cursor: pointer !important;
                    border-radius: 50% !important;
                    border: none !important;
                }
            `;
            document.head.appendChild(style);
        },

        createPanel() {
            if (document.getElementById('devlabs-panel')) {
                this.toggle();
                return;
            }

            const panel = document.createElement('div');
            panel.id = 'devlabs-panel';
            panel.innerHTML = `
                <div class="devlabs-header" id="devlabs-header">
                    <div class="devlabs-title">🔍 Dev Labs Debugger</div>
                    <div class="devlabs-controls">
                        <button class="devlabs-btn" id="collapse-btn" onclick="DevLabsDebugger.toggleCollapse()" title="Collapse/Expand">−</button>
                        <button class="devlabs-btn" onclick="DevLabsDebugger.cycleTheme()" title="Change Theme">🎨</button>
                        <button class="devlabs-btn" onclick="DevLabsDebugger.exportCSS()" title="Export CSS">📤</button>
                        <button class="devlabs-btn" onclick="DevLabsDebugger.resetChanges()" title="Reset All">🔄</button>
                        <button class="devlabs-btn" onclick="DevLabsDebugger.close()" title="Close">×</button>
                    </div>
                </div>
                <div class="devlabs-body">
                    <div class="devlabs-section">
                        <button class="devlabs-button" id="pick-element-btn" onclick="DevLabsDebugger.startPicking()">
                            🎯 Pick Element
                        </button>
                    </div>
                    <div class="devlabs-section" id="element-info"></div>
                    <div class="devlabs-section" id="style-controls"></div>
                </div>
                <div class="devlabs-resize-handle" id="resize-handle"></div>
            `;
            document.body.appendChild(panel);

            // Setup dragging
            this.setupDragging();

            // Setup resizing
            this.setupResizing();
        },

        setupDragging() {
            const header = document.getElementById('devlabs-header');
            const panel = document.getElementById('devlabs-panel');

            header.addEventListener('mousedown', (e) => {
                // Don't drag if clicking on buttons
                if (e.target.classList.contains('devlabs-btn')) return;

                this.isDragging = true;
                this.dragStartX = e.clientX;
                this.dragStartY = e.clientY;

                const rect = panel.getBoundingClientRect();
                this.panelStartX = rect.left;
                this.panelStartY = rect.top;

                header.style.cursor = 'grabbing';
            });

            document.addEventListener('mousemove', (e) => {
                if (this.isDragging) {
                    e.preventDefault();
                    const deltaX = e.clientX - this.dragStartX;
                    const deltaY = e.clientY - this.dragStartY;

                    panel.style.left = (this.panelStartX + deltaX) + 'px';
                    panel.style.top = (this.panelStartY + deltaY) + 'px';
                    panel.style.right = 'auto';
                    panel.style.bottom = 'auto';
                }
            });

            document.addEventListener('mouseup', () => {
                if (this.isDragging) {
                    this.isDragging = false;
                    header.style.cursor = 'move';
                }
            });
        },

        setupResizing() {
            const handle = document.getElementById('resize-handle');
            const panel = document.getElementById('devlabs-panel');

            handle.addEventListener('mousedown', (e) => {
                e.stopPropagation();
                this.isResizing = true;
                this.resizeStartX = e.clientX;
                this.resizeStartY = e.clientY;
                this.startWidth = panel.offsetWidth;
                this.startHeight = panel.offsetHeight;
            });

            document.addEventListener('mousemove', (e) => {
                if (this.isResizing) {
                    e.preventDefault();
                    const deltaX = e.clientX - this.resizeStartX;
                    const deltaY = e.clientY - this.resizeStartY;

                    const newWidth = Math.max(300, this.startWidth + deltaX);
                    const newHeight = Math.max(200, this.startHeight + deltaY);

                    panel.style.width = newWidth + 'px';
                    panel.style.maxHeight = newHeight + 'px';
                }
            });

            document.addEventListener('mouseup', () => {
                if (this.isResizing) {
                    this.isResizing = false;
                }
            });
        },

        toggle() {
            this.isOpen = !this.isOpen;
            const panel = document.getElementById('devlabs-panel');
            if (panel) {
                panel.classList.toggle('show');
            }
        },

        show() {
            this.isOpen = true;
            const panel = document.getElementById('devlabs-panel');
            if (panel) {
                panel.classList.add('show');
            }
        },

        close() {
            this.isOpen = false;
            const panel = document.getElementById('devlabs-panel');
            if (panel) {
                panel.classList.remove('show');
            }
            if (this.isPickingElement) {
                this.startPicking(); // Stop picking
            }
        },

        toggleCollapse() {
            this.isCollapsed = !this.isCollapsed;
            const panel = document.getElementById('devlabs-panel');
            const btn = document.getElementById('collapse-btn');
            if (panel) {
                panel.classList.toggle('collapsed');
                btn.textContent = this.isCollapsed ? '+' : '−';
                btn.title = this.isCollapsed ? 'Expand' : 'Collapse';
            }
        },

        cycleTheme() {
            const themes = {
                cyan: { primary: '#0ff', name: 'Cyan' },
                red: { primary: '#ff0040', name: 'Red' },
                green: { primary: '#00ff88', name: 'Green' },
                purple: { primary: '#a855f7', name: 'Purple' }
            };

            const themeKeys = Object.keys(themes);
            const currentIndex = themeKeys.indexOf(this.theme);
            this.theme = themeKeys[(currentIndex + 1) % themeKeys.length];

            const color = themes[this.theme].primary;
            const style = document.getElementById('devlabs-debugger-styles');

            // Update CSS variables by replacing colors
            let css = style.textContent;
            css = css.replace(/#0ff/g, color);
            css = css.replace(/rgba\\(0, 255, 255/g, this.hexToRgba(color));
            style.textContent = css;

            console.log('🎨 Theme changed to:', themes[this.theme].name);
        },

        hexToRgba(hex) {
            const r = parseInt(hex.slice(1, 3), 16);
            const g = parseInt(hex.slice(3, 5), 16);
            const b = parseInt(hex.slice(5, 7), 16);
            return `rgba(${r}, ${g}, ${b}`;
        },

        startPicking() {
            this.isPickingElement = !this.isPickingElement;
            const btn = document.getElementById('pick-element-btn');

            if (this.isPickingElement) {
                btn.textContent = '⏹️ Stop Picking';
                btn.classList.add('active');
                document.body.style.cursor = 'crosshair';
                document.addEventListener('click', this.pickElementHandler, true);
                document.addEventListener('mouseover', this.highlightElementHandler, true);
            } else {
                btn.textContent = '🎯 Pick Element';
                btn.classList.remove('active');
                document.body.style.cursor = 'default';
                document.removeEventListener('click', this.pickElementHandler, true);
                document.removeEventListener('mouseover', this.highlightElementHandler, true);
                this.clearHighlight();
            }
        },

        highlightElementHandler: (e) => {
            if (e.target.closest('#devlabs-panel')) {
                return;
            }
            window.DevLabsDebugger.clearHighlight();
            e.target.setAttribute('data-devlabs-highlight', '');
        },

        pickElementHandler: (e) => {
            if (e.target.closest('#devlabs-panel')) {
                return;
            }
            e.preventDefault();
            e.stopPropagation();
            window.DevLabsDebugger.selectElement(e.target);
            window.DevLabsDebugger.startPicking();
        },

        clearHighlight() {
            document.querySelectorAll('[data-devlabs-highlight]').forEach(el => {
                el.removeAttribute('data-devlabs-highlight');
            });
        },

        selectElement(element) {
            this.selectedElement = element;
            this.displayElementInfo(element);
            this.createStyleControls(element);
        },

        displayElementInfo(element) {
            const computed = window.getComputedStyle(element);
            const info = document.getElementById('element-info');
            info.innerHTML = `
                <div class="devlabs-element-info">
                    <strong style="color: #0ff;">Selected Element</strong><br>
                    <strong>Tag:</strong> &lt;${element.tagName.toLowerCase()}&gt;<br>
                    <strong>Class:</strong> ${element.className || '(none)'}<br>
                    <strong>ID:</strong> ${element.id || '(none)'}<br>
                    <strong>Size:</strong> ${element.offsetWidth}×${element.offsetHeight}px
                </div>
            `;
        },

        createStyleControls(element) {
            const computed = window.getComputedStyle(element);
            const controls = document.getElementById('style-controls');

            controls.innerHTML = `
                <div class="devlabs-section">
                    <label class="devlabs-label">🎨 Background Color</label>
                    <input type="color" class="devlabs-input" value="${this.rgbToHex(computed.backgroundColor)}" onchange="DevLabsDebugger.updateStyle('backgroundColor', this.value)">
                </div>
                <div class="devlabs-section">
                    <label class="devlabs-label">📝 Text Color</label>
                    <input type="color" class="devlabs-input" value="${this.rgbToHex(computed.color)}" onchange="DevLabsDebugger.updateStyle('color', this.value)">
                </div>
                <div class="devlabs-section">
                    <label class="devlabs-label">📏 Width (px)</label>
                    <input type="number" class="devlabs-input" value="${parseInt(computed.width)}" onchange="DevLabsDebugger.updateStyle('width', this.value + 'px')">
                </div>
                <div class="devlabs-section">
                    <label class="devlabs-label">📐 Height (px)</label>
                    <input type="number" class="devlabs-input" value="${parseInt(computed.height)}" onchange="DevLabsDebugger.updateStyle('height', this.value + 'px')">
                </div>
                <div class="devlabs-section">
                    <label class="devlabs-label">📦 Padding (px)</label>
                    <input type="number" class="devlabs-input" value="${parseInt(computed.padding)}" onchange="DevLabsDebugger.updateStyle('padding', this.value + 'px')">
                </div>
                <div class="devlabs-section">
                    <label class="devlabs-label">📍 Margin (px)</label>
                    <input type="number" class="devlabs-input" value="${parseInt(computed.margin)}" onchange="DevLabsDebugger.updateStyle('margin', this.value + 'px')">
                </div>
                <div class="devlabs-section">
                    <label class="devlabs-label">⚪ Border Radius (px)</label>
                    <input type="number" class="devlabs-input" value="${parseInt(computed.borderRadius)}" onchange="DevLabsDebugger.updateStyle('borderRadius', this.value + 'px')">
                </div>
                <div class="devlabs-section">
                    <label class="devlabs-label">🔤 Font Size (px)</label>
                    <input type="number" class="devlabs-input" value="${parseInt(computed.fontSize)}" onchange="DevLabsDebugger.updateStyle('fontSize', this.value + 'px')">
                </div>
                <div class="devlabs-section">
                    <label class="devlabs-label">👻 Opacity (${computed.opacity})</label>
                    <input type="range" class="devlabs-input" min="0" max="1" step="0.05" value="${computed.opacity}" oninput="DevLabsDebugger.updateStyle('opacity', this.value); this.previousElementSibling.textContent = '👻 Opacity (' + this.value + ')'">
                </div>
            `;
        },

        updateStyle(property, value) {
            if (this.selectedElement) {
                this.selectedElement.style[property] = value;
                // Track change
                const selector = this.getElementSelector(this.selectedElement);
                if (!this.changes[selector]) {
                    this.changes[selector] = {};
                }
                this.changes[selector][property] = value;
            }
        },

        getElementSelector(element) {
            if (element.id) return '#' + element.id;
            if (element.className) {
                const classes = element.className.split(' ').filter(c => c.trim());
                if (classes.length > 0) return '.' + classes[0];
            }
            return element.tagName.toLowerCase();
        },

        rgbToHex(rgb) {
            if (!rgb || rgb === 'rgba(0, 0, 0, 0)') return '#000000';
            const match = rgb.match(/^rgba?\\((\\d+),\\s*(\\d+),\\s*(\\d+)/);
            if (!match) return '#000000';
            const hex = (x) => ("0" + parseInt(x).toString(16)).slice(-2);
            return "#" + hex(match[1]) + hex(match[2]) + hex(match[3]);
        },

        exportCSS() {
            if (Object.keys(this.changes).length === 0) {
                alert('⚠️ No changes to export!\\n\\nSelect an element and make some style changes first.');
                return;
            }

            let css = '/* Dev Labs Debugger - Exported CSS */\\n';
            css += '/* ' + new Date().toLocaleString() + ' */\\n\\n';

            for (const [selector, styles] of Object.entries(this.changes)) {
                css += `${selector} {\\n`;
                for (const [property, value] of Object.entries(styles)) {
                    const cssProperty = property.replace(/([A-Z])/g, '-$1').toLowerCase();
                    css += `    ${cssProperty}: ${value};\\n`;
                }
                css += `}\\n\\n`;
            }

            const blob = new Blob([css], { type: 'text/css' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'devlabs-exported-styles.css';
            a.click();
            URL.revokeObjectURL(url);

            console.log('📤 CSS exported:\\n', css);
            alert('✅ CSS exported!\\n\\nCheck your downloads folder for:\\ndevlabs-exported-styles.css');
        },

        resetChanges() {
            if (confirm('🔄 Reset ALL style changes?\\n\\nThis will reload the page.')) {
                window.location.reload();
            }
        }
    };

    // Auto-initialize
    window.DevLabsDebugger.init();
})();
