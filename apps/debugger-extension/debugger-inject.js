/**
 * Divine Debugger - Full Featured Injectable Version
 * Matches the Chrome DevTools extension functionality
 * Works on any page without requiring DevTools
 */
(function() {
    if (window.__DivineDebugger) {
        // Toggle off if already running
        const overlay = document.getElementById('divine-debugger-overlay');
        if (overlay) overlay.remove();
        const style = document.querySelector('style[data-divine-debugger]');
        if (style) style.remove();
        window.__DivineDebugger = null;
        return;
    }

    window.__DivineDebugger = {
        version: '2.1',
        selectedElement: null,
        selectedIndex: null,
        elements: [],
        logs: [],
        isPaused: false,
        activeTab: 'console',
        isMinimized: false,
        isDragging: false,
        isResizing: false,
        dragOffset: { x: 0, y: 0 },
        position: { x: 10, y: null, width: 400, height: 280 }
    };

    const DD = window.__DivineDebugger;

    // ==========================================
    // STYLES
    // ==========================================
    const css = `
        #divine-debugger-overlay {
            position: fixed;
            bottom: 10px;
            left: 10px;
            width: 400px;
            height: 280px;
            min-width: 300px;
            min-height: 150px;
            max-width: 95vw;
            max-height: 80vh;
            background: linear-gradient(180deg, #1a1a1a 0%, #0d0d0d 100%);
            border: 2px solid var(--theme-primary, #0ff);
            border-radius: 8px;
            box-shadow: 0 4px 30px rgba(0, 255, 255, 0.3);
            z-index: 2147483647;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            color: #e0e0e0;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }
        #divine-debugger-overlay.minimized {
            height: 36px !important;
            min-height: 36px !important;
        }
        #divine-debugger-overlay.minimized .dd-content,
        #divine-debugger-overlay.minimized .dd-tabs { display: none; }
        #divine-debugger-overlay * { box-sizing: border-box; margin: 0; padding: 0; }

        /* Resize handle */
        .dd-resize-handle {
            position: absolute;
            background: transparent;
            z-index: 10;
        }
        .dd-resize-n { top: 0; left: 10px; right: 10px; height: 6px; cursor: n-resize; }
        .dd-resize-e { top: 10px; right: 0; bottom: 10px; width: 6px; cursor: e-resize; }
        .dd-resize-s { bottom: 0; left: 10px; right: 10px; height: 6px; cursor: s-resize; }
        .dd-resize-w { top: 10px; left: 0; bottom: 10px; width: 6px; cursor: w-resize; }
        .dd-resize-nw { top: 0; left: 0; width: 10px; height: 10px; cursor: nw-resize; }
        .dd-resize-ne { top: 0; right: 0; width: 10px; height: 10px; cursor: ne-resize; }
        .dd-resize-se { bottom: 0; right: 0; width: 10px; height: 10px; cursor: se-resize; }
        .dd-resize-sw { bottom: 0; left: 0; width: 10px; height: 10px; cursor: sw-resize; }

        /* Header - draggable */
        .dd-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 6px 10px;
            background: rgba(0, 255, 255, 0.08);
            border-bottom: 1px solid rgba(0, 255, 255, 0.2);
            cursor: move;
            user-select: none;
            flex-shrink: 0;
        }
        .dd-title {
            color: var(--theme-primary, #0ff);
            font-size: 12px;
            font-weight: bold;
            text-shadow: 0 0 10px rgba(0, 255, 255, 0.5);
        }
        .dd-header-actions { display: flex; gap: 4px; }
        .dd-btn {
            background: transparent;
            border: 1px solid rgba(0, 255, 255, 0.3);
            color: var(--theme-primary, #0ff);
            padding: 3px 8px;
            font-size: 10px;
            cursor: pointer;
            border-radius: 3px;
            font-family: inherit;
            transition: all 0.2s;
        }
        .dd-btn:hover {
            background: rgba(0, 255, 255, 0.1);
            border-color: var(--theme-primary, #0ff);
        }
        .dd-btn-icon {
            padding: 3px 6px;
            font-size: 12px;
            line-height: 1;
        }
        .dd-btn-close { border-color: rgba(255,68,68,0.5); color: #f44; }
        .dd-btn-close:hover { background: rgba(255,68,68,0.15); }
        .dd-btn-min { border-color: rgba(255,200,0,0.5); color: #fc0; }
        .dd-btn-min:hover { background: rgba(255,200,0,0.15); }
        .dd-btn-primary {
            background: var(--theme-primary, #0ff);
            color: #000;
            border-color: var(--theme-primary, #0ff);
        }
        .dd-btn-primary:hover { box-shadow: 0 0 15px rgba(0,255,255,0.5); }

        /* Tabs */
        .dd-tabs {
            display: flex;
            background: #111;
            border-bottom: 1px solid #333;
            overflow-x: auto;
            flex-shrink: 0;
        }
        .dd-tabs::-webkit-scrollbar { height: 3px; }
        .dd-tab {
            background: transparent;
            border: none;
            color: #888;
            padding: 6px 10px;
            font-size: 11px;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            white-space: nowrap;
            font-family: inherit;
            transition: all 0.2s;
        }
        .dd-tab:hover { color: var(--theme-primary, #0ff); background: rgba(0,255,255,0.05); }
        .dd-tab.active { color: var(--theme-primary, #0ff); border-bottom-color: var(--theme-primary, #0ff); }

        /* Main Content */
        .dd-content { flex: 1; overflow: hidden; display: flex; }
        .dd-panel { display: none; flex: 1; overflow: hidden; flex-direction: column; }
        .dd-panel.active { display: flex; }

        /* Console Panel */
        .dd-console-output {
            flex: 1;
            overflow-y: auto;
            padding: 8px;
            background: #0a0a0a;
        }
        .dd-log {
            padding: 6px 8px;
            border-bottom: 1px solid rgba(255,255,255,0.03);
            display: flex;
            gap: 8px;
            align-items: flex-start;
        }
        .dd-log-icon { opacity: 0.7; }
        .dd-log-msg { flex: 1; word-break: break-word; white-space: pre-wrap; }
        .dd-log-time { color: #555; font-size: 10px; }
        .dd-log.info .dd-log-msg { color: #6bc1ff; }
        .dd-log.warn .dd-log-msg { color: #ffd93d; }
        .dd-log.error .dd-log-msg { color: #ff6b6b; }
        .dd-log.cmd .dd-log-msg { color: var(--theme-primary, #0ff); }
        .dd-log.result .dd-log-msg { color: #a0e0a0; }

        .dd-console-input {
            display: flex;
            gap: 8px;
            padding: 8px;
            background: rgba(0,0,0,0.3);
            border-top: 1px solid rgba(0,255,255,0.1);
        }
        .dd-input {
            flex: 1;
            background: rgba(0,0,0,0.5);
            border: 1px solid rgba(0,255,255,0.2);
            color: #fff;
            padding: 8px 10px;
            font-family: inherit;
            font-size: 13px;
            border-radius: 4px;
            outline: none;
        }
        .dd-input:focus { border-color: var(--theme-primary, #0ff); box-shadow: 0 0 8px rgba(0,255,255,0.2); }

        /* Elements Panel */
        .dd-elements-layout { display: flex; flex: 1; overflow: hidden; }
        .dd-elements-list {
            width: 50%;
            overflow-y: auto;
            border-right: 1px solid #333;
            padding: 8px;
        }
        .dd-element-item {
            padding: 6px 8px;
            cursor: pointer;
            border-radius: 3px;
            font-size: 12px;
            color: #888;
            transition: all 0.15s;
        }
        .dd-element-item:hover { background: rgba(0,255,255,0.1); color: #fff; }
        .dd-element-item.selected { background: rgba(0,255,255,0.2); color: var(--theme-primary, #0ff); }
        .dd-element-tag { color: #ff79c6; }
        .dd-element-id { color: #50fa7b; }
        .dd-element-class { color: #f1fa8c; }

        .dd-style-editor {
            width: 50%;
            overflow-y: auto;
            padding: 12px;
        }
        .dd-section { margin-bottom: 16px; }
        .dd-section-title {
            color: var(--theme-primary, #0ff);
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
            padding-bottom: 6px;
            border-bottom: 1px solid #333;
        }
        .dd-control {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 8px;
        }
        .dd-control label { width: 80px; font-size: 11px; color: #888; }
        .dd-control input[type="range"] {
            flex: 1;
            height: 4px;
            background: #333;
            border-radius: 2px;
            -webkit-appearance: none;
        }
        .dd-control input[type="range"]::-webkit-slider-thumb {
            -webkit-appearance: none;
            width: 14px;
            height: 14px;
            background: var(--theme-primary, #0ff);
            border-radius: 50%;
            cursor: pointer;
        }
        .dd-control input[type="color"] {
            width: 40px;
            height: 24px;
            border: 1px solid #333;
            border-radius: 3px;
            cursor: pointer;
            background: #222;
        }
        .dd-control-value {
            width: 50px;
            font-size: 11px;
            color: var(--theme-primary, #0ff);
            text-align: right;
        }

        /* Analysis Panel */
        .dd-analysis-content { flex: 1; overflow-y: auto; padding: 12px; }
        .dd-analysis-buttons {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 8px;
            margin-bottom: 16px;
        }
        .dd-analysis-output {
            background: #0a0a0a;
            border: 1px solid #333;
            border-radius: 4px;
            padding: 12px;
            min-height: 200px;
            max-height: 400px;
            overflow-y: auto;
            font-size: 12px;
            line-height: 1.6;
        }
        .dd-issue { margin-bottom: 12px; padding: 10px; background: #111; border-radius: 4px; border-left: 3px solid #f44; }
        .dd-issue-title { color: #f44; font-weight: bold; margin-bottom: 6px; }
        .dd-issue-location { color: #888; font-size: 11px; }
        .dd-issue.warning { border-left-color: #ffd93d; }
        .dd-issue.warning .dd-issue-title { color: #ffd93d; }
        .dd-success { color: #50fa7b; text-align: center; padding: 20px; }

        /* Security Panel */
        .dd-security-content { flex: 1; overflow-y: auto; padding: 12px; }
        .dd-security-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
            gap: 8px;
            margin-bottom: 16px;
        }
        .dd-security-output {
            background: #0a0a0a;
            border: 1px solid #333;
            border-radius: 4px;
            padding: 12px;
            min-height: 200px;
        }
        .dd-security-item { padding: 8px; background: #111; border-radius: 4px; margin-bottom: 8px; }
        .dd-security-label { font-size: 11px; color: #888; margin-bottom: 4px; }
        .dd-security-value { color: #e0e0e0; font-size: 12px; word-break: break-all; }
        .dd-security-good { color: #50fa7b; }
        .dd-security-bad { color: #ff6b6b; }
        .dd-security-warn { color: #ffd93d; }

        /* Quick Actions */
        .dd-quick-actions {
            display: flex;
            gap: 6px;
            padding: 8px;
            background: #111;
            border-top: 1px solid #333;
        }

        /* Scrollbar */
        #divine-debugger-overlay ::-webkit-scrollbar { width: 6px; height: 6px; }
        #divine-debugger-overlay ::-webkit-scrollbar-track { background: #111; }
        #divine-debugger-overlay ::-webkit-scrollbar-thumb { background: #444; border-radius: 3px; }
        #divine-debugger-overlay ::-webkit-scrollbar-thumb:hover { background: #555; }

        /* Element highlight */
        .dd-highlight-overlay {
            position: fixed;
            pointer-events: none;
            background: rgba(0, 255, 255, 0.2);
            border: 2px solid var(--theme-primary, #0ff);
            z-index: 2147483646;
            transition: all 0.1s;
        }
    `;

    // ==========================================
    // HTML STRUCTURE
    // ==========================================
    const html = `
        <div class="dd-resize-handle dd-resize-n" data-resize="n"></div>
        <div class="dd-resize-handle dd-resize-e" data-resize="e"></div>
        <div class="dd-resize-handle dd-resize-s" data-resize="s"></div>
        <div class="dd-resize-handle dd-resize-w" data-resize="w"></div>
        <div class="dd-resize-handle dd-resize-nw" data-resize="nw"></div>
        <div class="dd-resize-handle dd-resize-ne" data-resize="ne"></div>
        <div class="dd-resize-handle dd-resize-se" data-resize="se"></div>
        <div class="dd-resize-handle dd-resize-sw" data-resize="sw"></div>
        <div class="dd-header" id="dd-drag-handle">
            <span class="dd-title">⚡ Divine Debugger</span>
            <div class="dd-header-actions">
                <button class="dd-btn dd-btn-icon dd-btn-min" onclick="DD.toggleMinimize()" title="Minimize">─</button>
                <button class="dd-btn dd-btn-icon dd-btn-close" onclick="DD.close()" title="Close">✕</button>
            </div>
        </div>
        <div class="dd-tabs">
            <button class="dd-tab active" data-tab="console">Console</button>
            <button class="dd-tab" data-tab="elements">Elements</button>
            <button class="dd-tab" data-tab="analysis">Analysis</button>
            <button class="dd-tab" data-tab="security">Security</button>
            <button class="dd-tab" data-tab="network">Network</button>
            <button class="dd-tab" data-tab="storage">Storage</button>
        </div>
        <div class="dd-content">
            <!-- Console Panel -->
            <div id="dd-panel-console" class="dd-panel active">
                <div class="dd-console-output" id="dd-console-output"></div>
                <div class="dd-console-input">
                    <input type="text" class="dd-input" id="dd-console-input" placeholder="JS..." autocomplete="off">
                    <button class="dd-btn dd-btn-primary" onclick="DD.execConsole()">▶</button>
                    <button class="dd-btn" onclick="DD.clearConsole()" title="Clear">🗑</button>
                    <button class="dd-btn" onclick="DD.exportLogs()" title="Export">💾</button>
                </div>
            </div>

            <!-- Elements Panel -->
            <div id="dd-panel-elements" class="dd-panel">
                <div class="dd-elements-layout">
                    <div class="dd-elements-list" id="dd-elements-list"></div>
                    <div class="dd-style-editor" id="dd-style-editor">
                        <div class="dd-section">
                            <div class="dd-section-title">Layout</div>
                            <div class="dd-control">
                                <label>Width</label>
                                <input type="range" min="0" max="1000" value="0" data-style="width" data-unit="px">
                                <span class="dd-control-value">auto</span>
                            </div>
                            <div class="dd-control">
                                <label>Height</label>
                                <input type="range" min="0" max="1000" value="0" data-style="height" data-unit="px">
                                <span class="dd-control-value">auto</span>
                            </div>
                            <div class="dd-control">
                                <label>Padding</label>
                                <input type="range" min="0" max="100" value="0" data-style="padding" data-unit="px">
                                <span class="dd-control-value">0px</span>
                            </div>
                            <div class="dd-control">
                                <label>Margin</label>
                                <input type="range" min="0" max="100" value="0" data-style="margin" data-unit="px">
                                <span class="dd-control-value">0px</span>
                            </div>
                        </div>
                        <div class="dd-section">
                            <div class="dd-section-title">Appearance</div>
                            <div class="dd-control">
                                <label>Background</label>
                                <input type="color" value="#111111" data-style="backgroundColor">
                            </div>
                            <div class="dd-control">
                                <label>Text Color</label>
                                <input type="color" value="#ffffff" data-style="color">
                            </div>
                            <div class="dd-control">
                                <label>Opacity</label>
                                <input type="range" min="0" max="100" value="100" data-style="opacity" data-unit="">
                                <span class="dd-control-value">100%</span>
                            </div>
                            <div class="dd-control">
                                <label>Border Radius</label>
                                <input type="range" min="0" max="50" value="0" data-style="borderRadius" data-unit="px">
                                <span class="dd-control-value">0px</span>
                            </div>
                        </div>
                        <div class="dd-section">
                            <div class="dd-section-title">Typography</div>
                            <div class="dd-control">
                                <label>Font Size</label>
                                <input type="range" min="8" max="72" value="16" data-style="fontSize" data-unit="px">
                                <span class="dd-control-value">16px</span>
                            </div>
                        </div>
                        <div class="dd-quick-actions">
                            <button class="dd-btn" onclick="DD.highlightElement()">Highlight</button>
                            <button class="dd-btn" onclick="DD.hideElement()">Hide</button>
                            <button class="dd-btn" onclick="DD.showElement()">Show</button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Analysis Panel -->
            <div id="dd-panel-analysis" class="dd-panel">
                <div class="dd-analysis-content">
                    <div class="dd-analysis-buttons">
                        <button class="dd-btn dd-btn-primary" onclick="DD.runFullAnalysis()">🚀 Run Full Analysis</button>
                        <button class="dd-btn" onclick="DD.checkDuplicates()">📋 Duplicates</button>
                        <button class="dd-btn" onclick="DD.checkScopes()">🔄 Scope Issues</button>
                        <button class="dd-btn" onclick="DD.checkSelectors()">🎯 Missing Selectors</button>
                    </div>
                    <div class="dd-analysis-output" id="dd-analysis-output">
                        <div style="text-align:center;padding:40px;color:#666;">
                            <div style="font-size:48px;margin-bottom:10px;">🔍</div>
                            Click "Run Full Analysis" to scan the page
                        </div>
                    </div>
                </div>
            </div>

            <!-- Security Panel -->
            <div id="dd-panel-security" class="dd-panel">
                <div class="dd-security-content">
                    <div class="dd-security-grid">
                        <button class="dd-btn dd-btn-primary" onclick="DD.runSecurityScan()">🔍 Full Scan</button>
                        <button class="dd-btn" onclick="DD.checkCookies()">🍪 Cookies</button>
                        <button class="dd-btn" onclick="DD.checkStorage()">💾 Storage</button>
                        <button class="dd-btn" onclick="DD.checkScripts()">📜 Scripts</button>
                        <button class="dd-btn" onclick="DD.checkForms()">📝 Forms</button>
                        <button class="dd-btn" onclick="DD.checkLinks()">🔗 Links</button>
                    </div>
                    <div class="dd-security-output" id="dd-security-output">
                        <div style="text-align:center;padding:40px;color:#666;">
                            <div style="font-size:48px;margin-bottom:10px;">🔒</div>
                            Click "Full Scan" to analyze page security
                        </div>
                    </div>
                </div>
            </div>

            <!-- Network Panel -->
            <div id="dd-panel-network" class="dd-panel">
                <div class="dd-analysis-content">
                    <div style="margin-bottom:12px;">
                        <button class="dd-btn" onclick="DD.clearNetwork()">Clear</button>
                        <span style="margin-left:12px;color:#888;">Network requests are captured automatically</span>
                    </div>
                    <div class="dd-analysis-output" id="dd-network-output">
                        <div style="text-align:center;padding:40px;color:#666;">
                            <div style="font-size:48px;margin-bottom:10px;">🌐</div>
                            Network requests will appear here
                        </div>
                    </div>
                </div>
            </div>

            <!-- Storage Panel -->
            <div id="dd-panel-storage" class="dd-panel">
                <div class="dd-security-content">
                    <div class="dd-security-grid">
                        <button class="dd-btn" onclick="DD.showLocalStorage()">📦 LocalStorage</button>
                        <button class="dd-btn" onclick="DD.showSessionStorage()">📋 SessionStorage</button>
                        <button class="dd-btn" onclick="DD.showCookiesStorage()">🍪 Cookies</button>
                    </div>
                    <div class="dd-security-output" id="dd-storage-output">
                        <div style="text-align:center;padding:40px;color:#666;">
                            <div style="font-size:48px;margin-bottom:10px;">💾</div>
                            Select a storage type to view
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;

    // ==========================================
    // CREATE OVERLAY
    // ==========================================
    const style = document.createElement('style');
    style.setAttribute('data-divine-debugger', '1');
    style.textContent = css;
    document.head.appendChild(style);

    const overlay = document.createElement('div');
    overlay.id = 'divine-debugger-overlay';
    overlay.innerHTML = html;
    document.body.appendChild(overlay);

    // ==========================================
    // CORE FUNCTIONS
    // ==========================================

    DD.close = function() {
        overlay.remove();
        style.remove();
        const highlight = document.querySelector('.dd-highlight-overlay');
        if (highlight) highlight.remove();
        window.__DivineDebugger = null;
    };

    DD.toggleMinimize = function() {
        DD.isMinimized = !DD.isMinimized;
        overlay.classList.toggle('minimized', DD.isMinimized);
    };

    // ==========================================
    // DRAG & RESIZE
    // ==========================================

    const dragHandle = document.getElementById('dd-drag-handle');
    let resizeDir = null;
    let startRect = null;
    let startMouse = null;

    dragHandle.addEventListener('mousedown', (e) => {
        if (e.target.closest('.dd-header-actions')) return;
        DD.isDragging = true;
        const rect = overlay.getBoundingClientRect();
        DD.dragOffset = { x: e.clientX - rect.left, y: e.clientY - rect.top };
        overlay.style.transition = 'none';
    });

    overlay.querySelectorAll('.dd-resize-handle').forEach(handle => {
        handle.addEventListener('mousedown', (e) => {
            e.preventDefault();
            DD.isResizing = true;
            resizeDir = handle.dataset.resize;
            startRect = overlay.getBoundingClientRect();
            startMouse = { x: e.clientX, y: e.clientY };
            overlay.style.transition = 'none';
        });
    });

    document.addEventListener('mousemove', (e) => {
        if (DD.isDragging) {
            const x = e.clientX - DD.dragOffset.x;
            const y = e.clientY - DD.dragOffset.y;
            overlay.style.left = Math.max(0, Math.min(window.innerWidth - 100, x)) + 'px';
            overlay.style.top = Math.max(0, Math.min(window.innerHeight - 50, y)) + 'px';
            overlay.style.bottom = 'auto';
            overlay.style.right = 'auto';
        }
        if (DD.isResizing && startRect) {
            const dx = e.clientX - startMouse.x;
            const dy = e.clientY - startMouse.y;
            const minW = 300, minH = 150;

            if (resizeDir.includes('e')) {
                overlay.style.width = Math.max(minW, startRect.width + dx) + 'px';
            }
            if (resizeDir.includes('w')) {
                const newW = Math.max(minW, startRect.width - dx);
                overlay.style.width = newW + 'px';
                overlay.style.left = (startRect.left + (startRect.width - newW)) + 'px';
            }
            if (resizeDir.includes('s')) {
                overlay.style.height = Math.max(minH, startRect.height + dy) + 'px';
            }
            if (resizeDir.includes('n')) {
                const newH = Math.max(minH, startRect.height - dy);
                overlay.style.height = newH + 'px';
                overlay.style.top = (startRect.top + (startRect.height - newH)) + 'px';
                overlay.style.bottom = 'auto';
            }
        }
    });

    document.addEventListener('mouseup', () => {
        DD.isDragging = false;
        DD.isResizing = false;
        resizeDir = null;
        startRect = null;
        overlay.style.transition = '';
    });

    // Touch support for mobile
    dragHandle.addEventListener('touchstart', (e) => {
        if (e.target.closest('.dd-header-actions')) return;
        DD.isDragging = true;
        const touch = e.touches[0];
        const rect = overlay.getBoundingClientRect();
        DD.dragOffset = { x: touch.clientX - rect.left, y: touch.clientY - rect.top };
        overlay.style.transition = 'none';
    }, { passive: true });

    document.addEventListener('touchmove', (e) => {
        if (DD.isDragging) {
            const touch = e.touches[0];
            const x = touch.clientX - DD.dragOffset.x;
            const y = touch.clientY - DD.dragOffset.y;
            overlay.style.left = Math.max(0, Math.min(window.innerWidth - 100, x)) + 'px';
            overlay.style.top = Math.max(0, Math.min(window.innerHeight - 50, y)) + 'px';
            overlay.style.bottom = 'auto';
            overlay.style.right = 'auto';
        }
    }, { passive: true });

    document.addEventListener('touchend', () => {
        DD.isDragging = false;
        overlay.style.transition = '';
    });

    DD.log = function(msg, type = 'log') {
        if (DD.isPaused) return;
        const output = document.getElementById('dd-console-output');
        if (!output) return;

        const icons = { log: '›', info: 'ℹ', warn: '⚠', error: '✗', cmd: '›', result: '←' };
        const time = new Date().toLocaleTimeString();

        const div = document.createElement('div');
        div.className = `dd-log ${type}`;
        div.innerHTML = `
            <span class="dd-log-icon">${icons[type] || '›'}</span>
            <span class="dd-log-msg">${DD.escapeHtml(String(msg))}</span>
            <span class="dd-log-time">${time}</span>
        `;
        output.appendChild(div);
        output.scrollTop = output.scrollHeight;
        DD.logs.push({ msg, type, time });
    };

    DD.escapeHtml = function(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    };

    DD.clearConsole = function() {
        const output = document.getElementById('dd-console-output');
        if (output) output.innerHTML = '';
        DD.logs = [];
    };

    DD.execConsole = function() {
        const input = document.getElementById('dd-console-input');
        const code = input.value.trim();
        if (!code) return;

        DD.log(code, 'cmd');
        try {
            const result = eval(code);
            if (result !== undefined) {
                const display = typeof result === 'object' ? JSON.stringify(result, null, 2) : String(result);
                DD.log(display, 'result');
            }
        } catch (e) {
            DD.log(e.message, 'error');
        }
        input.value = '';
    };

    DD.exportLogs = function() {
        const data = DD.logs.map(l => `[${l.time}] [${l.type.toUpperCase()}] ${l.msg}`).join('\n');
        const blob = new Blob([data], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'divine-debugger-logs.txt';
        a.click();
        URL.revokeObjectURL(url);
    };

    // ==========================================
    // ELEMENTS PANEL
    // ==========================================

    DD.loadElements = function() {
        const list = document.getElementById('dd-elements-list');
        if (!list) return;

        DD.elements = Array.from(document.querySelectorAll('body *')).filter(el => {
            return el.id !== 'divine-debugger-overlay' && !el.closest('#divine-debugger-overlay');
        });

        list.innerHTML = DD.elements.slice(0, 200).map((el, i) => {
            const tag = el.tagName.toLowerCase();
            const id = el.id ? `#${el.id}` : '';
            const cls = el.className && typeof el.className === 'string' ? `.${el.className.split(' ')[0]}` : '';
            return `<div class="dd-element-item" data-index="${i}">
                <span class="dd-element-tag">${tag}</span><span class="dd-element-id">${id}</span><span class="dd-element-class">${cls}</span>
            </div>`;
        }).join('');

        if (DD.elements.length > 200) {
            list.innerHTML += `<div style="padding:10px;color:#888;text-align:center;">... and ${DD.elements.length - 200} more elements</div>`;
        }
    };

    DD.selectElement = function(index) {
        DD.selectedIndex = index;
        DD.selectedElement = DD.elements[index];

        document.querySelectorAll('.dd-element-item').forEach(el => el.classList.remove('selected'));
        const item = document.querySelector(`.dd-element-item[data-index="${index}"]`);
        if (item) item.classList.add('selected');

        DD.updateStyleControls();
        DD.highlightElement();
    };

    DD.updateStyleControls = function() {
        if (!DD.selectedElement) return;
        const computed = window.getComputedStyle(DD.selectedElement);

        document.querySelectorAll('.dd-style-editor input[type="range"]').forEach(input => {
            const prop = input.dataset.style;
            const value = parseInt(computed[prop]) || 0;
            input.value = prop === 'opacity' ? value * 100 : value;
            const display = input.nextElementSibling;
            if (display) {
                display.textContent = prop === 'opacity' ? `${Math.round(value * 100)}%` : `${value}px`;
            }
        });

        document.querySelectorAll('.dd-style-editor input[type="color"]').forEach(input => {
            const prop = input.dataset.style;
            const value = computed[prop];
            try {
                const rgb = value.match(/\d+/g);
                if (rgb && rgb.length >= 3) {
                    input.value = '#' + rgb.slice(0, 3).map(x => parseInt(x).toString(16).padStart(2, '0')).join('');
                }
            } catch (e) {}
        });
    };

    DD.applyStyle = function(prop, value) {
        if (!DD.selectedElement) return;
        DD.selectedElement.style[prop] = value;
    };

    DD.highlightElement = function() {
        let highlight = document.querySelector('.dd-highlight-overlay');
        if (!highlight) {
            highlight = document.createElement('div');
            highlight.className = 'dd-highlight-overlay';
            document.body.appendChild(highlight);
        }

        if (!DD.selectedElement) {
            highlight.style.display = 'none';
            return;
        }

        const rect = DD.selectedElement.getBoundingClientRect();
        highlight.style.display = 'block';
        highlight.style.top = rect.top + 'px';
        highlight.style.left = rect.left + 'px';
        highlight.style.width = rect.width + 'px';
        highlight.style.height = rect.height + 'px';

        setTimeout(() => { highlight.style.display = 'none'; }, 2000);
    };

    DD.hideElement = function() {
        if (DD.selectedElement) DD.selectedElement.style.display = 'none';
    };

    DD.showElement = function() {
        if (DD.selectedElement) DD.selectedElement.style.display = '';
    };

    // ==========================================
    // CODE ANALYSIS (Ported from Python)
    // ==========================================

    DD.runFullAnalysis = function() {
        const output = document.getElementById('dd-analysis-output');
        output.innerHTML = '<div style="text-align:center;padding:20px;color:var(--theme-primary,#0ff);">🔍 Running analysis...</div>';

        setTimeout(() => {
            let html = '';

            // Check duplicates
            const duplicates = DD.findDuplicateFunctions();
            if (duplicates.length > 0) {
                html += '<div class="dd-section-title">📋 Duplicate Functions</div>';
                duplicates.forEach(d => {
                    html += `<div class="dd-issue"><div class="dd-issue-title">${d.name}</div><div class="dd-issue-location">Found in: ${d.locations.join(', ')}</div></div>`;
                });
            }

            // Check scope issues
            const scopes = DD.findScopeMismatches();
            if (scopes.length > 0) {
                html += '<div class="dd-section-title">🔄 Scope Mismatches</div>';
                scopes.forEach(s => {
                    html += `<div class="dd-issue warning"><div class="dd-issue-title">${s.name}</div><div class="dd-issue-location">Used as both local and window.${s.name}</div></div>`;
                });
            }

            // Check selectors
            const missing = DD.findMissingSelectors();
            if (missing.length > 0) {
                html += '<div class="dd-section-title">🎯 Missing Selectors</div>';
                missing.forEach(m => {
                    html += `<div class="dd-issue"><div class="dd-issue-title">${m.type}: ${m.name}</div><div class="dd-issue-location">Referenced but not found in DOM</div></div>`;
                });
            }

            if (!html) {
                html = '<div class="dd-success">✅ No issues found! Code looks clean.</div>';
            }

            output.innerHTML = html;
        }, 100);
    };

    DD.findDuplicateFunctions = function() {
        const scripts = document.querySelectorAll('script:not([src])');
        const functions = {};
        const patterns = [
            /function\s+(\w+)\s*\(/g,
            /const\s+(\w+)\s*=\s*(?:async\s*)?\(/g,
            /(\w+)\s*:\s*function\s*\(/g
        ];

        scripts.forEach((script, idx) => {
            const content = script.textContent;
            patterns.forEach(pattern => {
                let match;
                while ((match = pattern.exec(content)) !== null) {
                    const name = match[1];
                    if (!['init', 'render', 'show', 'hide', 'toggle', 'setup'].includes(name)) {
                        if (!functions[name]) functions[name] = [];
                        functions[name].push(`inline-script-${idx + 1}`);
                    }
                }
            });
        });

        // Check window functions
        const windowFuncs = Object.keys(window).filter(k => typeof window[k] === 'function' && !k.startsWith('webkit'));

        return Object.entries(functions)
            .filter(([name, locs]) => locs.length > 1)
            .map(([name, locations]) => ({ name, locations }));
    };

    DD.findScopeMismatches = function() {
        const scripts = document.querySelectorAll('script:not([src])');
        const localVars = new Set();
        const windowVars = new Set();

        scripts.forEach(script => {
            const content = script.textContent;

            // Find window.variable
            const windowMatches = content.match(/window\.(\w+)/g) || [];
            windowMatches.forEach(m => windowVars.add(m.replace('window.', '')));

            // Find local declarations
            const localMatches = content.match(/(?:let|const|var)\s+(\w+)\s*=/g) || [];
            localMatches.forEach(m => {
                const name = m.match(/(?:let|const|var)\s+(\w+)/)[1];
                localVars.add(name);
            });
        });

        // Find overlap
        const mismatches = [];
        localVars.forEach(v => {
            if (windowVars.has(v)) {
                mismatches.push({ name: v });
            }
        });

        return mismatches;
    };

    DD.findMissingSelectors = function() {
        const scripts = document.querySelectorAll('script:not([src])');
        const missing = [];

        scripts.forEach(script => {
            const content = script.textContent;

            // Find getElementById calls
            const idMatches = content.match(/getElementById\(['"]([\w-]+)['"]\)/g) || [];
            idMatches.forEach(m => {
                const id = m.match(/getElementById\(['"]([\w-]+)['"]\)/)[1];
                if (!document.getElementById(id)) {
                    missing.push({ type: 'ID', name: '#' + id });
                }
            });

            // Find querySelector with IDs
            const qsIdMatches = content.match(/querySelector\(['"]#([\w-]+)['"]\)/g) || [];
            qsIdMatches.forEach(m => {
                const id = m.match(/querySelector\(['"]#([\w-]+)['"]\)/)[1];
                if (!document.getElementById(id)) {
                    missing.push({ type: 'ID', name: '#' + id });
                }
            });
        });

        // Dedupe
        return missing.filter((m, i, arr) => arr.findIndex(x => x.name === m.name) === i);
    };

    DD.checkDuplicates = function() {
        const output = document.getElementById('dd-analysis-output');
        const duplicates = DD.findDuplicateFunctions();
        if (duplicates.length === 0) {
            output.innerHTML = '<div class="dd-success">✅ No duplicate functions found</div>';
        } else {
            output.innerHTML = duplicates.map(d =>
                `<div class="dd-issue"><div class="dd-issue-title">${d.name}</div><div class="dd-issue-location">Found in: ${d.locations.join(', ')}</div></div>`
            ).join('');
        }
    };

    DD.checkScopes = function() {
        const output = document.getElementById('dd-analysis-output');
        const scopes = DD.findScopeMismatches();
        if (scopes.length === 0) {
            output.innerHTML = '<div class="dd-success">✅ No scope mismatches found</div>';
        } else {
            output.innerHTML = scopes.map(s =>
                `<div class="dd-issue warning"><div class="dd-issue-title">${s.name}</div><div class="dd-issue-location">Used as both local and window.${s.name}</div></div>`
            ).join('');
        }
    };

    DD.checkSelectors = function() {
        const output = document.getElementById('dd-analysis-output');
        const missing = DD.findMissingSelectors();
        if (missing.length === 0) {
            output.innerHTML = '<div class="dd-success">✅ All selectors found in DOM</div>';
        } else {
            output.innerHTML = missing.map(m =>
                `<div class="dd-issue"><div class="dd-issue-title">${m.type}: ${m.name}</div><div class="dd-issue-location">Referenced but not found</div></div>`
            ).join('');
        }
    };

    // ==========================================
    // SECURITY PANEL
    // ==========================================

    DD.runSecurityScan = function() {
        const output = document.getElementById('dd-security-output');
        let html = '';

        // HTTPS Check
        const isHttps = location.protocol === 'https:';
        html += `<div class="dd-security-item">
            <div class="dd-security-label">Protocol</div>
            <div class="dd-security-value ${isHttps ? 'dd-security-good' : 'dd-security-bad'}">${location.protocol} ${isHttps ? '✓ Secure' : '⚠ Not Secure'}</div>
        </div>`;

        // Cookies
        const cookies = document.cookie.split(';').filter(c => c.trim());
        html += `<div class="dd-security-item">
            <div class="dd-security-label">Cookies</div>
            <div class="dd-security-value">${cookies.length} cookies found</div>
        </div>`;

        // LocalStorage
        const lsKeys = Object.keys(localStorage);
        const sensitiveKeys = lsKeys.filter(k => /token|key|secret|password|auth/i.test(k));
        html += `<div class="dd-security-item">
            <div class="dd-security-label">LocalStorage</div>
            <div class="dd-security-value ${sensitiveKeys.length ? 'dd-security-warn' : ''}">${lsKeys.length} items ${sensitiveKeys.length ? `(⚠ ${sensitiveKeys.length} sensitive)` : ''}</div>
        </div>`;

        // External Scripts
        const externalScripts = document.querySelectorAll('script[src]');
        const thirdParty = Array.from(externalScripts).filter(s => {
            try { return new URL(s.src).hostname !== location.hostname; } catch { return false; }
        });
        html += `<div class="dd-security-item">
            <div class="dd-security-label">External Scripts</div>
            <div class="dd-security-value">${externalScripts.length} total, ${thirdParty.length} third-party</div>
        </div>`;

        // Forms without CSRF
        const forms = document.querySelectorAll('form');
        const formsWithoutCsrf = Array.from(forms).filter(f => !f.querySelector('input[name*="csrf"]'));
        html += `<div class="dd-security-item">
            <div class="dd-security-label">Forms</div>
            <div class="dd-security-value ${formsWithoutCsrf.length ? 'dd-security-warn' : ''}">${forms.length} forms ${formsWithoutCsrf.length ? `(⚠ ${formsWithoutCsrf.length} without CSRF)` : ''}</div>
        </div>`;

        // Links with target=_blank without rel=noopener
        const unsafeLinks = document.querySelectorAll('a[target="_blank"]:not([rel*="noopener"])');
        html += `<div class="dd-security-item">
            <div class="dd-security-label">Unsafe Links</div>
            <div class="dd-security-value ${unsafeLinks.length ? 'dd-security-warn' : 'dd-security-good'}">${unsafeLinks.length} links missing rel="noopener"</div>
        </div>`;

        output.innerHTML = html;
    };

    DD.checkCookies = function() {
        const output = document.getElementById('dd-security-output');
        const cookies = document.cookie.split(';').filter(c => c.trim());
        if (cookies.length === 0) {
            output.innerHTML = '<div style="text-align:center;padding:20px;color:#888;">No cookies found</div>';
            return;
        }
        output.innerHTML = cookies.map(c => {
            const [name, value] = c.split('=');
            return `<div class="dd-security-item">
                <div class="dd-security-label">${name.trim()}</div>
                <div class="dd-security-value">${value || '(empty)'}</div>
            </div>`;
        }).join('');
    };

    DD.checkStorage = function() { DD.showLocalStorage(); };

    DD.checkScripts = function() {
        const output = document.getElementById('dd-security-output');
        const scripts = document.querySelectorAll('script[src]');
        output.innerHTML = Array.from(scripts).map(s => `
            <div class="dd-security-item">
                <div class="dd-security-value" style="word-break:break-all;font-size:11px;">${s.src}</div>
            </div>
        `).join('') || '<div style="text-align:center;padding:20px;color:#888;">No external scripts</div>';
    };

    DD.checkForms = function() {
        const output = document.getElementById('dd-security-output');
        const forms = document.querySelectorAll('form');
        output.innerHTML = Array.from(forms).map((f, i) => `
            <div class="dd-security-item">
                <div class="dd-security-label">Form ${i + 1}</div>
                <div class="dd-security-value">
                    Action: ${f.action || '(none)'}<br>
                    Method: ${f.method || 'GET'}<br>
                    Inputs: ${f.querySelectorAll('input').length}
                </div>
            </div>
        `).join('') || '<div style="text-align:center;padding:20px;color:#888;">No forms found</div>';
    };

    DD.checkLinks = function() {
        const output = document.getElementById('dd-security-output');
        const links = document.querySelectorAll('a[href]');
        const external = Array.from(links).filter(a => {
            try { return new URL(a.href).hostname !== location.hostname; } catch { return false; }
        });
        output.innerHTML = `<div style="margin-bottom:12px;color:#888;">External links: ${external.length}</div>` +
            external.slice(0, 20).map(a => `
                <div class="dd-security-item">
                    <div class="dd-security-value" style="font-size:11px;word-break:break-all;">${a.href}</div>
                </div>
            `).join('');
    };

    // ==========================================
    // STORAGE PANEL
    // ==========================================

    DD.showLocalStorage = function() {
        const output = document.getElementById('dd-storage-output');
        const keys = Object.keys(localStorage);
        if (keys.length === 0) {
            output.innerHTML = '<div style="text-align:center;padding:20px;color:#888;">LocalStorage is empty</div>';
            return;
        }
        output.innerHTML = keys.map(k => `
            <div class="dd-security-item">
                <div class="dd-security-label">${k}</div>
                <div class="dd-security-value" style="max-height:60px;overflow:hidden;">${localStorage.getItem(k).substring(0, 200)}</div>
            </div>
        `).join('');
    };

    DD.showSessionStorage = function() {
        const output = document.getElementById('dd-storage-output');
        const keys = Object.keys(sessionStorage);
        if (keys.length === 0) {
            output.innerHTML = '<div style="text-align:center;padding:20px;color:#888;">SessionStorage is empty</div>';
            return;
        }
        output.innerHTML = keys.map(k => `
            <div class="dd-security-item">
                <div class="dd-security-label">${k}</div>
                <div class="dd-security-value" style="max-height:60px;overflow:hidden;">${sessionStorage.getItem(k).substring(0, 200)}</div>
            </div>
        `).join('');
    };

    DD.showCookiesStorage = function() { DD.checkCookies(); };

    // ==========================================
    // NETWORK PANEL
    // ==========================================

    DD.networkRequests = [];

    DD.logNetwork = function(method, url, status, duration) {
        const output = document.getElementById('dd-network-output');
        if (!output) return;

        if (DD.networkRequests.length === 0) output.innerHTML = '';

        const statusClass = status >= 400 ? 'dd-security-bad' : status >= 300 ? 'dd-security-warn' : 'dd-security-good';
        const div = document.createElement('div');
        div.className = 'dd-security-item';
        div.innerHTML = `
            <div class="dd-security-label">${method} <span class="${statusClass}">${status}</span> <span style="color:#888;">${duration}ms</span></div>
            <div class="dd-security-value" style="font-size:11px;word-break:break-all;">${url}</div>
        `;
        output.insertBefore(div, output.firstChild);
        DD.networkRequests.push({ method, url, status, duration });
    };

    DD.clearNetwork = function() {
        DD.networkRequests = [];
        const output = document.getElementById('dd-network-output');
        if (output) output.innerHTML = '<div style="text-align:center;padding:40px;color:#666;"><div style="font-size:48px;margin-bottom:10px;">🌐</div>Network requests will appear here</div>';
    };

    // Intercept fetch
    const originalFetch = window.fetch;
    window.fetch = async function(...args) {
        const start = performance.now();
        const url = typeof args[0] === 'string' ? args[0] : args[0].url;
        const method = args[1]?.method || 'GET';
        try {
            const response = await originalFetch.apply(this, args);
            DD.logNetwork(method, url, response.status, Math.round(performance.now() - start));
            return response;
        } catch (e) {
            DD.logNetwork(method, url, 'ERR', Math.round(performance.now() - start));
            throw e;
        }
    };

    // Intercept XMLHttpRequest
    const originalXHR = window.XMLHttpRequest;
    window.XMLHttpRequest = function() {
        const xhr = new originalXHR();
        let method, url, start;
        const originalOpen = xhr.open;
        const originalSend = xhr.send;
        xhr.open = function(m, u, ...rest) { method = m; url = u; return originalOpen.apply(this, [m, u, ...rest]); };
        xhr.send = function(...args) {
            start = performance.now();
            xhr.addEventListener('loadend', () => DD.logNetwork(method, url, xhr.status || 'ERR', Math.round(performance.now() - start)));
            return originalSend.apply(this, args);
        };
        return xhr;
    };

    // ==========================================
    // EVENT LISTENERS
    // ==========================================

    // Tab switching
    overlay.querySelectorAll('.dd-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            overlay.querySelectorAll('.dd-tab').forEach(t => t.classList.remove('active'));
            overlay.querySelectorAll('.dd-panel').forEach(p => p.classList.remove('active'));
            tab.classList.add('active');
            document.getElementById('dd-panel-' + tab.dataset.tab).classList.add('active');

            if (tab.dataset.tab === 'elements' && DD.elements.length === 0) {
                DD.loadElements();
            }
        });
    });

    // Console input
    document.getElementById('dd-console-input').addEventListener('keydown', e => {
        if (e.key === 'Enter') DD.execConsole();
    });

    // Element selection
    document.getElementById('dd-elements-list').addEventListener('click', e => {
        const item = e.target.closest('.dd-element-item');
        if (item) DD.selectElement(parseInt(item.dataset.index));
    });

    // Style controls
    overlay.querySelectorAll('.dd-style-editor input[type="range"]').forEach(input => {
        input.addEventListener('input', () => {
            const prop = input.dataset.style;
            const unit = input.dataset.unit;
            let value = input.value;

            if (prop === 'opacity') {
                value = value / 100;
                input.nextElementSibling.textContent = `${Math.round(value * 100)}%`;
            } else {
                value = value + unit;
                input.nextElementSibling.textContent = value;
            }

            DD.applyStyle(prop, value);
        });
    });

    overlay.querySelectorAll('.dd-style-editor input[type="color"]').forEach(input => {
        input.addEventListener('input', () => {
            DD.applyStyle(input.dataset.style, input.value);
        });
    });

    // Intercept console methods
    const originalConsole = { log: console.log, error: console.error, warn: console.warn, info: console.info };
    console.log = function(...args) { originalConsole.log.apply(console, args); DD.log(args.join(' '), 'log'); };
    console.error = function(...args) { originalConsole.error.apply(console, args); DD.log(args.join(' '), 'error'); };
    console.warn = function(...args) { originalConsole.warn.apply(console, args); DD.log(args.join(' '), 'warn'); };
    console.info = function(...args) { originalConsole.info.apply(console, args); DD.log(args.join(' '), 'info'); };

    // Catch errors
    window.addEventListener('error', e => DD.log(`${e.message} at ${e.filename}:${e.lineno}`, 'error'));

    // Initial log
    DD.log('Divine Debugger v2.1 loaded. Drag header to move, edges to resize.', 'info');
})();
