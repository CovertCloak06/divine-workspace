/**
 * DVN Code Academy - Code Playground
 * Enhanced code editor with live preview, syntax hints, and error detection
 * ref:index.html, academy.js
 */

class CodePlayground {
  constructor() {
    this.editor = null; // Code editor textarea element
    this.preview = null; // Preview iframe element
    this.currentLanguage = 'html'; // Current editor language (html, css, js)
    this.autoUpdate = true; // Auto-update preview on code change
    this.updateTimeout = null; // Debounce timeout for auto-update
    this.init(); // Initialize playground
  }

  /**
   * Initialize code playground
   */
  init() {
    console.log('🎮 Code Playground initializing...');

    this.editor = document.getElementById('playgroundCode');
    this.preview = document.getElementById('previewFrame');
    this.languageSelector =
      document.getElementById('editorLanguage') || document.querySelector('.editor-language');

    if (!this.editor || !this.preview) {
      console.warn('⚠️ Playground elements not found on this page');
      return;
    }

    this.attachEventListeners();
    this.setupEditor();

    console.log('✅ Code Playground ready');
  }

  /**
   * Attach event listeners
   */
  attachEventListeners() {
    // Language selector
    this.languageSelector?.addEventListener('change', (e) => {
      this.changeLanguage(e.target.value);
    });

    // Code editor input - auto-update preview
    this.editor?.addEventListener('input', () => {
      if (this.autoUpdate) {
        clearTimeout(this.updateTimeout);
        this.updateTimeout = setTimeout(() => {
          this.updatePreview();
        }, 500); // 500ms debounce for smooth typing
      }
    });

    // Tab key support for indentation
    this.editor?.addEventListener('keydown', (e) => {
      if (e.key === 'Tab') {
        e.preventDefault(); // Prevent focus change

        const start = this.editor.selectionStart;
        const end = this.editor.selectionEnd;
        const value = this.editor.value;

        // Insert tab character (2 spaces)
        this.editor.value = value.substring(0, start) + '  ' + value.substring(end);

        // Move cursor after inserted spaces
        this.editor.selectionStart = this.editor.selectionEnd = start + 2;
      }
    });

    // Listen for external code updates (from tutorial engine)
    window.addEventListener('dvn-update-playground', (e) => {
      this.setCode(e.detail.code, e.detail.language);
    });
  }

  /**
   * Setup code editor with default content and styling
   */
  setupEditor() {
    if (!this.editor) {
      return;
    }

    // Add line numbers (simple implementation)
    this.editor.setAttribute('spellcheck', 'false');
    this.editor.setAttribute('autocomplete', 'off');
    this.editor.setAttribute('autocorrect', 'off');
    this.editor.setAttribute('autocapitalize', 'off');

    // Set initial font (monospace)
    this.editor.style.fontFamily = "'Courier New', 'Consolas', monospace";
    this.editor.style.fontSize = '14px';
    this.editor.style.lineHeight = '1.5';
    this.editor.style.tabSize = '2';
  }

  /**
   * Change editor language
   */
  changeLanguage(language) {
    console.log(`🔄 Switching to ${language}`);
    this.currentLanguage = language;

    // Update placeholder or starter code based on language
    const starters = {
      html: '<!-- Write your HTML here -->\n<h1>Hello World</h1>',
      css: '/* Write your CSS here */\nbody {\n  background: #000;\n  color: #0ff;\n}',
      js: '// Write your JavaScript here\nconsole.log("Hello World");',
    };

    if (this.editor && !this.editor.value.trim()) {
      this.editor.value = starters[language] || '';
    }

    this.updatePreview();
  }

  /**
   * Set code in editor programmatically
   */
  setCode(code, language = null) {
    if (this.editor) {
      this.editor.value = code;

      if (language) {
        this.currentLanguage = language;
        if (this.languageSelector) {
          this.languageSelector.value = language;
        }
      }

      this.updatePreview();
    }
  }

  /**
   * Get current code from editor
   */
  getCode() {
    return this.editor?.value || '';
  }

  /**
   * Update preview iframe with current code
   */
  updatePreview() {
    if (!this.preview) {
      return;
    }

    const code = this.getCode();

    // Build full HTML document based on current language
    let fullHTML = '';

    if (this.currentLanguage === 'html') {
      // Direct HTML
      fullHTML = this.buildHTMLDocument(code);
    } else if (this.currentLanguage === 'css') {
      // CSS in style tag
      fullHTML = this.buildHTMLDocument(
        `<style>${code}</style><div class="demo-content"><h1>Styled Content</h1><p>Your CSS is applied to this page.</p></div>`
      );
    } else if (this.currentLanguage === 'js') {
      // JavaScript in script tag
      fullHTML = this
        .buildHTMLDocument(`<div class="console-output" id="consoleOutput"><strong>Console Output:</strong><div id="consoleLog"></div></div><script>
                // Capture console.log
                const originalLog = console.log;
                console.log = function(...args) {
                    const output = document.getElementById('consoleLog');
                    if (output) {
                        output.innerHTML += '<div>' + args.join(' ') + '</div>';
                    }
                    originalLog.apply(console, args);
                };

                try {
                    ${code}
                } catch (error) {
                    document.getElementById('consoleLog').innerHTML += '<div style="color: #f33">Error: ' + error.message + '</div>';
                }
            </script>`);
    }

    // Update iframe
    this.preview.srcdoc = fullHTML;

    // Track code execution
    window.ProgressTracker?.incrementCodeExecutions();
  }

  /**
   * Build complete HTML document for iframe
   */
  buildHTMLDocument(bodyContent) {
    return `
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    * {
                        margin: 0;
                        padding: 0;
                        box-sizing: border-box;
                    }
                    body {
                        font-family: Arial, sans-serif;
                        padding: 20px;
                        background: #fff;
                        color: #000;
                    }
                    .demo-content {
                        padding: 20px;
                    }
                    .console-output {
                        background: #1a1a1a;
                        color: #0f0;
                        padding: 15px;
                        border-radius: 6px;
                        font-family: 'Courier New', monospace;
                        font-size: 14px;
                        min-height: 100px;
                    }
                    #consoleLog div {
                        margin: 5px 0;
                        padding: 3px 0;
                        border-bottom: 1px solid #333;
                    }
                </style>
            </head>
            <body>
                ${bodyContent}
            </body>
            </html>
        `;
  }

  /**
   * Clear editor content
   */
  clear() {
    if (this.editor) {
      this.editor.value = '';
      this.updatePreview();
    }
  }

  /**
   * Format code (basic indentation)
   */
  formatCode() {
    if (!this.editor) {
      return;
    }

    let code = this.getCode();

    // Basic HTML formatting
    if (this.currentLanguage === 'html') {
      code = this.formatHTML(code);
    }

    this.setCode(code);
  }

  /**
   * Basic HTML formatter
   */
  formatHTML(html) {
    let formatted = '';
    let indent = 0;
    const tab = '  ';

    // Remove existing indentation
    html = html.replace(/^\s+/gm, '');

    // Split by tags
    const parts = html.split(/(<[^>]+>)/g);

    parts.forEach((part) => {
      if (!part.trim()) {
        return;
      }

      if (part.match(/<\/[\w]+>/)) {
        // Closing tag - decrease indent first
        indent = Math.max(0, indent - 1);
        formatted += tab.repeat(indent) + part + '\n';
      } else if (part.match(/<[\w]+[^>]*\/>/)) {
        // Self-closing tag
        formatted += tab.repeat(indent) + part + '\n';
      } else if (part.match(/<[\w]+[^>]*>/)) {
        // Opening tag - add indent after
        formatted += tab.repeat(indent) + part + '\n';
        indent++;
      } else {
        // Text content
        formatted += tab.repeat(indent) + part.trim() + '\n';
      }
    });

    return formatted.trim();
  }

  /**
   * Toggle auto-update preview
   */
  toggleAutoUpdate() {
    this.autoUpdate = !this.autoUpdate;
    console.log(`Auto-update: ${this.autoUpdate ? 'ON' : 'OFF'}`);
    return this.autoUpdate;
  }

  /**
   * Download current code as file
   */
  downloadCode() {
    const code = this.getCode();
    const extension =
      {
        html: 'html',
        css: 'css',
        js: 'js',
      }[this.currentLanguage] || 'txt';

    const blob = new Blob([code], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);

    const link = document.createElement('a');
    link.href = url;
    link.download = `code.${extension}`;
    link.click();

    URL.revokeObjectURL(url);
    console.log(`📥 Downloaded code.${extension}`);
  }

  /**
   * Share code (copy to clipboard)
   */
  async shareCode() {
    const code = this.getCode();

    try {
      await navigator.clipboard.writeText(code);
      alert('✅ Code copied to clipboard!');
    } catch (error) {
      console.error('Failed to copy code:', error);
      alert('❌ Failed to copy code. Please copy manually.');
    }
  }

  /**
   * Load example code for current language
   */
  loadExample(exampleId) {
    const examples = {
      html: {
        basic: '<h1>My Page</h1>\n<p>Welcome to my website!</p>',
        form: '<form>\n  <label>Name:</label>\n  <input type="text" name="name">\n  <button>Submit</button>\n</form>',
        list: '<ul>\n  <li>Item 1</li>\n  <li>Item 2</li>\n  <li>Item 3</li>\n</ul>',
      },
      css: {
        basic: 'body {\n  background: #000;\n  color: #0ff;\n  font-family: Arial;\n}',
        flexbox:
          '.container {\n  display: flex;\n  justify-content: center;\n  align-items: center;\n  min-height: 100vh;\n}',
        gradient:
          '.box {\n  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);\n  padding: 30px;\n  border-radius: 12px;\n}',
      },
      js: {
        basic: 'console.log("Hello World!");',
        loop: 'for (let i = 1; i <= 5; i++) {\n  console.log("Count: " + i);\n}',
        function:
          'function greet(name) {\n  return "Hello, " + name + "!";\n}\n\nconsole.log(greet("World"));',
      },
    };

    const example = examples[this.currentLanguage]?.[exampleId];
    if (example) {
      this.setCode(example);
    }
  }
}

// Create global instance
window.CodePlayground = new CodePlayground();
