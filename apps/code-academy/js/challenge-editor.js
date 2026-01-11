/**
 * Challenge Editor Component for DVN Code Academy
 * Tier 3 (Advanced) - Full code editor with requirements checklist
 */

class ChallengeEditor {
  constructor(taskData, taskArea, onComplete) {
    this.taskData = taskData;
    this.taskArea = taskArea;
    this.onComplete = onComplete;
    this.htmlCode = taskData.htmlStarter || '';
    this.cssCode = taskData.cssStarter || '';
    this.jsCode = taskData.jsStarter || '';
    this.currentTab = 'html';
    this.autoSaveTimer = null;

    this.render();
  }

  render() {
    this.taskArea.innerHTML = `
            <div class="challenge-editor">
                <!-- Requirements Checklist -->
                <div class="challenge-requirements">
                    <div class="requirements-header">
                        <strong>📋 Requirements:</strong>
                        <button id="toggleRequirements" class="btn-text">Hide</button>
                    </div>
                    <ul id="requirementsList">
                        ${this.taskData.requirements
                          .map(
                            (req, i) =>
                              `<li id="req-${i}" class="requirement-item">
                                <span class="req-checkbox">☐</span>
                                <span class="req-text">${req}</span>
                            </li>`
                          )
                          .join('')}
                    </ul>
                </div>

                <!-- Code Editor -->
                <div class="challenge-code-section">
                    <!-- Editor Tabs -->
                    <div class="challenge-tabs">
                        <button class="challenge-tab active" data-tab="html">HTML</button>
                        <button class="challenge-tab" data-tab="css">CSS</button>
                        <button class="challenge-tab ${this.taskData.jsStarter ? '' : 'disabled'}" data-tab="js">
                            JavaScript
                        </button>
                        <div class="tab-spacer"></div>
                        <button id="viewSolution" class="btn-text hint-btn">👁 View Solution</button>
                    </div>

                    <!-- Code Editor Area -->
                    <div class="challenge-editor-area">
                        <textarea
                            id="challengeCodeEditor"
                            class="code-editor-textarea"
                            spellcheck="false"
                            placeholder="Write your code here..."
                        >${this.htmlCode}</textarea>
                    </div>

                    <!-- Editor Actions -->
                    <div class="challenge-actions">
                        <button id="formatCode" class="btn-secondary">
                            ⚡ Format Code
                        </button>
                        <button id="runChallenge" class="btn-primary">
                            ▶ Run & Check
                        </button>
                    </div>
                </div>

                <!-- Live Preview -->
                <div class="challenge-preview-section">
                    <div class="preview-header">
                        <strong>Live Preview</strong>
                        <button id="refreshPreview" class="btn-text">🔄 Refresh</button>
                    </div>
                    <div id="challengePreviewFrame" class="preview-frame">
                        <!-- Live preview renders here -->
                    </div>
                </div>

                <!-- Feedback & Hints -->
                <div id="challengeFeedback" class="task-feedback"></div>

                <div class="challenge-hints" id="challengeHints" style="display: none;">
                    <strong>💡 Hints:</strong>
                    <ul>
                        ${this.taskData.hints.map((hint) => `<li>${hint}</li>`).join('')}
                    </ul>
                </div>
            </div>
        `;

    this.attachListeners();
    this.updatePreview();
  }

  attachListeners() {
    const editor = document.getElementById('challengeCodeEditor');

    // Tab switching
    this.taskArea.querySelectorAll('.challenge-tab:not(.disabled)').forEach((tab) => {
      tab.addEventListener('click', (e) => {
        const newTab = e.target.dataset.tab;
        this.switchTab(newTab);
      });
    });

    // Code editor changes
    editor?.addEventListener('input', (e) => {
      this.saveCode(this.currentTab, e.target.value);

      // Auto-update preview with debounce
      clearTimeout(this.autoSaveTimer);
      this.autoSaveTimer = setTimeout(() => {
        this.updatePreview();
      }, 500);
    });

    // Tab key support
    editor?.addEventListener('keydown', (e) => {
      if (e.key === 'Tab') {
        e.preventDefault();
        const start = e.target.selectionStart;
        const end = e.target.selectionEnd;
        const value = e.target.value;

        // Insert 2 spaces
        e.target.value = value.substring(0, start) + '  ' + value.substring(end);
        e.target.selectionStart = e.target.selectionEnd = start + 2;

        this.saveCode(this.currentTab, e.target.value);
      }
    });

    // Toggle requirements
    document.getElementById('toggleRequirements')?.addEventListener('click', (e) => {
      const list = document.getElementById('requirementsList');
      if (list.style.display === 'none') {
        list.style.display = 'block';
        e.target.textContent = 'Hide';
      } else {
        list.style.display = 'none';
        e.target.textContent = 'Show';
      }
    });

    // View solution
    document.getElementById('viewSolution')?.addEventListener('click', () => {
      this.showSolution();
    });

    // Format code
    document.getElementById('formatCode')?.addEventListener('click', () => {
      this.formatCode();
    });

    // Run & Check
    document.getElementById('runChallenge')?.addEventListener('click', () => {
      this.runChallenge();
    });

    // Refresh preview
    document.getElementById('refreshPreview')?.addEventListener('click', () => {
      this.updatePreview();
    });
  }

  switchTab(tab) {
    // Save current code
    const editor = document.getElementById('challengeCodeEditor');
    this.saveCode(this.currentTab, editor.value);

    // Update active tab
    this.currentTab = tab;
    this.taskArea.querySelectorAll('.challenge-tab').forEach((t) => {
      t.classList.toggle('active', t.dataset.tab === tab);
    });

    // Load new code
    let code = '';
    if (tab === 'html') {
      code = this.htmlCode;
    } else if (tab === 'css') {
      code = this.cssCode;
    } else if (tab === 'js') {
      code = this.jsCode;
    }

    editor.value = code;
  }

  saveCode(tab, code) {
    if (tab === 'html') {
      this.htmlCode = code;
    } else if (tab === 'css') {
      this.cssCode = code;
    } else if (tab === 'js') {
      this.jsCode = code;
    }
  }

  updatePreview() {
    const previewFrame = document.getElementById('challengePreviewFrame');
    if (!previewFrame) {
      return;
    }

    // Build complete HTML document
    const fullHTML = `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    ${this.cssCode}
                </style>
            </head>
            <body>
                ${this.htmlCode}
                <script>
                    try {
                        ${this.jsCode}
                    } catch (e) {
                        console.error('JavaScript error:', e);
                    }
                </script>
            </body>
            </html>
        `;

    // Create iframe for preview
    previewFrame.innerHTML = '<iframe class="preview-iframe" sandbox="allow-scripts"></iframe>';
    const iframe = previewFrame.querySelector('iframe');
    iframe.contentDocument.open();
    iframe.contentDocument.write(fullHTML);
    iframe.contentDocument.close();
  }

  formatCode() {
    const editor = document.getElementById('challengeCodeEditor');
    const code = editor.value;

    // Basic formatting (can be enhanced)
    if (this.currentTab === 'html' || this.currentTab === 'css') {
      // Simple indentation fix
      const lines = code.split('\n');
      let indentLevel = 0;
      const formatted = lines
        .map((line) => {
          const trimmed = line.trim();
          if (!trimmed) {
            return '';
          }

          // Decrease indent for closing tags
          if (trimmed.startsWith('</') || trimmed.startsWith('}')) {
            indentLevel = Math.max(0, indentLevel - 1);
          }

          const indented = '  '.repeat(indentLevel) + trimmed;

          // Increase indent for opening tags
          if (trimmed.match(/<[^/>]+>$/) || trimmed.endsWith('{')) {
            indentLevel++;
          }

          return indented;
        })
        .join('\n');

      editor.value = formatted;
      this.saveCode(this.currentTab, formatted);
    }
  }

  runChallenge() {
    const feedback = document.getElementById('challengeFeedback');

    // Run validation function if provided
    if (this.taskData.validate) {
      try {
        const validateFn = eval(this.taskData.validate);
        const passed = validateFn(this.htmlCode, this.cssCode, this.jsCode);

        if (passed) {
          // Check individual requirements
          this.checkRequirements();

          feedback.innerHTML = `
                        <div class="feedback-success">
                            ✓ Excellent work! Your code passes all validations. Click "Next" to continue.
                        </div>
                    `;
          this.onComplete(true);
        } else {
          feedback.innerHTML = `
                        <div class="feedback-warning">
                            ⚠ Your code runs, but doesn't meet all requirements yet. Check the list above!
                        </div>
                    `;
          this.checkRequirements();
        }
      } catch (e) {
        console.error('Validation error:', e);
        feedback.innerHTML = `
                    <div class="feedback-error">
                        ✗ Error checking your code. Make sure your syntax is correct!
                    </div>
                `;
      }
    } else {
      // No validation function - mark as complete
      feedback.innerHTML = `
                <div class="feedback-success">
                    ✓ Code submitted! Click "Next" when you're ready to continue.
                </div>
            `;
      this.onComplete(true);
    }

    this.updatePreview();
  }

  checkRequirements() {
    // Simple requirement checking based on code content
    const allCode = this.htmlCode + this.cssCode + this.jsCode;

    this.taskData.requirements.forEach((req, index) => {
      const reqEl = document.getElementById(`req-${index}`);
      const checkbox = reqEl?.querySelector('.req-checkbox');

      // Basic checks (can be enhanced with regex patterns)
      let met = false;
      if (req.toLowerCase().includes('must have') || req.toLowerCase().includes('should have')) {
        // Extract expected content
        const matches = req.match(/['"`]([^'"`]+)['"`]/g);
        if (matches) {
          met = matches.every((match) => allCode.includes(match.replace(/['"`]/g, '')));
        } else {
          met = true; // Can't auto-check, assume met
        }
      } else {
        met = true; // Can't auto-check
      }

      if (checkbox) {
        checkbox.textContent = met ? '☑' : '☐';
        reqEl.classList.toggle('req-met', met);
      }
    });
  }

  showSolution() {
    const hintsDiv = document.getElementById('challengeHints');

    if (confirm('Are you sure? Viewing the solution will give you the answer!')) {
      const solutionHTML = this.taskData.solution || 'No solution available';

      hintsDiv.innerHTML = `
                <strong>💡 Solution:</strong>
                <pre class="solution-code">${this.escapeHtml(solutionHTML)}</pre>
                <button id="copySolution" class="btn-secondary" style="margin-top: 10px;">
                    📋 Copy Solution
                </button>
            `;
      hintsDiv.style.display = 'block';

      document.getElementById('copySolution')?.addEventListener('click', () => {
        navigator.clipboard.writeText(solutionHTML);
        alert('Solution copied to clipboard!');
      });
    }
  }

  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
}

// Export for use in tutorial engine
window.ChallengeEditor = ChallengeEditor;
