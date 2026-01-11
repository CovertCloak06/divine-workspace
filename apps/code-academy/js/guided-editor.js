/**
 * Guided Code Editor Component for DVN Code Academy
 * Tier 2 (Intermediate) - Fill-in-the-blanks with locked code sections
 */

class GuidedEditor {
  constructor(taskData, taskArea, onComplete) {
    this.taskData = taskData;
    this.taskArea = taskArea;
    this.onComplete = onComplete;
    this.blankValues = {};

    // Initialize blank values
    taskData.blanks.forEach((blank, index) => {
      this.blankValues[blank.id || `blank${index + 1}`] = '';
    });

    this.render();
  }

  render() {
    this.taskArea.innerHTML = `
            <div class="guided-editor">
                <!-- Code Template with Blanks -->
                <div class="guided-code-container">
                    ${this.renderCodeTemplate()}
                </div>

                <!-- Hints Section (initially hidden) -->
                <div class="guided-hints" id="guidedHints" style="display: none;">
                    <strong>💡 Hints:</strong>
                    <ul id="hintsList"></ul>
                </div>

                <!-- Action Buttons -->
                <div class="guided-actions">
                    <button id="showGuidedHints" class="btn-secondary">
                        💡 Show Hints
                    </button>
                    <button id="checkGuidedCode" class="btn-primary">
                        ✓ Check Code
                    </button>
                </div>

                <!-- Live Preview (if applicable) -->
                <div class="guided-preview" id="guidedPreview">
                    <div class="preview-label">Preview:</div>
                    <div id="guidedPreviewFrame"></div>
                </div>

                <!-- Feedback -->
                <div id="guidedFeedback" class="task-feedback"></div>
            </div>
        `;

    this.attachListeners();
  }

  renderCodeTemplate() {
    const lines = this.taskData.template.split('\n');
    let html = '<div class="code-editor-locked">';
    let blankIndex = 0;

    lines.forEach((line, lineNum) => {
      html += '<div class="code-line">';
      html += `<span class="line-number">${lineNum + 1}</span>`;

      // Check if line contains a blank (marked with ___)
      if (line.includes('___')) {
        const parts = line.split('___');
        parts.forEach((part, i) => {
          if (i > 0) {
            const blank = this.taskData.blanks[blankIndex];
            const blankId = blank.id || `blank${blankIndex + 1}`;

            html += this.renderBlankInput(blank, blankId);
            blankIndex++;
          }
          html += `<span class="code-text locked">${this.escapeHtml(part)}</span>`;
        });
      } else {
        html += `<span class="code-text locked">${this.escapeHtml(line)}</span>`;
      }

      html += '</div>';
    });

    html += '</div>';
    return html;
  }

  renderBlankInput(blank, blankId) {
    const hasAutocomplete = blank.autocomplete && blank.autocomplete.length > 0;
    const inputType = blank.type === 'number' ? 'number' : 'text';
    const autocompleteAttr = hasAutocomplete ? 'list="' + blankId + '-list"' : '';

    let html = `
            <input
                type="${inputType}"
                class="code-blank"
                data-blank-id="${blankId}"
                placeholder="..."
                ${autocompleteAttr}
                spellcheck="false"
            />
        `;

    if (hasAutocomplete) {
      html += `<datalist id="${blankId}-list">`;
      blank.autocomplete.forEach((option) => {
        html += `<option value="${option}">`;
      });
      html += '</datalist>';
    }

    return html;
  }

  attachListeners() {
    // Blank input changes
    this.taskArea.querySelectorAll('.code-blank').forEach((input) => {
      input.addEventListener('input', (e) => {
        const blankId = e.target.dataset.blankId;
        this.blankValues[blankId] = e.target.value;
        this.updatePreview();
      });

      // Auto-advance on Enter
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          const blanks = Array.from(this.taskArea.querySelectorAll('.code-blank'));
          const currentIndex = blanks.indexOf(input);
          if (currentIndex < blanks.length - 1) {
            blanks[currentIndex + 1].focus();
          } else {
            this.checkCode();
          }
        }
      });
    });

    // Show hints button
    document.getElementById('showGuidedHints')?.addEventListener('click', () => {
      this.showHints();
    });

    // Check code button
    document.getElementById('checkGuidedCode')?.addEventListener('click', () => {
      this.checkCode();
    });
  }

  showHints() {
    const hintsContainer = document.getElementById('guidedHints');
    const hintsList = document.getElementById('hintsList');

    if (hintsContainer.style.display === 'none') {
      hintsList.innerHTML = this.taskData.blanks.map((blank) => `<li>${blank.hint}</li>`).join('');
      hintsContainer.style.display = 'block';
    } else {
      hintsContainer.style.display = 'none';
    }
  }

  updatePreview() {
    // Build complete code by replacing blanks with values
    let code = this.taskData.template;

    this.taskData.blanks.forEach((blank, index) => {
      const blankId = blank.id || `blank${index + 1}`;
      const value = this.blankValues[blankId] || '___';
      code = code.replace('___', value);
    });

    // Update preview if it's CSS/HTML
    const previewFrame = document.getElementById('guidedPreviewFrame');
    if (previewFrame && code) {
      // Simple HTML preview (can be enhanced)
      previewFrame.innerHTML = `<pre class="code-preview">${this.escapeHtml(code)}</pre>`;
    }
  }

  checkCode() {
    const feedback = document.getElementById('guidedFeedback');
    let allCorrect = true;
    const incorrectBlanks = [];

    this.taskData.blanks.forEach((blank, index) => {
      const blankId = blank.id || `blank${index + 1}`;
      const userValue = this.blankValues[blankId].trim().toLowerCase();
      const correctValue = blank.answer.toLowerCase();

      if (userValue !== correctValue) {
        allCorrect = false;
        incorrectBlanks.push({
          id: blankId,
          hint: blank.hint,
        });
      }
    });

    if (allCorrect) {
      // Build final code
      let finalCode = this.taskData.template;
      this.taskData.blanks.forEach((blank, index) => {
        const blankId = blank.id || `blank${index + 1}`;
        finalCode = finalCode.replace('___', this.blankValues[blankId]);
      });

      // Validate with custom function if provided
      let passesValidation = true;
      if (this.taskData.validate) {
        try {
          const validateFn = eval(this.taskData.validate);
          passesValidation = validateFn(finalCode);
        } catch (e) {
          console.error('Validation error:', e);
        }
      }

      if (passesValidation) {
        feedback.innerHTML = `
                    <div class="feedback-success">
                        ✓ Perfect! Your code is correct. Click "Next" to continue.
                    </div>
                `;
        this.onComplete(true);
      } else {
        feedback.innerHTML = `
                    <div class="feedback-warning">
                        ⚠ The blanks are filled correctly, but the code doesn't quite work. Double-check your syntax!
                    </div>
                `;
      }
    } else {
      feedback.innerHTML = `
                <div class="feedback-error">
                    ✗ Some blanks are incorrect. Try again!
                    ${incorrectBlanks.length <= 2 ? '<br><small>Hint: ' + incorrectBlanks.map((b) => b.hint).join(', ') + '</small>' : ''}
                </div>
            `;
    }
  }

  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
}

// Export for use in tutorial engine
window.GuidedEditor = GuidedEditor;
