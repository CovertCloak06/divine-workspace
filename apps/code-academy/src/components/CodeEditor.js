/**
 * Code Editor Component
 * Provides a code editing textarea with live validation and syntax checking
 * Self-contained component with validation feedback
 */

import { validateCode } from '../utils/validators.js';

class CodeEditor {
  /**
   * Creates a code editor component instance
   * @param {HTMLElement} container - Container element to render into
   * @param {Object} task - Task configuration object
   * @param {string} [task.starter] - Initial code to populate editor
   * @param {string} task.validate - Validation function as string
   * @param {Array<string>} [task.expectedContent] - Expected content (fallback validation)
   * @param {string} [task.solution] - Solution code (for hints)
   * @param {Function} onComplete - Callback when code is validated successfully
   * @param {Function} [onCodeChange] - Callback when code changes (for preview updates)
   */
  constructor(container, task, onComplete, onCodeChange) {
    this.container = container;
    this.task = task;
    this.onComplete = onComplete;
    this.onCodeChange = onCodeChange;
    this.state = {
      code: task.starter || '',
      isValid: false,
      hasChecked: false,
    };

    this.render();
    this.attachListeners();
  }

  /**
   * Renders code editor HTML into container
   * @private
   */
  render() {
    this.container.innerHTML = `
      <textarea
        class="code-editor"
        id="codeInput"
        rows="4"
        spellcheck="false"
        placeholder="Type your code here..."
      >${this.state.code}</textarea>
      <button class="btn-primary check-btn" id="checkCode">
        ✓ Check My Code
      </button>
    `;
  }

  /**
   * Attaches event listeners
   * @private
   */
  attachListeners() {
    const codeInput = this.container.querySelector('#codeInput');
    const checkBtn = this.container.querySelector('#checkCode');

    // Live validation as user types | Provides immediate feedback
    codeInput.addEventListener('input', () => {
      this.handleInput(codeInput.value);
    });

    // Check button validates and completes task
    checkBtn.addEventListener('click', () => {
      this.checkCode();
    });
  }

  /**
   * Handles code input changes
   * @param {string} code - Current code value
   * @private
   */
  handleInput(code) {
    this.state.code = code;

    // Notify parent of code change (for live preview) | ref:TutorialEngine.js stepCode tracking
    if (this.onCodeChange) {
      this.onCodeChange(code);
    }

    // Validate code live
    const isValid = validateCode(code, this.task);
    this.state.isValid = isValid;

    // Show live feedback (without completing task)
    this.showLiveFeedback(code, isValid);
  }

  /**
   * Shows live validation feedback as user types
   * @param {string} code - Current code
   * @param {boolean} isValid - Whether code is valid
   * @private
   */
  showLiveFeedback(code, isValid) {
    const feedback = document.getElementById('taskFeedback');

    if (!feedback) {
      return;
    }

    if (code.trim().length === 0) {
      feedback.className = 'task-feedback';
      feedback.innerHTML = '';
      return;
    }

    if (isValid) {
      feedback.className = 'task-feedback success';
      feedback.innerHTML = '✅ Looks good! Click "Check My Code" to continue.';
    } else {
      feedback.className = 'task-feedback error';
      feedback.innerHTML = '❌ Keep trying... Check the hint if stuck!';
    }
  }

  /**
   * Validates code and triggers completion if valid
   */
  checkCode() {
    const isValid = validateCode(this.state.code, this.task);

    this.state.isValid = isValid;
    this.state.hasChecked = true;

    const feedback = document.getElementById('taskFeedback');

    if (isValid) {
      if (feedback) {
        feedback.className = 'task-feedback success';
        feedback.innerHTML = '✅ Perfect! Your code is correct!';
      }

      // Trigger completion callback | ref:TutorialEngine.js nextStep()
      if (this.onComplete) {
        this.onComplete(this.state.code);
      }
    } else {
      if (feedback) {
        feedback.className = 'task-feedback error';
        feedback.innerHTML = "❌ Not quite right. Check the hint if you're stuck!";
      }
    }
  }

  /**
   * Gets current code value
   * @returns {string} Current code
   */
  getCode() {
    return this.state.code;
  }

  /**
   * Sets code value programmatically
   * @param {string} code - Code to set
   */
  setCode(code) {
    this.state.code = code;
    const codeInput = this.container.querySelector('#codeInput');

    if (codeInput) {
      codeInput.value = code;
      this.handleInput(code);
    }
  }

  /**
   * Checks if current code is valid
   * @returns {boolean} True if code is valid
   */
  isValid() {
    return this.state.isValid;
  }

  /**
   * Resets editor to initial state
   */
  reset() {
    this.state = {
      code: this.task.starter || '',
      isValid: false,
      hasChecked: false,
    };

    const codeInput = this.container.querySelector('#codeInput');
    if (codeInput) {
      codeInput.value = this.state.code;
    }

    // Clear feedback
    const feedback = document.getElementById('taskFeedback');
    if (feedback) {
      feedback.className = 'task-feedback';
      feedback.innerHTML = '';
    }
  }

  /**
   * Gets component state
   * @returns {Object} Current state
   */
  getState() {
    return { ...this.state };
  }

  /**
   * Destroys component and cleans up
   */
  destroy() {
    this.container.innerHTML = '';
    this.state = null;
  }
}

export default CodeEditor;
