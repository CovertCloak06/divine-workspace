/**
 * Task Renderer Component
 * Handles rendering different task types and managing task state
 * Dispatches to specific task components based on task.type
 */

import QuizComponent from './QuizComponent.js';
import CodeEditor from './CodeEditor.js';

class TaskRenderer {
  /**
   * Creates a task renderer instance
   * @param {HTMLElement} container - Container element for tasks
   * @param {Function} onTaskComplete - Callback when task is completed
   */
  constructor(container, onTaskComplete) {
    this.container = container;
    this.onTaskComplete = onTaskComplete;
    this.currentComponent = null; // Active task component instance
    this.currentTask = null; // Current task data
    this.stepCode = {}; // Storage for code from all steps | ref:TutorialEngine.js stepCode
  }

  /**
   * Renders a task based on its type
   * @param {Object} task - Task configuration object
   * @param {string} task.type - Task type ('code' | 'quiz' | 'completion' | etc.)
   * @param {string} [task.instruction] - Task instruction text
   * @param {string} [task.hint] - Hint text
   * @param {number} currentStep - Current step index (for code storage)
   */
  render(task, currentStep) {
    // Clean up previous component | Prevent memory leaks
    if (this.currentComponent && this.currentComponent.destroy) {
      this.currentComponent.destroy();
    }

    this.currentTask = task;

    // Update instruction text
    this.updateInstruction(task.instruction);

    // Update hint button visibility
    this.updateHintButton(task.hint);

    // Dispatch to appropriate renderer based on task type
    switch (task.type) {
      case 'code':
        this.renderCodeTask(task, currentStep);
        break;

      case 'quiz':
        this.renderQuizTask(task);
        break;

      case 'completion':
        this.renderCompletionTask(task);
        break;

      case 'info':
        this.renderInfoTask(task);
        break;

      // TODO: Add other task types as needed
      // case 'slider':
      // case 'visual-adjuster':
      // case 'guided-code':
      // case 'challenge':
      // case 'terminal-command':

      default:
        this.renderUnknownTask(task);
    }
  }

  /**
   * Renders code editor task
   * @param {Object} task - Code task configuration
   * @param {number} currentStep - Current step index
   * @private
   */
  renderCodeTask(task, currentStep) {
    const taskArea = document.getElementById('taskArea');

    this.currentComponent = new CodeEditor(
      taskArea,
      task,
      (code) => {
        // Store code for this step | Used for preview and completion validation
        this.stepCode[currentStep] = code;

        // Enable next button and trigger completion
        document.getElementById('nextStep').disabled = false;

        // Notify parent | ref:TutorialEngine.js nextStep()
        if (this.onTaskComplete) {
          this.onTaskComplete(true, code);
        }
      },
      (code) => {
        // Code changed callback | Store code as user types
        this.stepCode[currentStep] = code;
      }
    );
  }

  /**
   * Renders quiz task
   * @param {Object} task - Quiz task configuration
   * @private
   */
  renderQuizTask(task) {
    const taskArea = document.getElementById('taskArea');

    this.currentComponent = new QuizComponent(taskArea, task, (isCorrect) => {
      // Enable next button on correct answer
      document.getElementById('nextStep').disabled = !isCorrect;

      // Notify parent
      if (this.onTaskComplete) {
        this.onTaskComplete(isCorrect);
      }
    });
  }

  /**
   * Renders completion task
   * @param {Object} task - Completion task configuration
   * @private
   */
  renderCompletionTask(task) {
    const taskArea = document.getElementById('taskArea');

    // Check if user actually completed code tasks
    const hasValidCode = Object.keys(this.stepCode).length > 0;

    if (!hasValidCode) {
      taskArea.innerHTML = `
        <div class="completion-message">
          <div class="completion-icon">⚠️</div>
          <p style="color: var(--error);">
            You need to complete the coding tasks above before finishing!
          </p>
          <p>Go back and make sure your code passes validation.</p>
        </div>
      `;
      document.getElementById('nextStep').disabled = true;
    } else {
      taskArea.innerHTML = `
        <div class="completion-message">
          <div class="completion-icon">🎉</div>
          <p>${task.instruction}</p>
        </div>
      `;
      document.getElementById('nextStep').disabled = false;

      // Notify parent that lesson is ready to complete
      if (this.onTaskComplete) {
        this.onTaskComplete(true);
      }
    }
  }

  /**
   * Renders info task (informational only, no interaction)
   * @param {Object} task - Info task configuration
   * @private
   */
  renderInfoTask(task) {
    const taskArea = document.getElementById('taskArea');

    taskArea.innerHTML = `
      <div class="info-message">
        <p>${task.content || task.instruction}</p>
      </div>
    `;

    // Auto-enable next button for info tasks
    document.getElementById('nextStep').disabled = false;

    if (this.onTaskComplete) {
      this.onTaskComplete(true);
    }
  }

  /**
   * Renders fallback for unknown task types
   * @param {Object} task - Task configuration
   * @private
   */
  renderUnknownTask(task) {
    const taskArea = document.getElementById('taskArea');

    taskArea.innerHTML = `
      <div class="error-message">
        <p>⚠️ Unknown task type: <code>${task.type}</code></p>
        <p>This task type needs to be implemented.</p>
      </div>
    `;

    console.warn(`Unknown task type: ${task.type}`, task);
  }

  /**
   * Updates instruction text
   * @param {string} instruction - Instruction text
   * @private
   */
  updateInstruction(instruction) {
    const instructionEl = document.getElementById('taskInstruction');

    if (instructionEl) {
      instructionEl.textContent = instruction || 'Your Task:';
    }
  }

  /**
   * Updates hint button visibility and content
   * @param {string} hint - Hint text
   * @private
   */
  updateHintButton(hint) {
    const hintBtn = document.getElementById('showHint');
    const hintText = document.getElementById('hintText');

    if (hint) {
      if (hintText) {
        hintText.textContent = hint;
      }

      if (hintBtn) {
        hintBtn.style.display = 'block';
      }
    } else {
      if (hintText) {
        hintText.textContent = '';
      }

      if (hintBtn) {
        hintBtn.style.display = 'none';
      }
    }
  }

  /**
   * Gets all stored code from completed steps
   * @returns {Object} Map of step index to code
   */
  getStepCode() {
    return { ...this.stepCode };
  }

  /**
   * Clears all stored code
   */
  clearStepCode() {
    this.stepCode = {};
  }

  /**
   * Gets current task component instance
   * @returns {Object|null} Current component or null
   */
  getCurrentComponent() {
    return this.currentComponent;
  }

  /**
   * Destroys renderer and cleans up
   */
  destroy() {
    if (this.currentComponent && this.currentComponent.destroy) {
      this.currentComponent.destroy();
    }

    this.currentComponent = null;
    this.currentTask = null;
    this.stepCode = {};
  }
}

export default TaskRenderer;
