/**
 * Quiz Component
 * Renders multiple choice questions with feedback
 * Self-contained component with own state and event handling
 */

class QuizComponent {
  /**
   * Creates a quiz component instance
   * @param {HTMLElement} container - Container element to render into
   * @param {Object} task - Task configuration object
   * @param {string} task.question - Quiz question text
   * @param {Array<Object>} task.options - Array of answer options
   * @param {string} task.options[].text - Option text
   * @param {boolean} task.options[].correct - Whether option is correct
   * @param {string} [task.instruction] - Optional instruction text
   * @param {Function} onComplete - Callback when quiz is answered correctly
   */
  constructor(container, task, onComplete) {
    this.container = container;
    this.task = task;
    this.onComplete = onComplete;
    this.state = {
      answered: false,
      selectedIndex: null,
      isCorrect: false,
    };

    this.render();
    this.attachListeners();
  }

  /**
   * Renders quiz HTML into container
   * @private
   */
  render() {
    const { instruction, question, options } = this.task;

    this.container.innerHTML = `
      ${instruction ? `<div class="task-instruction">${instruction}</div>` : ''}
      <div class="quiz-question">${question}</div>
      <div class="quiz-options">
        ${options
          .map(
            (opt, i) => `
          <button
            class="quiz-option"
            data-index="${i}"
            data-correct="${opt.correct}"
          >
            ${opt.text}
          </button>
        `
          )
          .join('')}
      </div>
    `;
  }

  /**
   * Attaches event listeners to quiz buttons
   * @private
   */
  attachListeners() {
    this.container.querySelectorAll('.quiz-option').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        this.handleAnswer(e.target);
      });
    });
  }

  /**
   * Handles quiz answer selection
   * @param {HTMLElement} button - Clicked button element
   * @private
   */
  handleAnswer(button) {
    // Ignore if already answered
    if (this.state.answered) {
      return;
    }

    const selectedIndex = parseInt(button.dataset.index);
    const isCorrect = button.dataset.correct === 'true';

    // Update state
    this.state.answered = true;
    this.state.selectedIndex = selectedIndex;
    this.state.isCorrect = isCorrect;

    // Disable all options and highlight correct answer
    this.container.querySelectorAll('.quiz-option').forEach((btn) => {
      btn.disabled = true;

      // Highlight correct answer
      if (btn.dataset.correct === 'true') {
        btn.classList.add('correct');
      }
    });

    // Add visual feedback to selected answer
    if (isCorrect) {
      button.classList.add('selected-correct');
      this.showFeedback('✅ Correct! Well done!', 'success');

      // Trigger completion callback | ref:TutorialEngine.js nextStep()
      if (this.onComplete) {
        this.onComplete(true);
      }
    } else {
      button.classList.add('selected-wrong');
      this.showFeedback('❌ Not quite. The correct answer is highlighted.', 'error');

      // Still call callback but with false | Allows engine to decide behavior
      if (this.onComplete) {
        this.onComplete(false);
      }
    }
  }

  /**
   * Shows feedback message
   * @param {string} message - Feedback text
   * @param {string} type - Feedback type ('success' | 'error')
   * @private
   */
  showFeedback(message, type) {
    const feedback = document.getElementById('taskFeedback');

    if (feedback) {
      feedback.className = `task-feedback ${type}`;
      feedback.innerHTML = message;
    }
  }

  /**
   * Resets quiz to initial state
   * Allows user to answer again
   */
  reset() {
    this.state = {
      answered: false,
      selectedIndex: null,
      isCorrect: false,
    };

    this.render();
    this.attachListeners();

    // Clear feedback
    const feedback = document.getElementById('taskFeedback');
    if (feedback) {
      feedback.className = 'task-feedback';
      feedback.innerHTML = '';
    }
  }

  /**
   * Gets current quiz state
   * @returns {Object} Current state object
   */
  getState() {
    return { ...this.state };
  }

  /**
   * Checks if quiz has been answered correctly
   * @returns {boolean} True if answered correctly
   */
  isCorrect() {
    return this.state.isCorrect;
  }

  /**
   * Destroys component and cleans up
   */
  destroy() {
    this.container.innerHTML = '';
    this.state = null;
  }
}

export default QuizComponent;
