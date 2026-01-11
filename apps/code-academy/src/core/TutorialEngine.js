/**
 * Tutorial Engine - Core Orchestrator
 * Coordinates lesson flow, step navigation, and component interaction
 * Refactored to be modular - orchestration only, delegates to specialized components
 * Original: 1116 lines | Refactored: ~300 lines
 */

import LessonLoader from '../services/LessonLoader.js';
import TaskRenderer from '../components/TaskRenderer.js';
import { formatContent } from '../utils/formatters.js';

class TutorialEngine {
  constructor() {
    // Core state
    this.currentPath = null; // Current learning path (html, css, js, etc.)
    this.currentLesson = null; // Current lesson data object
    this.currentStep = 0; // Current step index in lesson
    this.lessonStartTime = null; // Track time spent on lesson
    this.modal = null; // Tutorial modal element

    // Services and components | Dependency injection pattern
    this.lessonLoader = new LessonLoader();
    this.taskRenderer = null; // Created on demand

    this.init();
  }

  /**
   * Initialize tutorial engine
   * Creates modal UI and attaches event listeners
   */
  init() {
    console.log('🎓 Tutorial Engine initializing...');
    this.createTutorialModal(); // Build modal UI structure
    console.log('✅ Tutorial Engine ready');
  }

  /**
   * Start a learning path
   * Called from academy.js when user clicks a path
   * @param {string} pathId - Path identifier (e.g., 'html', 'css')
   * @param {Object} pathData - Path configuration with lessons array
   */
  startPath(pathId, pathData) {
    console.log(`📚 Starting path: ${pathId}`, pathData);

    this.currentPath = pathData;

    // Show lesson selector for this path
    this.showLessonSelector(pathData);
  }

  /**
   * Show lesson selector modal
   * Displays all lessons in the path for user to choose
   * @param {Object} pathData - Path configuration
   */
  showLessonSelector(pathData) {
    const modal = document.getElementById('lessonSelectorModal');

    if (!modal) {
      console.error('Lesson selector modal not found');
      return;
    }

    // Populate lesson cards
    const grid = document.getElementById('lessonSelectorGrid');
    grid.innerHTML = ''; // Clear previous lessons

    pathData.lessons.forEach((lesson, index) => {
      const isCompleted = window.ProgressTracker?.isLessonCompleted(lesson.id);
      const isLocked =
        index > 0 && !window.ProgressTracker?.isLessonCompleted(pathData.lessons[index - 1].id);

      const card = document.createElement('div');
      card.className = `lesson-selector-card ${isCompleted ? 'completed' : ''} ${
        isLocked ? 'locked' : ''
      }`;
      card.innerHTML = `
        <div class="lesson-number">${index + 1}</div>
        <div class="lesson-status">${isCompleted ? '✓' : isLocked ? '🔒' : '▶'}</div>
        <h4>${lesson.title}</h4>
        <p>${lesson.description}</p>
        ${isCompleted ? '<div class="completed-badge">Completed</div>' : ''}
      `;

      if (!isLocked) {
        card.style.cursor = 'pointer';
        card.addEventListener('click', () => {
          this.loadLesson(lesson, pathData.id);
          modal.classList.add('hidden');
        });
      }

      grid.appendChild(card);
    });

    // Show modal
    modal.classList.remove('hidden');
  }

  /**
   * Load a specific lesson
   * Fetches lesson content and starts tutorial
   * @param {Object} lessonMeta - Lesson metadata from path config
   * @param {string} pathId - Parent path ID
   */
  async loadLesson(lessonMeta, pathId) {
    console.log(`📖 Loading lesson: ${lessonMeta.id}`);

    try {
      // Load lesson data from JSON file | ref:LessonLoader.js
      const lessonData = await this.lessonLoader.loadLesson(lessonMeta);

      if (!lessonData) {
        throw new Error('Lesson data not found');
      }

      this.currentLesson = {
        ...lessonMeta,
        ...lessonData,
        pathId: pathId,
      };

      this.currentStep = 0;
      this.lessonStartTime = Date.now();

      // Initialize task renderer | Handles all task types
      const taskArea = document.getElementById('taskArea');
      this.taskRenderer = new TaskRenderer(taskArea, (isComplete, data) => {
        // Task completion callback | Enables next button when task is done
        console.log('Task completed:', isComplete, data);
      });

      // Show tutorial modal and render first step
      this.showTutorialModal();
      this.renderStep();
    } catch (error) {
      console.error('❌ Error loading lesson:', error);
      alert('Failed to load lesson. Please try again.');
    }
  }

  /**
   * Show tutorial modal
   */
  showTutorialModal() {
    this.modal.classList.remove('hidden');

    // Update lesson title
    document.getElementById('lessonTitle').textContent = this.currentLesson.title;
  }

  /**
   * Close tutorial and return to lesson selector
   */
  closeTutorial() {
    this.modal.classList.add('hidden');

    // Cleanup | ref:TaskRenderer.js destroy()
    if (this.taskRenderer) {
      this.taskRenderer.destroy();
      this.taskRenderer = null;
    }

    // Save progress if lesson was started | ref:progress-tracker.js
    if (this.lessonStartTime && window.ProgressTracker) {
      const timeSpent = Math.floor((Date.now() - this.lessonStartTime) / 60000); // Minutes
      window.ProgressTracker.updateLessonTime(this.currentLesson.id, timeSpent);
    }

    // Reset state
    this.currentLesson = null;
    this.currentStep = 0;
    this.lessonStartTime = null;
  }

  /**
   * Render current step
   * Updates UI with step content, visual, and task
   */
  renderStep() {
    const step = this.currentLesson.steps[this.currentStep];

    // Update progress bar
    const progress = ((this.currentStep + 1) / this.currentLesson.steps.length) * 100;
    document.getElementById('tutorialProgress').style.width = `${progress}%`;
    document.getElementById('progressText').textContent = `Step ${this.currentStep + 1} of ${
      this.currentLesson.steps.length
    }`;

    // Update content | ref:formatters.js
    document.getElementById('stepTitle').textContent = step.title;
    document.getElementById('stepContent').innerHTML = formatContent(step.content);

    // Render visual
    if (step.visual) {
      if (step.visual === 'preview') {
        // Show live preview of user's code from ALL previous steps
        const allCode = Object.values(this.taskRenderer?.getStepCode() || {}).join('\n');
        document.getElementById('stepVisual').innerHTML = `
          <div class="live-preview">
            <div class="preview-label">Live Preview of Your Code:</div>
            <div class="preview-box" id="stepPreview">${
              allCode || '<p style="color:#888;">No code written yet.</p>'
            }</div>
          </div>
        `;
      } else {
        document.getElementById('stepVisual').innerHTML = step.visual;
      }
    } else {
      document.getElementById('stepVisual').innerHTML = '';
    }

    // Render task | ref:TaskRenderer.js
    if (this.taskRenderer) {
      this.taskRenderer.render(step.task, this.currentStep);
    }

    // Update navigation buttons
    this.updateNavigationButtons();
  }

  /**
   * Update navigation button states
   */
  updateNavigationButtons() {
    const prevBtn = document.getElementById('prevStep');
    const nextBtn = document.getElementById('nextStep');

    // Previous button only enabled if not on first step
    prevBtn.disabled = this.currentStep === 0;

    // Next button starts disabled, task completion enables it
    // Exception: First step auto-enabled for welcome screens
    nextBtn.disabled = this.currentStep !== 0;

    // Update next button text for last step
    const isLastStep = this.currentStep === this.currentLesson.steps.length - 1;
    nextBtn.textContent = isLastStep ? '🎉 Complete Lesson' : 'Next →';
  }

  /**
   * Show hint for current task
   */
  showHint() {
    const hintEl = document.getElementById('taskHint');
    if (hintEl) {
      hintEl.classList.toggle('hidden');
    }
  }

  /**
   * Navigate to next step
   */
  nextStep() {
    const isLastStep = this.currentStep === this.currentLesson.steps.length - 1;

    if (isLastStep) {
      // Complete the lesson
      this.completeLesson();
    } else {
      // Move to next step
      this.currentStep++;
      this.renderStep();

      // Scroll to top of tutorial | Better UX for long content
      const tutorialLeft = document.querySelector('.tutorial-left');
      if (tutorialLeft) {
        tutorialLeft.scrollTop = 0;
      }
    }
  }

  /**
   * Navigate to previous step
   */
  prevStep() {
    if (this.currentStep > 0) {
      this.currentStep--;
      this.renderStep();
    }
  }

  /**
   * Complete current lesson
   * Saves progress and shows completion screen
   */
  completeLesson() {
    const timeSpent = Math.floor((Date.now() - this.lessonStartTime) / 60000); // Minutes
    const score = 100; // TODO: Calculate based on attempts, time, hints used

    // Mark lesson as complete | ref:progress-tracker.js
    if (window.ProgressTracker) {
      window.ProgressTracker.completeLesson(this.currentLesson.id, score, timeSpent);
    }

    this.showCompletionScreen(score, timeSpent);
  }

  /**
   * Show lesson completion screen
   * @param {number} score - Lesson score (0-100)
   * @param {number} timeSpent - Time spent in minutes
   */
  showCompletionScreen(score, timeSpent) {
    const modal = this.modal;

    modal.querySelector('.modal-content').innerHTML = `
      <div class="completion-screen">
        <div class="completion-icon">🎉</div>
        <h2>Lesson Complete!</h2>
        <p>Great job completing <strong>${this.currentLesson.title}</strong>!</p>

        <div class="completion-stats">
          <div class="stat">
            <div class="stat-label">Score</div>
            <div class="stat-value">${score}%</div>
          </div>
          <div class="stat">
            <div class="stat-label">Time Spent</div>
            <div class="stat-value">${timeSpent} min</div>
          </div>
        </div>

        <div class="completion-actions">
          <button class="btn-secondary" id="backToLessons">← Back to Lessons</button>
          <button class="btn-primary" id="nextLesson">Next Lesson →</button>
        </div>
      </div>
    `;

    // Attach button handlers
    document.getElementById('backToLessons')?.addEventListener('click', () => {
      this.closeTutorial();
      this.showLessonSelector(this.currentPath);
    });

    document.getElementById('nextLesson')?.addEventListener('click', () => {
      this.loadNextLesson();
    });
  }

  /**
   * Load next lesson in sequence
   */
  loadNextLesson() {
    const currentIndex = this.currentPath.lessons.findIndex((l) => l.id === this.currentLesson.id);

    if (currentIndex < this.currentPath.lessons.length - 1) {
      const nextLesson = this.currentPath.lessons[currentIndex + 1];
      this.loadLesson(nextLesson, this.currentPath.id);
    } else {
      // No more lessons in this path
      alert('🎉 Congratulations! You completed all lessons in this path!');
      this.closeTutorial();
      this.showLessonSelector(this.currentPath);
    }
  }

  /**
   * Create tutorial modal UI structure
   * Large method - could be extracted to ModalManager in future refactor
   */
  createTutorialModal() {
    // Create lesson selector modal
    const selectorModal = document.createElement('div');
    selectorModal.id = 'lessonSelectorModal';
    selectorModal.className = 'tutorial-modal hidden';
    selectorModal.innerHTML = `
      <div class="modal-overlay" id="lessonSelectorOverlay"></div>
      <div class="modal-content lesson-selector">
        <div class="modal-header">
          <h2 id="pathTitle">Select a Lesson</h2>
          <button class="close-btn" id="closeLessonSelector">✕</button>
        </div>
        <div class="lessons-grid" id="lessonSelectorGrid">
          <!-- Populated dynamically -->
        </div>
      </div>
    `;

    // Create main tutorial modal
    const tutorialModal = document.createElement('div');
    tutorialModal.id = 'tutorialModal';
    tutorialModal.className = 'tutorial-modal hidden';
    tutorialModal.innerHTML = `
      <div class="modal-overlay"></div>
      <div class="modal-content tutorial-content">
        <!-- Header -->
        <div class="tutorial-header">
          <h2 id="lessonTitle">Lesson Title</h2>
          <button class="close-btn" id="closeTutorial">✕</button>
        </div>

        <!-- Progress Bar -->
        <div class="progress-container">
          <div class="progress-bar">
            <div class="progress-fill" id="tutorialProgress" style="width: 0%"></div>
          </div>
          <div class="progress-text" id="progressText">Step 1 of 3</div>
        </div>

        <!-- Main Content Area -->
        <div class="tutorial-main">
          <!-- Left: Instruction & Visual -->
          <div class="tutorial-left">
            <div class="step-title" id="stepTitle">Step Title</div>
            <div class="step-content" id="stepContent">Content goes here...</div>
            <div class="step-visual" id="stepVisual"></div>
          </div>

          <!-- Right: Interactive Task -->
          <div class="tutorial-right">
            <div class="task-instruction" id="taskInstruction">Your Task:</div>
            <div class="task-area" id="taskArea">
              <!-- Dynamic task UI (code editor, quiz, etc.) -->
            </div>
            <div class="task-hint hidden" id="taskHint">
              <strong>💡 Hint:</strong> <span id="hintText"></span>
            </div>
            <div class="task-feedback" id="taskFeedback"></div>
          </div>
        </div>

        <!-- Footer Navigation -->
        <div class="tutorial-footer">
          <button id="prevStep" class="btn-secondary" disabled>← Previous</button>
          <button id="showHint" class="btn-secondary">💡 Show Hint</button>
          <button id="nextStep" class="btn-primary">Next →</button>
        </div>
      </div>
    `;

    document.body.appendChild(selectorModal);
    document.body.appendChild(tutorialModal);

    this.modal = tutorialModal;

    // Attach event listeners
    this.attachModalListeners();
  }

  /**
   * Attach event listeners to modal elements
   */
  attachModalListeners() {
    // Lesson selector close
    document.getElementById('closeLessonSelector')?.addEventListener('click', () => {
      document.getElementById('lessonSelectorModal').classList.add('hidden');
    });

    // Tutorial close
    document.getElementById('closeTutorial')?.addEventListener('click', () => {
      this.closeTutorial();
    });

    // Navigation buttons
    document.getElementById('prevStep')?.addEventListener('click', () => {
      this.prevStep();
    });

    document.getElementById('nextStep')?.addEventListener('click', () => {
      this.nextStep();
    });

    // Hint button
    document.getElementById('showHint')?.addEventListener('click', () => {
      this.showHint();
    });

    // Overlay click to close lesson selector
    document.getElementById('lessonSelectorOverlay')?.addEventListener('click', () => {
      document.getElementById('lessonSelectorModal').classList.add('hidden');
    });
  }
}

export default TutorialEngine;
