/**
 * DVN Code Academy - Tutorial Engine
 * Interactive lesson system with step-by-step tutorials, code validation, and progress tracking
 * ref:academy.js, progress-tracker.js, index.html
 */

class TutorialEngine {
  constructor() {
    this.currentPath = null; // Current learning path (html, css, js, debugging)
    this.currentLesson = null; // Current lesson data object
    this.currentStep = 0; // Current step index in lesson
    this.lessonStartTime = null; // Track time spent on lesson
    this.modal = null; // Tutorial modal element
    this.init(); // Initialize the engine
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
      const isCompleted = window.ProgressTracker.isLessonCompleted(lesson.id);
      const isLocked =
        index > 0 && !window.ProgressTracker.isLessonCompleted(pathData.lessons[index - 1].id);

      const card = document.createElement('div');
      card.className = `lesson-selector-card ${isCompleted ? 'completed' : ''} ${isLocked ? 'locked' : ''}`;
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
   */
  async loadLesson(lessonMeta, pathId) {
    console.log(`📖 Loading lesson: ${lessonMeta.id}`);

    try {
      // Load lesson data from JSON file
      const lessonData = await this.fetchLessonData(lessonMeta);

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

      // Show tutorial modal and render first step
      this.showTutorialModal();
      this.renderStep();
    } catch (error) {
      console.error('❌ Error loading lesson:', error);
      alert('Failed to load lesson. Please try again.');
    }
  }

  /**
   * Fetch lesson data from JSON file
   * Loads from lessons/ directory based on lesson metadata
   */
  async fetchLessonData(lessonMeta) {
    try {
      // lessonMeta.content contains the path like 'lessons/html/lesson-01.json'
      const jsonPath = lessonMeta.content;

      if (!jsonPath) {
        console.error('No content path specified for lesson:', lessonMeta.id);
        return null;
      }

      console.log(`🔄 Fetching lesson from: ${jsonPath}`);

      const response = await fetch(jsonPath);

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const lessonData = await response.json();
      console.log(`✅ Loaded lesson data for: ${lessonMeta.id}`, lessonData);

      return lessonData;
    } catch (error) {
      console.error(`❌ Error loading lesson ${lessonMeta.id}:`, error);
      return null;
    }
  }

  /**
   * Create tutorial modal UI structure
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
                            <!-- Dynamic task UI (code editor, quiz, slider, etc.) -->
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
    document.getElementById('nextStep')?.addEventListener('click', () => this.nextStep());
    document.getElementById('prevStep')?.addEventListener('click', () => this.prevStep());
    document.getElementById('showHint')?.addEventListener('click', () => this.showHint());

    // Close on overlay click
    document.querySelectorAll('.modal-overlay').forEach((overlay) => {
      overlay.addEventListener('click', (e) => {
        if (e.target === overlay) {
          const modal = overlay.closest('.tutorial-modal');
          if (modal && modal.id === 'lessonSelectorModal') {
            modal.classList.add('hidden');
          }
        }
      });
    });
  }

  /**
   * Show tutorial modal
   */
  showTutorialModal() {
    this.modal?.classList.remove('hidden');

    // Update lesson title
    document.getElementById('lessonTitle').textContent = this.currentLesson.title;
  }

  /**
   * Close tutorial modal
   */
  closeTutorial() {
    if (confirm('Are you sure you want to exit this lesson? Your progress will not be saved.')) {
      this.modal?.classList.add('hidden');

      // Track time spent
      if (this.lessonStartTime) {
        const timeSpent = Math.floor((Date.now() - this.lessonStartTime) / 60000); // Minutes
        window.ProgressTracker.addTime(timeSpent);
      }

      this.currentLesson = null;
      this.currentStep = 0;
    }
  }

  /**
   * Render current step
   */
  renderStep() {
    if (!this.currentLesson) {
      return;
    }

    const step = this.currentLesson.steps[this.currentStep];

    // Update progress
    const progress = ((this.currentStep + 1) / this.currentLesson.steps.length) * 100;
    document.getElementById('tutorialProgress').style.width = `${progress}%`;
    document.getElementById('progressText').textContent =
      `Step ${this.currentStep + 1} of ${this.currentLesson.steps.length}`;

    // Update content
    document.getElementById('stepTitle').textContent = step.title;
    document.getElementById('stepContent').innerHTML = this.formatContent(step.content);

    // Render visual
    if (step.visual) {
      if (step.visual === 'preview') {
        // Show live preview of user's code from ALL previous steps
        const allCode = Object.values(this.stepCode || {}).join('\n');
        document.getElementById('stepVisual').innerHTML = `
                    <div class="live-preview">
                        <div class="preview-label">Live Preview of Your Code:</div>
                        <div class="preview-box" id="stepPreview">${allCode || '<p style="color:#888;">No code written yet.</p>'}</div>
                    </div>
                `;
      } else {
        document.getElementById('stepVisual').innerHTML = step.visual;
      }
    } else {
      document.getElementById('stepVisual').innerHTML = '';
    }

    // Render task
    this.renderTask(step.task);

    // Update navigation buttons
    const prevBtn = document.getElementById('prevStep');
    if (this.currentStep === 0) {
      prevBtn.style.display = 'none'; // Hide on first step
    } else {
      prevBtn.style.display = 'block'; // Show on other steps
      prevBtn.disabled = false;
    }
    document.getElementById('nextStep').textContent =
      this.currentStep === this.currentLesson.steps.length - 1 ? 'Complete Lesson 🎉' : 'Next →';

    // Hide hint by default
    document.getElementById('taskHint').classList.add('hidden');
    document.getElementById('taskFeedback').innerHTML = '';
    document.getElementById('taskFeedback').className = 'task-feedback';
  }

  /**
   * Format content with markdown-like syntax
   */
  formatContent(content) {
    // Process lists
    let formatted = content.replace(/^- (.+)$/gm, '<li>$1</li>'); // Convert - items to <li>

    // Wrap consecutive <li> tags in <ul>
    formatted = formatted.replace(/(<li>.*<\/li>\n?)+/gs, (match) => {
      return '<ul>' + match + '</ul>';
    });

    // Process other markdown
    formatted = formatted
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>') // **bold**
      .replace(/`(.*?)`/g, '<code>$1</code>') // `code`
      .replace(/\n\n/g, '</p><p>') // Double newlines = new paragraph
      .replace(/\n/g, '<br>'); // Single newlines = line break

    // Wrap in paragraph if not already wrapped
    if (!formatted.startsWith('<')) {
      formatted = '<p>' + formatted + '</p>';
    }

    return formatted;
  }

  /**
   * Render task UI based on task type
   */
  renderTask(task) {
    const taskArea = document.getElementById('taskArea');
    const instruction = document.getElementById('taskInstruction');

    instruction.textContent = task.instruction || 'Your Task:';

    // Store hint text and show/hide hint button
    const hintBtn = document.getElementById('showHint');
    if (task.hint) {
      document.getElementById('hintText').textContent = task.hint;
      hintBtn.style.display = 'block'; // Show hint button
    } else {
      document.getElementById('hintText').textContent = '';
      hintBtn.style.display = 'none'; // Hide hint button if no hint available
    }

    switch (task.type) {
      case 'code':
        this.renderCodeTask(task, taskArea);
        break;

      case 'quiz':
        this.renderQuizTask(task, taskArea);
        break;

      case 'slider':
        this.renderSliderTask(task, taskArea);
        break;

      case 'visual-adjuster':
        this.renderVisualAdjusterTask(task, taskArea);
        break;

      case 'guided-code':
        this.renderGuidedCodeTask(task, taskArea);
        break;

      case 'challenge':
        this.renderChallengeTask(task, taskArea);
        break;

      case 'terminal-command':
        this.renderTerminalCommandTask(task, taskArea);
        break;

      case 'code-with-terminal':
        this.renderCodeWithTerminalTask(task, taskArea);
        break;

      case 'preview-with-terminal':
        this.renderPreviewWithTerminalTask(task, taskArea);
        break;

      case 'info':
        this.renderInfoTask(task, taskArea);
        break;

      case 'completion':
        this.renderCompletionTask(task, taskArea);
        break;

      default:
        taskArea.innerHTML = '<p>Unknown task type</p>';
    }
  }

  /**
   * Render code editor task
   */
  renderCodeTask(task, container) {
    container.innerHTML = `
            <textarea class="code-editor" id="codeInput" rows="4" spellcheck="false">${task.starter || ''}</textarea>
            <button class="btn-primary check-btn" id="checkCode">✓ Check My Code</button>
        `;

    const codeInput = document.getElementById('codeInput');
    const checkBtn = document.getElementById('checkCode');

    // Live validation as user types
    codeInput.addEventListener('input', () => {
      const code = codeInput.value;
      const feedback = document.getElementById('taskFeedback');

      // Store code for this step
      if (!this.stepCode) {
        this.stepCode = {};
      }
      this.stepCode[this.currentStep] = code;

      // Check validation live
      let isValid = false;
      try {
        const validateFn = eval(task.validate);
        isValid = validateFn(code);
      } catch (e) {
        isValid = task.expectedContent
          ? task.expectedContent.every((content) => code.includes(content))
          : code.trim().length > 0;
      }

      // Show live feedback
      if (code.trim().length > 0) {
        if (isValid) {
          feedback.className = 'task-feedback success';
          feedback.innerHTML = '✅ Looks good! Click "Check My Code" to continue.';
        } else {
          feedback.className = 'task-feedback error';
          feedback.innerHTML = '❌ Keep trying... Check the hint if stuck!';
        }
      } else {
        feedback.innerHTML = '';
        feedback.className = 'task-feedback';
      }
    });

    checkBtn.addEventListener('click', () => {
      this.checkCodeTask(task);
    });
  }

  /**
   * Check code task answer
   */
  checkCodeTask(task) {
    const code = document.getElementById('codeInput').value;
    const feedback = document.getElementById('taskFeedback');

    // Store code for this step (for preview later)
    if (!this.stepCode) {
      this.stepCode = {};
    }
    this.stepCode[this.currentStep] = code;

    // Check validation - task.validate is a string, need to eval it
    let isValid = false;
    try {
      const validateFn = eval(task.validate);
      isValid = validateFn(code);
    } catch (e) {
      // Fallback: simple check
      isValid = task.expectedContent
        ? task.expectedContent.every((content) => code.includes(content))
        : code.trim().length > 0;
    }

    if (isValid) {
      feedback.className = 'task-feedback success';
      feedback.innerHTML = '✅ Perfect! Your code is correct!';

      // Enable next button
      document.getElementById('nextStep').disabled = false;

      // Increment code execution counter
      window.ProgressTracker.incrementCodeExecutions();
    } else {
      feedback.className = 'task-feedback error';
      feedback.innerHTML = "❌ Not quite right. Check the hint if you're stuck!";

      document.getElementById('nextStep').disabled = true;
    }
  }

  /**
   * Render quiz task
   */
  renderQuizTask(task, container) {
    container.innerHTML = `
            ${task.instruction ? `<div class="task-instruction">${task.instruction}</div>` : ''}
            <div class="quiz-question">${task.question}</div>
            <div class="quiz-options">
                ${task.options
                  .map(
                    (opt, i) => `
                    <button class="quiz-option" data-index="${i}" data-correct="${opt.correct}">
                        ${opt.text}
                    </button>
                `
                  )
                  .join('')}
            </div>
        `;

    container.querySelectorAll('.quiz-option').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        this.checkQuizTask(e.target, task);
      });
    });
  }

  /**
   * Check quiz answer
   */
  checkQuizTask(button, task) {
    const isCorrect = button.dataset.correct === 'true';
    const feedback = document.getElementById('taskFeedback');

    // Disable all options after answer
    document.querySelectorAll('.quiz-option').forEach((btn) => {
      btn.disabled = true;
      if (btn.dataset.correct === 'true') {
        btn.classList.add('correct');
      }
    });

    if (isCorrect) {
      button.classList.add('selected-correct');
      feedback.className = 'task-feedback success';
      feedback.innerHTML = '✅ Correct! Well done!';
      document.getElementById('nextStep').disabled = false;
    } else {
      button.classList.add('selected-wrong');
      feedback.className = 'task-feedback error';
      feedback.innerHTML = '❌ Not quite. The correct answer is highlighted.';
    }
  }

  /**
   * Render slider task
   */
  renderSliderTask(task, container) {
    container.innerHTML = `
            <div class="slider-widget">
                <div class="slider-label">${task.property}</div>
                <input type="range" id="taskSlider" min="${task.min}" max="${task.max}" value="${task.min}">
                <div class="slider-value">
                    <span id="sliderValue">${task.min}</span>${task.unit}
                </div>
                <div class="slider-demo" id="sliderDemo" style="${task.property}: ${task.min}${task.unit}">
                    Demo Element
                </div>
            </div>
        `;

    const slider = document.getElementById('taskSlider');
    slider.addEventListener('input', (e) => {
      const value = e.target.value;
      document.getElementById('sliderValue').textContent = value;
      document.getElementById('sliderDemo').style[task.property] = `${value}${task.unit}`;
    });

    // Auto-complete after interacting
    slider.addEventListener('change', () => {
      document.getElementById('nextStep').disabled = false;
    });
  }

  /**
   * Render completion task (end of lesson)
   */
  renderCompletionTask(task, container) {
    // Check if user actually completed all code tasks correctly
    const hasValidCode = this.stepCode && Object.keys(this.stepCode).length > 0;

    if (!hasValidCode) {
      container.innerHTML = `
                <div class="completion-message">
                    <div class="completion-icon">⚠️</div>
                    <p style="color: var(--error);">You need to complete the coding tasks above before finishing this lesson!</p>
                    <p>Go back and make sure your code passes validation.</p>
                </div>
            `;
      document.getElementById('nextStep').disabled = true;
    } else {
      container.innerHTML = `
                <div class="completion-message">
                    <div class="completion-icon">🎉</div>
                    <p>${task.instruction}</p>
                </div>
            `;
      // Enable next button (which will complete the lesson)
      document.getElementById('nextStep').disabled = false;
    }
  }

  /**
   * Render visual adjuster task (Tier 1 - Beginner)
   */
  renderVisualAdjusterTask(task, container) {
    if (typeof VisualAdjuster === 'undefined') {
      container.innerHTML = '<p>Visual Adjuster component not loaded</p>';
      return;
    }

    // Initialize visual adjuster component
    new VisualAdjuster(task, container, (completed) => {
      if (completed) {
        document.getElementById('nextStep').disabled = false;
      }
    });
  }

  /**
   * Render guided code editor task (Tier 2 - Intermediate)
   */
  renderGuidedCodeTask(task, container) {
    if (typeof GuidedEditor === 'undefined') {
      container.innerHTML = '<p>Guided Editor component not loaded</p>';
      return;
    }

    // Initialize guided editor component
    new GuidedEditor(task, container, (completed) => {
      if (completed) {
        document.getElementById('nextStep').disabled = false;
      }
    });
  }

  /**
   * Render challenge editor task (Tier 3 - Advanced)
   */
  renderChallengeTask(task, container) {
    if (typeof ChallengeEditor === 'undefined') {
      container.innerHTML = '<p>Challenge Editor component not loaded</p>';
      return;
    }

    // Initialize challenge editor component
    new ChallengeEditor(task, container, (completed) => {
      if (completed) {
        document.getElementById('nextStep').disabled = false;
      }
    });
  }

  /**
   * Render info task (no interaction, just informational)
   */
  renderInfoTask(task, container) {
    container.innerHTML = `
            <div class="info-message">
                <div class="info-icon">ℹ️</div>
                <p>${task.instruction}</p>
            </div>
        `;

    // Enable next button immediately for info steps
    document.getElementById('nextStep').disabled = false;
  }

  /**
   * Render terminal command task (project-builder lessons)
   */
  renderTerminalCommandTask(task, container) {
    if (typeof TerminalWidget === 'undefined') {
      container.innerHTML = '<p>Terminal Widget component not loaded</p>';
      return;
    }

    // Store project name if user customizes it
    if (!this.projectData) {
      this.projectData = {
        name: 'my-first-website',
        files: [],
        currentDir: '~',
      };
    }

    // Create container for terminal
    container.innerHTML = `
            <div id="terminalContainer"></div>
            <div class="terminal-task-actions">
                ${
                  task.allowCustomName
                    ? `
                    <div class="custom-name-input">
                        <label>Project name (optional):</label>
                        <input type="text" id="customProjectName" placeholder="${task.providedCommand.split(' ')[1]}" />
                    </div>
                `
                    : ''
                }
                <button class="btn-primary" id="executeTerminalCmd">
                    ▶ Run Command
                </button>
            </div>
            <div id="terminalFeedback" class="task-feedback"></div>
        `;

    // Initialize terminal widget
    const terminalContainer = document.getElementById('terminalContainer');
    const terminal = new TerminalWidget(terminalContainer, {
      prompt:
        this.projectData.currentDir === '~'
          ? 'student@dvn:~$'
          : `student@dvn:${this.projectData.currentDir}$`,
      animated: true,
      height: '2-line',
    });

    // Store terminal instance
    this.terminal = terminal;

    // Handle command execution
    document.getElementById('executeTerminalCmd').addEventListener('click', async () => {
      let command = task.providedCommand;

      // If custom name allowed, replace it
      if (task.allowCustomName) {
        const customName = document.getElementById('customProjectName').value.trim();
        if (customName && task.namePattern) {
          const pattern = new RegExp(task.namePattern);
          if (pattern.test(customName)) {
            // Replace name in command
            const parts = command.split(' ');
            parts[1] = customName;
            command = parts.join(' ');
            this.projectData.name = customName;
          }
        }
      }

      // If usePreviousName, replace with stored project name
      if (task.usePreviousName) {
        const parts = command.split(' ');
        if (parts.length > 1) {
          parts[1] = this.projectData.name;
          command = parts.join(' ');
        }
      }

      // Execute command in terminal
      await terminal.executeCommand(command, task.successMessage);

      // Update project data based on action
      if (task.expectedAction === 'create_directory') {
        this.projectData.currentDir = '~/projects';
      } else if (task.expectedAction === 'change_directory') {
        this.projectData.currentDir = `~/projects/${this.projectData.name}`;
      } else if (task.expectedAction === 'create_file') {
        const fileName = command.split(' ')[1];
        this.projectData.files.push(fileName);
      } else if (task.expectedAction === 'list_files') {
        terminal.showInfo(this.projectData.files.join('  '));
      }

      // Show feedback and enable next
      const feedback = document.getElementById('terminalFeedback');
      feedback.className = 'task-feedback success';
      feedback.innerHTML = '✅ Command executed successfully!';
      document.getElementById('nextStep').disabled = false;
    });
  }

  /**
   * Render code editor with terminal command (project-builder lessons)
   */
  renderCodeWithTerminalTask(task, container) {
    if (typeof TerminalWidget === 'undefined') {
      container.innerHTML = '<p>Terminal Widget component not loaded</p>';
      return;
    }

    container.innerHTML = `
            <div id="terminalContainer"></div>
            <div class="code-editor-section" id="codeEditorSection" style="display:none; margin-top:20px;">
                <div class="editor-header">
                    <strong>Editing: ${task.file}</strong>
                    <button class="btn-secondary" id="closeEditor">Close Editor</button>
                </div>
                <textarea class="code-editor" id="codeInput" rows="12" spellcheck="false">${task.starter || ''}</textarea>
                <div class="editor-actions">
                    <button class="btn-primary" id="saveFile">💾 Save File</button>
                </div>
            </div>
            <div id="terminalFeedback" class="task-feedback"></div>
        `;

    // Initialize terminal widget
    const terminalContainer = document.getElementById('terminalContainer');
    const terminal = new TerminalWidget(terminalContainer, {
      prompt: `student@dvn:~/projects/${this.projectData?.name || 'my-website'}$`,
      animated: true,
      height: '1-line',
    });

    // Show terminal command
    setTimeout(async () => {
      await terminal.executeCommand(task.terminalCommand, `Opening ${task.file}...`);

      // Show code editor after terminal command
      setTimeout(() => {
        document.getElementById('codeEditorSection').style.display = 'block';
        document.getElementById('codeInput').focus();
      }, 500);
    }, 300);

    // Handle save
    document.getElementById('saveFile').addEventListener('click', () => {
      const code = document.getElementById('codeInput').value;

      // Store code in projectData for later use
      if (task.file.endsWith('.html')) {
        this.projectData.htmlCode = code;
      } else if (task.file.endsWith('.css')) {
        this.projectData.cssCode = code;
      } else if (task.file.endsWith('.js')) {
        this.projectData.jsCode = code;
      }

      // Basic validation
      let valid = true;
      if (task.expectedContent) {
        valid = task.expectedContent.every((content) => code.includes(content));
      }

      const feedback = document.getElementById('terminalFeedback');
      if (valid) {
        terminal.showInfo(`✓ ${task.file} saved successfully!`);
        feedback.className = 'task-feedback success';
        feedback.innerHTML = `✅ ${task.successMessage || 'File saved!'}`;
        document.getElementById('nextStep').disabled = false;
      } else {
        feedback.className = 'task-feedback error';
        feedback.innerHTML = '❌ Your code is missing some required content. Check the hints!';
      }
    });

    // Handle close editor (without saving)
    document.getElementById('closeEditor').addEventListener('click', () => {
      document.getElementById('codeEditorSection').style.display = 'none';
      terminal.showInfo('Editor closed without saving');
    });
  }

  /**
   * Render preview with terminal command (project-builder lessons)
   */
  renderPreviewWithTerminalTask(task, container) {
    if (typeof TerminalWidget === 'undefined') {
      container.innerHTML = '<p>Terminal Widget component not loaded</p>';
      return;
    }

    container.innerHTML = `
            <div id="terminalContainer"></div>
            <div class="preview-section" id="previewSection" style="display:none; margin-top:20px;">
                <div class="preview-header">
                    <strong>🌐 Browser Preview</strong>
                    <button class="btn-secondary" id="refreshPreview">🔄 Refresh</button>
                </div>
                <div class="preview-frame">
                    <iframe id="previewIframe" sandbox="allow-scripts" style="width:100%; height:400px; border:none; background:#fff;"></iframe>
                </div>
            </div>
            <div id="terminalFeedback" class="task-feedback"></div>
        `;

    // Initialize terminal widget
    const terminalContainer = document.getElementById('terminalContainer');
    const terminal = new TerminalWidget(terminalContainer, {
      prompt: `student@dvn:~/projects/${this.projectData?.name || 'my-website'}$`,
      animated: true,
      height: '1-line',
    });

    // Show terminal command
    setTimeout(async () => {
      await terminal.executeCommand(
        task.terminalCommand,
        task.successMessage || 'Opening in browser...'
      );

      // Show preview after terminal command
      if (task.showPreview) {
        setTimeout(() => {
          document.getElementById('previewSection').style.display = 'block';
          this.updateProjectPreview();
        }, 500);
      }

      // Enable next button
      const feedback = document.getElementById('terminalFeedback');
      feedback.className = 'task-feedback success';
      feedback.innerHTML = '✅ Preview loaded! You can now see your website.';
      document.getElementById('nextStep').disabled = false;
    }, 300);

    // Handle refresh
    document.getElementById('refreshPreview')?.addEventListener('click', () => {
      this.updateProjectPreview();
      terminal.showInfo('Preview refreshed');
    });
  }

  /**
   * Update project preview iframe with current project files
   */
  updateProjectPreview() {
    const iframe = document.getElementById('previewIframe');
    if (!iframe) {
      return;
    }

    // Get code from previous steps (stored in projectData)
    const html = this.projectData?.htmlCode || '<h1>No HTML file yet</h1>';
    const css = this.projectData?.cssCode || '';

    const fullHTML = `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>${css}</style>
            </head>
            <body>
                ${html}
            </body>
            </html>
        `;

    iframe.contentDocument.open();
    iframe.contentDocument.write(fullHTML);
    iframe.contentDocument.close();
  }

  /**
   * Show hint for current task
   */
  showHint() {
    document.getElementById('taskHint').classList.remove('hidden');
    window.ProgressTracker.incrementHintsUsed();
  }

  /**
   * Move to next step
   */
  nextStep() {
    if (this.currentStep < this.currentLesson.steps.length - 1) {
      this.currentStep++;
      this.renderStep();
    } else {
      // Lesson complete!
      this.completeLesson();
    }
  }

  /**
   * Move to previous step
   */
  prevStep() {
    if (this.currentStep > 0) {
      this.currentStep--;
      this.renderStep();
    }
  }

  /**
   * Complete current lesson
   */
  completeLesson() {
    const timeSpent = Math.floor((Date.now() - this.lessonStartTime) / 60000); // Minutes
    const score = 100; // Could calculate based on hints used, attempts, etc.

    // Record completion in progress tracker
    window.ProgressTracker.completeLesson(this.currentLesson.id, this.currentLesson.pathId, score);

    // Show completion screen
    this.showCompletionScreen(score, timeSpent);
  }

  /**
   * Show lesson completion screen
   */
  showCompletionScreen(score, timeSpent) {
    const content = this.modal.querySelector('.tutorial-main');
    content.innerHTML = `
            <div class="completion-screen">
                <div class="completion-icon-large">🎉</div>
                <h2>Lesson Complete!</h2>
                <p>You've successfully completed: <strong>${this.currentLesson.title}</strong></p>

                <div class="completion-stats">
                    <div class="stat">
                        <div class="stat-value">${score}%</div>
                        <div class="stat-label">Score</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">${timeSpent}</div>
                        <div class="stat-label">Minutes</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">${this.currentLesson.steps.length}</div>
                        <div class="stat-label">Steps</div>
                    </div>
                </div>

                <div class="completion-actions">
                    <button id="nextLessonBtn" class="btn-primary">Next Lesson →</button>
                    <button id="backToPathBtn" class="btn-secondary">Back to Path</button>
                </div>
            </div>
        `;

    // Hide footer nav
    this.modal.querySelector('.tutorial-footer').style.display = 'none';

    // Attach button listeners
    document.getElementById('nextLessonBtn')?.addEventListener('click', () => {
      this.loadNextLesson();
    });

    document.getElementById('backToPathBtn')?.addEventListener('click', () => {
      this.modal.classList.add('hidden');
      this.showLessonSelector(this.currentPath);
    });
  }

  /**
   * Load next lesson in path
   */
  loadNextLesson() {
    const currentIndex = this.currentPath.lessons.findIndex((l) => l.id === this.currentLesson.id);
    const nextLesson = this.currentPath.lessons[currentIndex + 1];

    if (nextLesson) {
      this.loadLesson(nextLesson, this.currentLesson.pathId);
      this.modal.querySelector('.tutorial-footer').style.display = 'flex'; // Show footer again
    } else {
      // No more lessons in this path
      alert("🎉 Congratulations! You've completed all lessons in this path!");
      this.modal.classList.add('hidden');
    }
  }
}

// Create global instance
window.TutorialEngine = new TutorialEngine();
