/**
 * Interactive Tutorial System - Learn by Doing!
 * Hands-on lessons with visuals, no boring reading required
 * ref:panel.html, COMPLETE_BEGINNERS_GUIDE.md
 */

class InteractiveTutorial {
    constructor() {
        this.currentLesson = 0;  // Track progress | Which lesson user is on
        this.currentStep = 0;    // Track current step in lesson
        this.completed = new Set();  // Track completed lessons | Save progress
        this.mode = 'interactive';  // 'interactive' or 'reading' | User preference
        this.lessons = this.createLessons();  // All available lessons
        this.init();
    }

    /**
     * Initialize tutorial system
     */
    init() {
        this.loadProgress();  // Load saved progress from localStorage | ref:localStorage
        this.createTutorialUI();  // Build tutorial interface
        this.attachEventListeners();  // Wire up buttons
    }

    /**
     * Create all tutorial lessons
     * Each lesson has steps with interactive tasks
     */
    createLessons() {
        return [
            // Lesson 1: First Steps
            {
                id: 'basics-html',
                title: '🎯 Your First HTML Element',
                difficulty: 'Beginner',
                duration: '5 min',
                description: 'Create a button and see it appear on the page',
                visual: 'button-example.svg',  // Visual aid
                steps: [
                    {
                        title: 'Step 1: Understanding HTML Tags',
                        explanation: 'HTML uses TAGS to create elements. Tags look like <this>.',
                        visual: `
                            <div class="visual-example">
                                <div class="code-visual">
                                    <span class="tag">&lt;button&gt;</span>
                                    <span class="content">Click Me</span>
                                    <span class="tag">&lt;/button&gt;</span>
                                </div>
                                <div class="arrow">↓</div>
                                <div class="result">
                                    <button class="demo-btn">Click Me</button>
                                </div>
                            </div>
                        `,
                        task: {
                            type: 'code',  // User writes code
                            instruction: 'Type this code in the box below:',
                            starter: '',  // Empty - user types from scratch
                            solution: '<button>Hello!</button>',
                            hint: 'Start with < then button then >',
                            validate: (code) => {
                                return code.includes('<button>') && code.includes('</button>');
                            }
                        }
                    },
                    {
                        title: 'Step 2: Add an ID',
                        explanation: 'IDs let JavaScript find YOUR specific button',
                        visual: `
                            <div class="visual-example">
                                <div class="diagram">
                                    <div class="element-box">
                                        <div class="tag-line">
                                            &lt;button <span class="highlight">id="myBtn"</span>&gt;
                                        </div>
                                        <div class="explanation">
                                            ↑ This is the ID - like a name tag
                                        </div>
                                    </div>
                                </div>
                            </div>
                        `,
                        task: {
                            type: 'code',
                            instruction: 'Add id="myBtn" to your button:',
                            starter: '<button>Hello!</button>',
                            solution: '<button id="myBtn">Hello!</button>',
                            hint: 'Put id="myBtn" INSIDE the opening tag',
                            validate: (code) => {
                                return code.includes('id="myBtn"') || code.includes("id='myBtn'");
                            }
                        }
                    },
                    {
                        title: 'Step 3: See It Live!',
                        explanation: 'Watch your button appear in real-time',
                        visual: 'preview',  // Live preview of user's code
                        task: {
                            type: 'preview',  // Show live result
                            instruction: 'Your button is now live! Click it to test.',
                            interactive: true
                        }
                    }
                ]
            },

            // Lesson 2: Styling
            {
                id: 'basics-css',
                title: '🎨 Make It Pretty with CSS',
                difficulty: 'Beginner',
                duration: '7 min',
                description: 'Add colors and styling to your button',
                steps: [
                    {
                        title: 'Step 1: Change Background Color',
                        explanation: 'CSS uses properties like background-color to style elements',
                        visual: `
                            <div class="color-picker-demo">
                                <div class="before">
                                    <button>Boring Gray</button>
                                </div>
                                <div class="arrow">→</div>
                                <div class="after">
                                    <button style="background: cyan;">Cool Cyan!</button>
                                </div>
                            </div>
                        `,
                        task: {
                            type: 'code',
                            instruction: 'Make the button cyan:',
                            starter: '.myBtn {\n  \n}',
                            solution: '.myBtn {\n  background-color: cyan;\n}',
                            hint: 'Use background-color: cyan;',
                            validate: (code) => {
                                return code.includes('background') && code.includes('cyan');
                            }
                        }
                    },
                    {
                        title: 'Step 2: Interactive Color Picker',
                        explanation: 'Try different colors and see instant results!',
                        visual: 'color-picker',  // Special: color picker widget
                        task: {
                            type: 'interactive-picker',
                            properties: ['background-color', 'color', 'border-color'],
                            onChange: (property, value) => {
                                // Live update preview
                            }
                        }
                    },
                    {
                        title: 'Step 3: Add Padding',
                        explanation: 'Padding creates space INSIDE the button',
                        visual: `
                            <div class="box-model-demo">
                                <div class="before-after">
                                    <div class="example">
                                        <div class="label">No Padding</div>
                                        <button style="padding: 0;">Cramped</button>
                                    </div>
                                    <div class="example">
                                        <div class="label">With Padding</div>
                                        <button style="padding: 15px;">Comfortable</button>
                                    </div>
                                </div>
                            </div>
                        `,
                        task: {
                            type: 'slider',  // Interactive slider
                            property: 'padding',
                            min: 0,
                            max: 50,
                            unit: 'px',
                            instruction: 'Move the slider to add padding:',
                            showLive: true  // Live preview as they slide
                        }
                    }
                ]
            },

            // Lesson 3: JavaScript Interaction
            {
                id: 'basics-js',
                title: '⚡ Make It DO Something',
                difficulty: 'Beginner',
                duration: '10 min',
                description: 'Add click behavior with JavaScript',
                steps: [
                    {
                        title: 'Step 1: Find the Button',
                        explanation: 'JavaScript uses getElementById to find elements',
                        visual: `
                            <div class="find-element-demo">
                                <div class="dom-tree">
                                    <div class="html-structure">
                                        &lt;body&gt;
                                        <div class="indent">
                                            &lt;button <span class="highlight">id="myBtn"</span>&gt;
                                        </div>
                                        &lt;/body&gt;
                                    </div>
                                    <div class="arrow">↓</div>
                                    <div class="js-code">
                                        document.getElementById(<span class="highlight">'myBtn'</span>)
                                    </div>
                                    <div class="result">✓ Found it!</div>
                                </div>
                            </div>
                        `,
                        task: {
                            type: 'code',
                            instruction: 'Get the button with ID "myBtn":',
                            starter: 'const button = document.',
                            solution: 'const button = document.getElementById("myBtn");',
                            hint: 'Use getElementById("myBtn")',
                            validate: (code) => {
                                return code.includes('getElementById') && code.includes('myBtn');
                            }
                        }
                    },
                    {
                        title: 'Step 2: Add Click Listener',
                        explanation: 'Tell the button what to do when clicked',
                        visual: `
                            <div class="event-flow">
                                <div class="step">👆 User clicks</div>
                                <div class="arrow">↓</div>
                                <div class="step">🎯 Button detects click</div>
                                <div class="arrow">↓</div>
                                <div class="step">⚡ Your code runs!</div>
                            </div>
                        `,
                        task: {
                            type: 'code',
                            instruction: 'Make button show alert when clicked:',
                            starter: 'button.addEventListener("click", () => {\n  \n});',
                            solution: 'button.addEventListener("click", () => {\n  alert("Clicked!");\n});',
                            hint: 'Use alert("Clicked!"); inside the function',
                            validate: (code) => {
                                return code.includes('addEventListener') && code.includes('alert');
                            }
                        }
                    },
                    {
                        title: 'Step 3: Test Your Button!',
                        explanation: 'Click the button you created',
                        visual: 'preview',
                        task: {
                            type: 'test',  // User must click their button
                            instruction: 'Click the button to complete this lesson!',
                            success: 'You did it! Button works! 🎉',
                            checkCompletion: true
                        }
                    }
                ]
            },

            // Lesson 4: Fix Real Issues
            {
                id: 'fix-duplicate',
                title: '🔧 Fix a Duplicate Function',
                difficulty: 'Intermediate',
                duration: '15 min',
                description: 'Learn by fixing actual code issues',
                steps: [
                    {
                        title: 'Step 1: Understand the Problem',
                        explanation: 'This function exists in TWO files - which causes bugs',
                        visual: `
                            <div class="problem-visual">
                                <div class="file-comparison">
                                    <div class="file">
                                        <div class="filename">app.js</div>
                                        <pre>function closeMenu() {
  // Version 1
}</pre>
                                    </div>
                                    <div class="vs">❌ VS ❌</div>
                                    <div class="file">
                                        <div class="filename">utils.js</div>
                                        <pre>function closeMenu() {
  // Version 2
}</pre>
                                    </div>
                                </div>
                                <div class="issue">
                                    ⚠️ If you fix a bug in ONE file, it's still broken in the OTHER!
                                </div>
                            </div>
                        `,
                        task: {
                            type: 'quiz',
                            question: 'Why are duplicate functions bad?',
                            options: [
                                { text: 'They take up more disk space', correct: false },
                                { text: 'Fixing bugs in one doesn\'t fix the other', correct: true },
                                { text: 'The computer gets confused', correct: false },
                                { text: 'It makes the code run slower', correct: false }
                            ],
                            explanation: 'When you fix a bug in version 1, version 2 still has the bug! This causes inconsistent behavior.'
                        }
                    },
                    {
                        title: 'Step 2: Choose Which to Keep',
                        explanation: 'Keep the module version (utils.js), delete the duplicate',
                        visual: `
                            <div class="decision-tree">
                                <div class="choice">
                                    <div class="option keep">
                                        <div class="filename">utils.js</div>
                                        <div class="badge">✓ KEEP</div>
                                        <div class="reason">Has export - used by modules</div>
                                    </div>
                                    <div class="option delete">
                                        <div class="filename">app.js</div>
                                        <div class="badge">❌ DELETE</div>
                                        <div class="reason">Not imported anywhere</div>
                                    </div>
                                </div>
                            </div>
                        `,
                        task: {
                            type: 'interactive',
                            instruction: 'Click the file you should KEEP:',
                            options: ['app.js', 'utils.js'],
                            correct: 'utils.js',
                            feedback: {
                                correct: 'Exactly! Keep the one with export that modules use.',
                                wrong: 'Not quite - check which one is imported by other files'
                            }
                        }
                    },
                    {
                        title: 'Step 3: Apply the Fix',
                        explanation: 'Delete from app.js, import from utils.js instead',
                        visual: 'diff-viewer',  // Show before/after diff
                        task: {
                            type: 'code',
                            instruction: 'Add import at top of app.js:',
                            starter: '// Add import here\n',
                            solution: 'import { closeMenu } from \'./utils.js\';\n',
                            hint: 'Use import { closeMenu } from ...',
                            validate: (code) => {
                                return code.includes('import') && code.includes('closeMenu');
                            }
                        }
                    }
                ]
            },

            // More lessons...
            // - Scope mismatches
            // - Missing selectors
            // - Box model deep dive
            // - Flexbox layout
            // - API calls
            // etc.
        ];
    }

    /**
     * Create tutorial UI overlay
     */
    createTutorialUI() {
        const overlay = document.createElement('div');
        overlay.id = 'tutorialOverlay';
        overlay.className = 'tutorial-overlay hidden';
        overlay.innerHTML = `
            <div class="tutorial-modal">
                <!-- Header -->
                <div class="tutorial-header">
                    <h2 id="lessonTitle">Interactive Tutorial</h2>
                    <div class="tutorial-controls">
                        <button id="tutorialMode" class="mode-toggle" title="Switch to reading mode">
                            📖 Reading Mode
                        </button>
                        <button id="closeTutorial" class="close-btn">✕</button>
                    </div>
                </div>

                <!-- Progress Bar -->
                <div class="progress-bar">
                    <div class="progress-fill" id="progressFill" style="width: 0%"></div>
                    <div class="progress-text" id="progressText">Step 1 of 3</div>
                </div>

                <!-- Content Area -->
                <div class="tutorial-content">
                    <!-- Left: Explanation & Visual -->
                    <div class="tutorial-left">
                        <div class="step-title" id="stepTitle">Step Title</div>
                        <div class="step-explanation" id="stepExplanation">Explanation text...</div>
                        <div class="step-visual" id="stepVisual">
                            <!-- Visual aids, diagrams, examples -->
                        </div>
                    </div>

                    <!-- Right: Interactive Task -->
                    <div class="tutorial-right">
                        <div class="task-instruction" id="taskInstruction">Your Task:</div>
                        <div class="task-area" id="taskArea">
                            <!-- Code editor, sliders, pickers, etc. -->
                        </div>
                        <div class="task-hint hidden" id="taskHint">
                            💡 <span id="hintText">Hint text</span>
                        </div>
                        <div class="task-feedback hidden" id="taskFeedback">
                            <!-- Success/error messages -->
                        </div>
                    </div>
                </div>

                <!-- Footer Navigation -->
                <div class="tutorial-footer">
                    <button id="prevStep" class="nav-btn" disabled>← Previous</button>
                    <button id="showHint" class="hint-btn">💡 Show Hint</button>
                    <button id="nextStep" class="nav-btn">Next →</button>
                </div>
            </div>

            <!-- Lesson Selector (when closed) -->
            <div class="lesson-selector hidden" id="lessonSelector">
                <h3>Choose a Lesson</h3>
                <div class="lessons-grid" id="lessonsGrid">
                    <!-- Populated dynamically -->
                </div>
            </div>
        `;

        document.body.appendChild(overlay);
        this.overlay = overlay;  // Store reference | ref:this.overlay usage
    }

    /**
     * Attach event listeners to tutorial controls
     */
    attachEventListeners() {
        // Close button
        document.getElementById('closeTutorial')?.addEventListener('click', () => this.closeTutorial());

        // Navigation
        document.getElementById('nextStep')?.addEventListener('click', () => this.nextStep());
        document.getElementById('prevStep')?.addEventListener('click', () => this.prevStep());

        // Hint
        document.getElementById('showHint')?.addEventListener('click', () => this.showHint());

        // Mode toggle
        document.getElementById('tutorialMode')?.addEventListener('click', () => this.toggleMode());
    }

    /**
     * Start a specific lesson
     */
    startLesson(lessonId) {
        const lesson = this.lessons.find(l => l.id === lessonId);
        if (!lesson) return;

        this.currentLesson = this.lessons.indexOf(lesson);
        this.currentStep = 0;

        this.overlay.classList.remove('hidden');
        this.renderStep();
    }

    /**
     * Render current step with visuals and task
     */
    renderStep() {
        const lesson = this.lessons[this.currentLesson];
        const step = lesson.steps[this.currentStep];

        // Update header
        document.getElementById('lessonTitle').textContent = lesson.title;

        // Update progress
        const progress = ((this.currentStep + 1) / lesson.steps.length) * 100;
        document.getElementById('progressFill').style.width = progress + '%';
        document.getElementById('progressText').textContent =
            `Step ${this.currentStep + 1} of ${lesson.steps.length}`;

        // Update content
        document.getElementById('stepTitle').textContent = step.title;
        document.getElementById('stepExplanation').textContent = step.explanation;

        // Render visual
        this.renderVisual(step.visual);

        // Render task
        this.renderTask(step.task);

        // Update navigation buttons
        document.getElementById('prevStep').disabled = this.currentStep === 0;
        document.getElementById('nextStep').textContent =
            this.currentStep === lesson.steps.length - 1 ? 'Complete! 🎉' : 'Next →';
    }

    /**
     * Render visual aid for current step
     */
    renderVisual(visual) {
        const container = document.getElementById('stepVisual');

        if (typeof visual === 'string' && visual.includes('<div')) {
            // HTML visual
            container.innerHTML = visual;
        } else if (visual === 'preview') {
            // Live preview of user's code
            container.innerHTML = `
                <div class="live-preview">
                    <div class="preview-label">Live Preview:</div>
                    <div class="preview-area" id="livePreview">
                        <!-- User's code rendered here -->
                    </div>
                </div>
            `;
        } else if (visual === 'color-picker') {
            // Interactive color picker
            container.innerHTML = `
                <div class="color-picker-widget">
                    <input type="color" id="colorPicker" value="#00FFFF">
                    <div class="color-preview" id="colorPreview" style="background: #00FFFF"></div>
                </div>
            `;
        } else if (visual === 'diff-viewer') {
            // Before/after code comparison
            container.innerHTML = `
                <div class="diff-viewer">
                    <div class="diff-before">
                        <div class="diff-label">Before (has duplicate):</div>
                        <pre id="diffBefore">// Code before fix</pre>
                    </div>
                    <div class="diff-after">
                        <div class="diff-label">After (fixed):</div>
                        <pre id="diffAfter">// Code after fix</pre>
                    </div>
                </div>
            `;
        }
    }

    /**
     * Render interactive task for current step
     */
    renderTask(task) {
        const container = document.getElementById('taskArea');
        const instruction = document.getElementById('taskInstruction');

        instruction.textContent = task.instruction;

        if (task.type === 'code') {
            // Code editor
            container.innerHTML = `
                <textarea id="codeInput" class="code-editor" rows="6">${task.starter || ''}</textarea>
                <button id="checkCode" class="check-btn">✓ Check My Code</button>
            `;

            document.getElementById('checkCode').addEventListener('click', () => {
                this.checkCode(task);
            });

        } else if (task.type === 'slider') {
            // Interactive slider
            container.innerHTML = `
                <div class="slider-widget">
                    <input type="range" id="propertySlider"
                           min="${task.min}" max="${task.max}" value="${task.min}">
                    <div class="slider-value">
                        <span id="sliderValue">${task.min}</span>${task.unit}
                    </div>
                </div>
            `;

            const slider = document.getElementById('propertySlider');
            slider.addEventListener('input', (e) => {
                document.getElementById('sliderValue').textContent = e.target.value;
                if (task.showLive) {
                    this.updateLivePreview(task.property, e.target.value + task.unit);
                }
            });

        } else if (task.type === 'quiz') {
            // Multiple choice
            container.innerHTML = `
                <div class="quiz-options">
                    ${task.options.map((opt, i) => `
                        <button class="quiz-option" data-correct="${opt.correct}" data-index="${i}">
                            ${opt.text}
                        </button>
                    `).join('')}
                </div>
            `;

            container.querySelectorAll('.quiz-option').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    this.checkQuiz(e.target, task);
                });
            });

        } else if (task.type === 'interactive') {
            // Clickable choices
            container.innerHTML = `
                <div class="interactive-choices">
                    ${task.options.map(opt => `
                        <button class="choice-btn" data-choice="${opt}">${opt}</button>
                    `).join('')}
                </div>
            `;

            container.querySelectorAll('.choice-btn').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    this.checkInteractive(e.target.dataset.choice, task);
                });
            });
        }
    }

    /**
     * Check user's code against solution
     */
    checkCode(task) {
        const code = document.getElementById('codeInput').value;
        const feedback = document.getElementById('taskFeedback');

        if (task.validate(code)) {
            feedback.className = 'task-feedback success';
            feedback.innerHTML = '✅ Perfect! Your code works!';
            feedback.classList.remove('hidden');

            if (task.showLive !== false) {
                this.updateLivePreview(null, code);
            }

            // Enable next button
            document.getElementById('nextStep').disabled = false;

        } else {
            feedback.className = 'task-feedback error';
            feedback.innerHTML = '❌ Not quite right. Check the hint!';
            feedback.classList.remove('hidden');
        }
    }

    /**
     * Check quiz answer
     */
    checkQuiz(button, task) {
        const isCorrect = button.dataset.correct === 'true';
        const feedback = document.getElementById('taskFeedback');

        if (isCorrect) {
            button.classList.add('correct');
            feedback.className = 'task-feedback success';
            feedback.innerHTML = '✅ Correct! ' + task.explanation;
            document.getElementById('nextStep').disabled = false;
        } else {
            button.classList.add('wrong');
            feedback.className = 'task-feedback error';
            feedback.innerHTML = '❌ Try again!';
        }

        feedback.classList.remove('hidden');
    }

    /**
     * Check interactive choice
     */
    checkInteractive(choice, task) {
        const feedback = document.getElementById('taskFeedback');
        const isCorrect = choice === task.correct;

        if (isCorrect) {
            feedback.className = 'task-feedback success';
            feedback.innerHTML = '✅ ' + task.feedback.correct;
            document.getElementById('nextStep').disabled = false;
        } else {
            feedback.className = 'task-feedback error';
            feedback.innerHTML = '❌ ' + task.feedback.wrong;
        }

        feedback.classList.remove('hidden');
    }

    /**
     * Update live preview with user's code/changes
     */
    updateLivePreview(property, value) {
        const preview = document.getElementById('livePreview');
        if (!preview) return;

        if (property) {
            // Update CSS property
            const element = preview.querySelector('.demo-element');
            if (element) {
                element.style[property] = value;
            }
        } else {
            // Render HTML code
            try {
                preview.innerHTML = value;
            } catch (e) {
                preview.innerHTML = '<div class="error">Invalid HTML</div>';
            }
        }
    }

    /**
     * Show hint for current task
     */
    showHint() {
        const lesson = this.lessons[this.currentLesson];
        const step = lesson.steps[this.currentStep];
        const hintEl = document.getElementById('taskHint');
        const hintText = document.getElementById('hintText');

        hintText.textContent = step.task.hint || 'No hint available';
        hintEl.classList.remove('hidden');
    }

    /**
     * Move to next step
     */
    nextStep() {
        const lesson = this.lessons[this.currentLesson];

        if (this.currentStep < lesson.steps.length - 1) {
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
        const lesson = this.lessons[this.currentLesson];
        this.completed.add(lesson.id);
        this.saveProgress();

        // Show completion message
        const content = this.overlay.querySelector('.tutorial-content');
        content.innerHTML = `
            <div class="lesson-complete">
                <div class="complete-icon">🎉</div>
                <h2>Lesson Complete!</h2>
                <p>You've mastered: ${lesson.title}</p>
                <div class="complete-stats">
                    <div class="stat">
                        <div class="stat-value">${lesson.steps.length}</div>
                        <div class="stat-label">Steps Completed</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">${this.completed.size}</div>
                        <div class="stat-label">Total Lessons Done</div>
                    </div>
                </div>
                <button id="nextLesson" class="btn-primary">Next Lesson →</button>
                <button id="backToMenu" class="btn-secondary">Back to Menu</button>
            </div>
        `;

        document.getElementById('nextLesson')?.addEventListener('click', () => {
            if (this.currentLesson < this.lessons.length - 1) {
                this.startLesson(this.lessons[this.currentLesson + 1].id);
            }
        });

        document.getElementById('backToMenu')?.addEventListener('click', () => {
            this.showLessonSelector();
        });
    }

    /**
     * Show lesson selector menu
     */
    showLessonSelector() {
        this.overlay.querySelector('.tutorial-modal').classList.add('hidden');
        this.overlay.querySelector('.lesson-selector').classList.remove('hidden');

        this.renderLessonSelector();
    }

    /**
     * Render lesson selection grid
     */
    renderLessonSelector() {
        const grid = document.getElementById('lessonsGrid');

        grid.innerHTML = this.lessons.map((lesson, i) => {
            const isCompleted = this.completed.has(lesson.id);
            const isLocked = i > 0 && !this.completed.has(this.lessons[i - 1].id);

            return `
                <div class="lesson-card ${isCompleted ? 'completed' : ''} ${isLocked ? 'locked' : ''}"
                     data-lesson-id="${lesson.id}">
                    <div class="lesson-icon">${isCompleted ? '✓' : isLocked ? '🔒' : '▶'}</div>
                    <div class="lesson-info">
                        <h4>${lesson.title}</h4>
                        <p>${lesson.description}</p>
                        <div class="lesson-meta">
                            <span class="difficulty ${lesson.difficulty.toLowerCase()}">${lesson.difficulty}</span>
                            <span class="duration">⏱ ${lesson.duration}</span>
                        </div>
                    </div>
                </div>
            `;
        }).join('');

        // Add click handlers
        grid.querySelectorAll('.lesson-card:not(.locked)').forEach(card => {
            card.addEventListener('click', () => {
                this.startLesson(card.dataset.lessonId);
            });
        });
    }

    /**
     * Toggle between interactive and reading mode
     */
    toggleMode() {
        this.mode = this.mode === 'interactive' ? 'reading' : 'interactive';
        const btn = document.getElementById('tutorialMode');

        if (this.mode === 'reading') {
            btn.textContent = '🎮 Interactive Mode';
            this.showReadingMode();
        } else {
            btn.textContent = '📖 Reading Mode';
            this.renderStep();  // Back to interactive
        }
    }

    /**
     * Show full documentation for current lesson
     */
    showReadingMode() {
        const lesson = this.lessons[this.currentLesson];
        const content = this.overlay.querySelector('.tutorial-content');

        // Show full text version
        content.innerHTML = `
            <div class="reading-mode">
                <h2>${lesson.title}</h2>
                <div class="lesson-description">${lesson.description}</div>

                ${lesson.steps.map((step, i) => `
                    <div class="reading-step">
                        <h3>Step ${i + 1}: ${step.title}</h3>
                        <p>${step.explanation}</p>
                        ${step.visual && typeof step.visual === 'string' ? step.visual : ''}
                        ${step.task.instruction ? `<div class="task-box">
                            <strong>Task:</strong> ${step.task.instruction}
                            ${step.task.solution ? `<pre>${step.task.solution}</pre>` : ''}
                        </div>` : ''}
                    </div>
                `).join('')}

                <button id="backToInteractive" class="btn-primary">
                    Try Interactive Mode →
                </button>
            </div>
        `;

        document.getElementById('backToInteractive')?.addEventListener('click', () => {
            this.toggleMode();
        });
    }

    /**
     * Close tutorial
     */
    closeTutorial() {
        this.overlay.classList.add('hidden');
        this.saveProgress();
    }

    /**
     * Save progress to localStorage
     */
    saveProgress() {
        localStorage.setItem('tutorial_progress', JSON.stringify({
            completed: Array.from(this.completed),
            lastLesson: this.currentLesson,
            mode: this.mode
        }));
    }

    /**
     * Load progress from localStorage
     */
    loadProgress() {
        const saved = localStorage.getItem('tutorial_progress');
        if (saved) {
            const data = JSON.parse(saved);
            this.completed = new Set(data.completed || []);
            this.currentLesson = data.lastLesson || 0;
            this.mode = data.mode || 'interactive';
        }
    }
}

// Export for use in other files
window.InteractiveTutorial = InteractiveTutorial;
