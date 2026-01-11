/**
 * DVN Code Academy - Main Application
 * Handles navigation, path selection, and general UI interactions
 * ref:index.html, tutorial-engine.js, progress-tracker.js, code-playground.js
 */

class DVNAcademy {
  constructor() {
    this.currentPath = null; // Current learning path selected
    this.init(); // Initialize the application
  }

  /**
   * Initialize the academy application
   */
  init() {
    console.log('🎓 DVN Code Academy initializing...');

    this.attachEventListeners(); // Wire up all UI interactions
    this.loadProgress(); // Load user's saved progress
    this.updateDashboard(); // Update progress dashboard stats
    this.initializePlayground(); // Set up code playground

    console.log('✅ DVN Code Academy ready!');
  }

  /**
   * Attach event listeners to UI elements
   */
  attachEventListeners() {
    // Hero "Start Learning" button | Navigate to curriculum section
    document.getElementById('startLearning')?.addEventListener('click', () => {
      document.getElementById('curriculum')?.scrollIntoView({ behavior: 'smooth' });
    });

    // Path selection buttons | Open specific learning path
    document.querySelectorAll('.path-btn').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const pathId = e.target.dataset.pathId;
        this.selectPath(pathId);
      });
    });

    // Path cards (click anywhere) | Alternative way to select path
    document.querySelectorAll('.path-card').forEach((card) => {
      card.addEventListener('click', (e) => {
        // Don't trigger if button was clicked (avoid double trigger)
        if (e.target.classList.contains('path-btn')) {
          return;
        }

        const pathId = card.dataset.path;
        this.selectPath(pathId);
      });
    });

    // Navigation links | Smooth scroll to sections
    document.querySelectorAll('.nav-link').forEach((link) => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const target = link.getAttribute('href');

        // Remove active from all links
        document.querySelectorAll('.nav-link').forEach((l) => l.classList.remove('active'));
        // Add active to clicked link
        link.classList.add('active');

        // Scroll to target section
        if (target !== '#home') {
          document.querySelector(target)?.scrollIntoView({ behavior: 'smooth' });
        } else {
          window.scrollTo({ top: 0, behavior: 'smooth' });
        }
      });
    });

    // Playground "Open Full" button | Expand playground to fullscreen
    document.getElementById('openFullPlayground')?.addEventListener('click', () => {
      this.openFullPlayground();
    });

    // Playground refresh button | Refresh preview iframe
    document.getElementById('refreshPreview')?.addEventListener('click', () => {
      this.refreshPlaygroundPreview();
    });

    // Code editor live updates | Update preview as user types
    document.getElementById('playgroundCode')?.addEventListener('input', () => {
      // Debounce to avoid updating on every keystroke
      clearTimeout(this.playgroundUpdateTimeout);
      this.playgroundUpdateTimeout = setTimeout(() => {
        this.updatePlaygroundPreview();
      }, 500);
    });
  }

  /**
   * Select a learning path and open tutorial
   */
  selectPath(pathId) {
    console.log(`📚 Selected path: ${pathId}`);
    this.currentPath = pathId;

    // Get path data
    const pathData = this.getPathData(pathId);

    if (!pathData) {
      console.error(`Path "${pathId}" not found`);
      return;
    }

    // Launch tutorial engine for this path | ref:tutorial-engine.js
    if (window.TutorialEngine) {
      window.TutorialEngine.startPath(pathId, pathData);
    } else {
      console.error('TutorialEngine not loaded');
      alert('Tutorial system is loading... Please try again in a moment.');
    }
  }

  /**
   * Get learning path configuration data
   */
  getPathData(pathId) {
    const paths = {
      html: {
        id: 'html',
        name: 'HTML Fundamentals',
        icon: '🎯',
        description: 'Build web pages from scratch. Learn tags, elements, and structure.',
        lessons: [
          {
            id: 'html-01',
            title: 'Your First HTML Page',
            description: 'Create a basic HTML document',
            content: 'lessons/html/lesson-01.json',
          },
          {
            id: 'html-02',
            title: 'HTML Tags & Elements',
            description: 'Understand the building blocks of HTML',
            content: 'lessons/html/lesson-02.json',
          },
          {
            id: 'html-03',
            title: 'Links & Images',
            description: 'Add navigation and media to your pages',
            content: 'lessons/html/lesson-03.json',
          },
          {
            id: 'html-04',
            title: 'Forms & Input',
            description: 'Collect user input with forms',
            content: 'lessons/html/lesson-04.json',
          },
          {
            id: 'html-05',
            title: 'Semantic HTML',
            description: 'Write meaningful, accessible HTML',
            content: 'lessons/html/lesson-05.json',
          },
        ],
      },
      css: {
        id: 'css',
        name: 'CSS Styling',
        icon: '🎨',
        description: 'Make your pages beautiful. Colors, layouts, animations.',
        lessons: [
          {
            id: 'css-01',
            title: 'CSS Basics',
            description: 'Selectors, properties, and values',
            content: 'lessons/css/lesson-01.json',
          },
          {
            id: 'css-02',
            title: 'Colors & Typography',
            description: 'Style text and choose colors',
            content: 'lessons/css/lesson-02.json',
          },
          {
            id: 'css-03',
            title: 'Box Model',
            description: 'Understand padding, margin, and borders',
            content: 'lessons/css/lesson-03.json',
          },
          {
            id: 'css-04',
            title: 'Flexbox Layout',
            description: 'Create flexible, responsive layouts',
            content: 'lessons/css/lesson-04.json',
          },
          {
            id: 'css-05',
            title: 'Grid Layout',
            description: 'Advanced 2D layouts with CSS Grid',
            content: 'lessons/css/lesson-05.json',
          },
          {
            id: 'css-06',
            title: 'Animations',
            description: 'Add motion and transitions',
            content: 'lessons/css/lesson-06.json',
          },
        ],
      },
      js: {
        id: 'js',
        name: 'JavaScript Basics',
        icon: '⚡',
        description: 'Add interactivity. Click events, variables, functions.',
        lessons: [
          {
            id: 'js-01',
            title: 'JavaScript Introduction',
            description: 'What is JavaScript and how does it work?',
            content: 'lessons/js/lesson-01.json',
          },
          {
            id: 'js-02',
            title: 'Variables & Data Types',
            description: 'Store and manipulate data',
            content: 'lessons/js/lesson-02.json',
          },
          {
            id: 'js-03',
            title: 'Functions',
            description: 'Create reusable blocks of code',
            content: 'lessons/js/lesson-03.json',
          },
          {
            id: 'js-04',
            title: 'DOM Manipulation',
            description: 'Change web pages with JavaScript',
            content: 'lessons/js/lesson-04.json',
          },
          {
            id: 'js-05',
            title: 'Events',
            description: 'Respond to user interactions',
            content: 'lessons/js/lesson-05.json',
          },
          {
            id: 'js-06',
            title: 'Arrays & Objects',
            description: 'Work with collections of data',
            content: 'lessons/js/lesson-06.json',
          },
          {
            id: 'js-07',
            title: 'Conditionals & Loops',
            description: 'Control program flow',
            content: 'lessons/js/lesson-07.json',
          },
          {
            id: 'js-08',
            title: 'Fetch API',
            description: 'Load data from servers',
            content: 'lessons/js/lesson-08.json',
          },
        ],
      },
      debugging: {
        id: 'debugging',
        name: 'Debugging Mastery',
        icon: '🔧',
        description: 'Fix bugs like a pro. Learn tools, techniques, best practices.',
        lessons: [
          {
            id: 'debug-01',
            title: 'Browser DevTools',
            description: 'Master Chrome/Firefox developer tools',
            content: 'lessons/debugging/lesson-01.json',
          },
          {
            id: 'debug-02',
            title: 'Common Errors',
            description: 'Understand and fix typical bugs',
            content: 'lessons/debugging/lesson-02.json',
          },
          {
            id: 'debug-03',
            title: 'Best Practices',
            description: 'Write clean, maintainable code',
            content: 'lessons/debugging/lesson-03.json',
          },
          {
            id: 'debug-04',
            title: 'Code Quality Tools',
            description: 'Use linters, formatters, and analyzers',
            content: 'lessons/debugging/lesson-04.json',
          },
        ],
      },
      projects: {
        id: 'projects',
        name: 'Project Building',
        icon: '🚀',
        description:
          'Build real projects from scratch. Learn terminal commands and professional workflows.',
        lessons: [
          {
            id: 'project-builder-01',
            title: 'Build Your First Website Project',
            description: 'Learn project structure with terminal commands',
            content: 'lessons/project-builder-demo.json',
          },
        ],
      },
    };

    return paths[pathId] || null;
  }

  /**
   * Load user progress from localStorage
   */
  loadProgress() {
    if (window.ProgressTracker) {
      window.ProgressTracker.loadProgress();
      console.log('📊 Progress loaded');
    }
  }

  /**
   * Update dashboard statistics
   */
  updateDashboard() {
    if (!window.ProgressTracker) {
      return;
    }

    const stats = window.ProgressTracker.getStats();

    // Update stat cards
    document.getElementById('totalLessonsComplete').textContent = stats.lessonsCompleted || 0;
    document.getElementById('currentStreak').textContent = stats.dayStreak || 0;
    document.getElementById('totalChallenges').textContent = stats.challengesSolved || 0;
    document.getElementById('badgesEarned').textContent = stats.badges || 0;

    // Update lesson count in hero
    document.getElementById('lessonCount').textContent = `${stats.totalLessons || 23}+`;
  }

  /**
   * Initialize code playground with live preview
   */
  initializePlayground() {
    // Initialize with demo code
    this.updatePlaygroundPreview();
  }

  /**
   * Update playground preview iframe with current code
   */
  updatePlaygroundPreview() {
    const code = document.getElementById('playgroundCode')?.value || '';
    const iframe = document.getElementById('previewFrame');

    if (!iframe) {
      return;
    }

    // Create HTML document with code
    const fullHTML = `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    body {
                        margin: 0;
                        padding: 20px;
                        font-family: Arial, sans-serif;
                    }
                </style>
            </head>
            <body>
                ${code}
            </body>
            </html>
        `;

    // Update iframe content
    iframe.srcdoc = fullHTML;
  }

  /**
   * Refresh playground preview (reload iframe)
   */
  refreshPlaygroundPreview() {
    this.updatePlaygroundPreview();
  }

  /**
   * Open playground in fullscreen mode
   */
  openFullPlayground() {
    // TODO: Implement fullscreen playground modal
    // For now, just show an alert
    alert('Full playground feature coming soon! For now, you can expand your browser window.');
  }
}

// Initialize academy when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  window.dvnAcademy = new DVNAcademy();
});
