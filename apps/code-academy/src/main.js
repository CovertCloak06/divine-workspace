/**
 * Code Academy - Main Entry Point
 * Loads all modules and initializes the application
 */

// Core
import Academy from './core/Academy.js';
import TutorialEngine from './core/TutorialEngine.js';

// Services
import LessonLoader from './services/LessonLoader.js';

// Components
import TaskRenderer from './components/TaskRenderer.js';
import CodeEditor from './components/CodeEditor.js';
import QuizComponent from './components/QuizComponent.js';
import CodePlayground from './components/CodePlayground.js';
import ChallengeEditor from './components/ChallengeEditor.js';
import GuidedEditor from './components/GuidedEditor.js';
import TerminalWidget from './components/TerminalWidget.js';
import VisualAdjuster from './components/VisualAdjuster.js';
import ErrorBoundary from './components/ErrorBoundary.js';

// Managers
import ThemeManager from './managers/ThemeManager.js';
import ProgressTracker from './managers/ProgressTracker.js';

// Utils
import { formatContent } from './utils/formatters.js';
import * as validators from './utils/validators.js';

// Initialize the application
console.log('✅ Code Academy modules loaded');

// Make Academy available globally for backward compatibility
window.Academy = Academy;
window.TutorialEngine = TutorialEngine;

// Auto-initialize on DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        console.log('🚀 Code Academy initialized');
    });
} else {
    console.log('🚀 Code Academy initialized');
}

export {
    Academy,
    TutorialEngine,
    LessonLoader,
    TaskRenderer,
    CodeEditor,
    QuizComponent,
    ThemeManager,
    ProgressTracker,
    formatContent,
    validators
};
