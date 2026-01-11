/**
 * Integration tests for lesson flow
 * Tests TutorialEngine coordinating with components
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

// Setup DOM environment for testing
const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>');
global.window = dom.window;
global.document = dom.window.document;
global.DOMParser = dom.window.DOMParser;

describe('Lesson Flow Integration', () => {
  beforeEach(() => {
    // Reset DOM for each test
    document.body.innerHTML = '';
  });

  it('should load and initialize TutorialEngine', async () => {
    const { default: TutorialEngine } = await import('../../src/core/TutorialEngine.js');

    const engine = new TutorialEngine();
    expect(engine).toBeDefined();
    expect(engine.currentLesson).toBeNull();
    expect(engine.currentStep).toBe(0);
  });

  it('should create tutorial modal on initialization', async () => {
    const { default: TutorialEngine } = await import('../../src/core/TutorialEngine.js');

    const engine = new TutorialEngine();
    const modal = document.getElementById('tutorialModal');

    expect(modal).toBeDefined();
    expect(modal.classList.contains('hidden')).toBe(true);
  });

  it('should initialize with LessonLoader service', async () => {
    const { default: TutorialEngine } = await import('../../src/core/TutorialEngine.js');

    const engine = new TutorialEngine();
    expect(engine.lessonLoader).toBeDefined();
    expect(engine.lessonLoader.cache).toBeDefined();
  });

  it('should create lesson selector modal', async () => {
    const { default: TutorialEngine } = await import('../../src/core/TutorialEngine.js');

    const engine = new TutorialEngine();
    const selectorModal = document.getElementById('lessonSelectorModal');

    expect(selectorModal).toBeDefined();
    expect(selectorModal.classList.contains('hidden')).toBe(true);
  });

  it('should have navigation buttons in modal', async () => {
    const { default: TutorialEngine } = await import('../../src/core/TutorialEngine.js');

    const engine = new TutorialEngine();

    const prevBtn = document.getElementById('prevStep');
    const nextBtn = document.getElementById('nextStep');
    const hintBtn = document.getElementById('showHint');

    expect(prevBtn).toBeDefined();
    expect(nextBtn).toBeDefined();
    expect(hintBtn).toBeDefined();
  });
});

describe('LessonLoader Service', () => {
  it('should cache loaded lessons', async () => {
    const { default: LessonLoader } = await import('../../src/services/LessonLoader.js');

    const loader = new LessonLoader();
    expect(loader.cache).toBeDefined();
    expect(loader.cache.size).toBe(0);
  });

  it('should validate lesson data structure', async () => {
    const { default: LessonLoader } = await import('../../src/services/LessonLoader.js');

    const loader = new LessonLoader();

    const validLesson = {
      id: 'test-01',
      title: 'Test Lesson',
      steps: [
        {
          title: 'Step 1',
          content: 'Content',
          task: { type: 'info', instruction: 'Do something' },
        },
      ],
    };

    expect(() => loader.validateLessonData(validLesson)).not.toThrow();
  });

  it('should throw error for invalid lesson data', async () => {
    const { default: LessonLoader } = await import('../../src/services/LessonLoader.js');

    const loader = new LessonLoader();

    const invalidLesson = {
      id: 'test-01',
      // Missing required fields
    };

    expect(() => loader.validateLessonData(invalidLesson)).toThrow();
  });
});

describe('TaskRenderer Component', () => {
  beforeEach(() => {
    document.body.innerHTML =
      '<div id="taskArea"></div><div id="taskFeedback"></div><button id="nextStep"></button>';
  });

  it('should render info task correctly', async () => {
    const { default: TaskRenderer } = await import('../../src/components/TaskRenderer.js');

    const container = document.getElementById('taskArea');
    const renderer = new TaskRenderer(container, () => {});

    const task = {
      type: 'info',
      instruction: 'Read this',
      content: 'Info content',
    };

    renderer.render(task, 0);

    expect(container.innerHTML).toContain('Info content');
  });

  it('should enable next button for info tasks', async () => {
    const { default: TaskRenderer } = await import('../../src/components/TaskRenderer.js');

    const container = document.getElementById('taskArea');
    const renderer = new TaskRenderer(container, () => {});

    const task = {
      type: 'info',
      instruction: 'Read this',
      content: 'Info content',
    };

    renderer.render(task, 0);

    const nextBtn = document.getElementById('nextStep');
    expect(nextBtn.disabled).toBe(false);
  });

  it('should store code from code editor', async () => {
    const { default: TaskRenderer } = await import('../../src/components/TaskRenderer.js');

    const container = document.getElementById('taskArea');
    const renderer = new TaskRenderer(container, () => {});

    const task = {
      type: 'code',
      instruction: 'Write code',
      starter: '<h1></h1>',
      validate: '(code) => code.includes("<h1>")',
    };

    renderer.render(task, 0);

    const stepCode = renderer.getStepCode();
    expect(stepCode).toBeDefined();
  });
});
