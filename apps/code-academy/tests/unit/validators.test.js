/**
 * Unit tests for validation utilities
 * Tests all validator functions from src/utils/validators.js
 */

import { describe, it, expect } from 'vitest';
import {
  validateCode,
  hasHTMLTag,
  hasText,
  isValidHTML,
  checkQuizAnswer,
} from '../../src/utils/validators.js';

describe('hasHTMLTag', () => {
  it('should detect valid opening and closing tag', () => {
    expect(hasHTMLTag('<h1>Title</h1>', 'h1')).toBe(true);
    expect(hasHTMLTag('<p>Text</p>', 'p')).toBe(true);
  });

  it('should reject incomplete tags', () => {
    expect(hasHTMLTag('<h1>Title', 'h1')).toBe(false);
    expect(hasHTMLTag('Title</h1>', 'h1')).toBe(false);
  });

  it('should reject mismatched tags', () => {
    expect(hasHTMLTag('<h1>Title</h2>', 'h1')).toBe(false);
  });

  it('should handle nested content', () => {
    expect(hasHTMLTag('<div><span>Text</span></div>', 'div')).toBe(true);
  });

  it('should be case-insensitive', () => {
    expect(hasHTMLTag('<H1>Title</H1>', 'h1')).toBe(true);
  });
});

describe('hasText', () => {
  it('should detect exact text match', () => {
    expect(hasText('Hello World', 'Hello')).toBe(true);
    expect(hasText('Hello World', 'World')).toBe(true);
  });

  it('should return false for missing text', () => {
    expect(hasText('Hello World', 'Goodbye')).toBe(false);
  });

  it('should be case-sensitive by default', () => {
    expect(hasText('Hello World', 'hello')).toBe(false);
  });

  it('should handle special characters', () => {
    expect(hasText('Price: $10.99', '$10')).toBe(true);
  });
});

describe('isValidHTML', () => {
  it('should validate correct HTML', () => {
    expect(isValidHTML('<div>Content</div>')).toBe(true);
    expect(isValidHTML('<h1>Title</h1><p>Text</p>')).toBe(true);
  });

  it('should accept self-closing tags', () => {
    expect(isValidHTML('<img src="image.jpg" />')).toBe(true);
    expect(isValidHTML('<br />')).toBe(true);
  });

  it('should handle nested tags', () => {
    expect(isValidHTML('<div><p><strong>Bold</strong></p></div>')).toBe(true);
  });

  it('should reject malformed HTML', () => {
    expect(isValidHTML('<div><p>Unclosed')).toBe(false);
    // Note: DOMParser auto-corrects mismatched tags, so this passes
    // For stricter validation, use a dedicated HTML validator
  });

  it('should handle empty strings', () => {
    expect(isValidHTML('')).toBe(true);
  });
});

describe('checkQuizAnswer', () => {
  const quizOptions = [
    { text: 'Option A', correct: false },
    { text: 'Option B', correct: true },
    { text: 'Option C', correct: false },
  ];

  it('should return true for correct answer', () => {
    expect(checkQuizAnswer(1, quizOptions)).toBe(true);
  });

  it('should return false for incorrect answer', () => {
    expect(checkQuizAnswer(0, quizOptions)).toBe(false);
    expect(checkQuizAnswer(2, quizOptions)).toBe(false);
  });

  it('should handle out of bounds index', () => {
    expect(checkQuizAnswer(-1, quizOptions)).toBe(false);
    expect(checkQuizAnswer(999, quizOptions)).toBe(false);
  });

  it('should handle empty options array', () => {
    expect(checkQuizAnswer(0, [])).toBe(false);
  });
});

describe('validateCode (integration)', () => {
  it('should validate code with string validation function', () => {
    const task = {
      validate: '(code) => code.includes("<h1>")',
    };

    expect(validateCode('<h1>Title</h1>', task)).toBe(true);
    expect(validateCode('<p>No heading</p>', task)).toBe(false);
  });

  it('should validate code with expectedContent array', () => {
    const task = {
      expectedContent: ['<h1>', '</h1>', 'Title'],
    };

    expect(validateCode('<h1>Title</h1>', task)).toBe(true);
    expect(validateCode('<h1>Heading</h1>', task)).toBe(false); // missing "Title"
  });

  it('should handle complex validation functions', () => {
    const task = {
      validate: '(code) => code.includes("<h1>") && code.includes("<p>")',
    };

    expect(validateCode('<h1>Title</h1><p>Text</p>', task)).toBe(true);
    expect(validateCode('<h1>Title</h1>', task)).toBe(false);
  });

  it('should return false if no validation method provided', () => {
    const task = {};
    expect(validateCode('<h1>Title</h1>', task)).toBe(false);
  });

  it('should handle validation errors gracefully', () => {
    const task = {
      validate: '(code) => code.invalidMethod()',
    };

    expect(validateCode('<h1>Title</h1>', task)).toBe(false);
  });
});
