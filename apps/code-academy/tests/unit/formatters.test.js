/**
 * Unit tests for content formatting utilities
 * Tests formatContent function from src/utils/formatters.js
 */

import { describe, it, expect } from 'vitest';
import { formatContent } from '../../src/utils/formatters.js';

describe('formatContent', () => {
  it('should convert markdown-style bold to HTML', () => {
    const result = formatContent('This is **bold** text');
    expect(result).toContain('<strong>bold</strong>');
  });

  it('should convert inline code to HTML', () => {
    const result = formatContent('Use `console.log()` to print');
    expect(result).toContain('<code>console.log()</code>');
  });

  it('should convert markdown lists to HTML', () => {
    const input = `- Item 1
- Item 2
- Item 3`;

    const result = formatContent(input);
    expect(result).toContain('<ul>');
    expect(result).toContain('<li>Item 1</li>');
    expect(result).toContain('<li>Item 2</li>');
    expect(result).toContain('<li>Item 3</li>');
    expect(result).toContain('</ul>');
  });

  it('should convert line breaks correctly', () => {
    const result = formatContent('Line 1\nLine 2');
    expect(result).toContain('<br>');
  });

  it('should convert double line breaks to paragraphs', () => {
    const result = formatContent('Paragraph 1\n\nParagraph 2');
    expect(result).toContain('</p><p>');
  });

  it('should wrap content in paragraph tags if not already wrapped', () => {
    const result = formatContent('Simple text');
    expect(result).toMatch(/^<p>/);
    expect(result).toMatch(/<\/p>$/);
  });

  it('should handle mixed formatting', () => {
    const input =
      'HTML uses **tags** like `<h1>` to structure content.\n\nTags include:\n- Headings\n- Paragraphs\n- Links';

    const result = formatContent(input);

    expect(result).toContain('<strong>tags</strong>');
    expect(result).toContain('<code>&lt;h1&gt;</code>');
    expect(result).toContain('<ul>');
    expect(result).toContain('<li>Headings</li>');
  });

  it('should handle empty strings', () => {
    const result = formatContent('');
    expect(result).toBe('<p></p>');
  });

  it('should not double-wrap already formatted HTML', () => {
    const input = '<div>Already formatted</div>';
    const result = formatContent(input);
    expect(result).toBe(input); // Should not wrap in <p>
  });

  it('should preserve multiple bold sections', () => {
    const result = formatContent('**First** and **second** bold');
    expect(result).toContain('<strong>First</strong>');
    expect(result).toContain('<strong>second</strong>');
  });

  it('should preserve multiple code sections', () => {
    const result = formatContent('Use `const` or `let` for variables');
    expect(result).toContain('<code>const</code>');
    expect(result).toContain('<code>let</code>');
  });

  it('should handle nested markdown (bold in list)', () => {
    const input = '- This is **important**\n- This is `code`';
    const result = formatContent(input);

    expect(result).toContain('<li>This is <strong>important</strong></li>');
    expect(result).toContain('<li>This is <code>code</code></li>');
  });

  it('should handle special characters in code blocks', () => {
    const result = formatContent('Use `<div>` tags');
    expect(result).toContain('<code>&lt;div&gt;</code>');
  });
});
