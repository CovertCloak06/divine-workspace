/**
 * Content Formatting Utilities
 * Converts markdown-like syntax to HTML
 * Used for lesson content display
 */

/**
 * Formats lesson content with markdown-like syntax
 * Supports: **bold**, `code`, lists, paragraphs
 * @param {string} content - Raw content string with markdown
 * @returns {string} HTML-formatted content
 * @example
 * formatContent('**Bold** text with `code`')
 * // Returns: '<p><strong>Bold</strong> text with <code>code</code></p>'
 */
export function formatContent(content) {
  // Process lists first | Converts "- item" to <li>item</li>
  let formatted = content.replace(/^- (.+)$/gm, '<li>$1</li>');

  // Wrap consecutive <li> tags in <ul> | Groups list items together
  formatted = formatted.replace(/(<li>.*<\/li>\n?)+/gs, (match) => {
    return '<ul>' + match + '</ul>';
  });

  // Process inline markdown | Bold, code, paragraphs, line breaks
  formatted = formatted
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>') // **bold**
    .replace(/`(.*?)`/g, (match, code) => {
      // Escape HTML entities in code blocks
      return '<code>' + escapeHtml(code) + '</code>';
    }) // `code`
    .replace(/\n\n/g, '</p><p>') // Double newlines = new paragraph
    .replace(/\n/g, '<br>'); // Single newlines = line break

  // Wrap in paragraph if not already wrapped | Ensures proper HTML structure
  if (!formatted.startsWith('<')) {
    formatted = '<p>' + formatted + '</p>';
  }

  return formatted;
}

/**
 * Escapes HTML special characters to prevent XSS
 * @param {string} text - Text to escape
 * @returns {string} Escaped text safe for HTML insertion
 */
export function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;',
  };
  return text.replace(/[&<>"']/g, (char) => map[char]);
}

/**
 * Strips HTML tags from string
 * @param {string} html - HTML string
 * @returns {string} Plain text without HTML tags
 */
export function stripHtml(html) {
  const div = document.createElement('div');
  div.innerHTML = html;
  return div.textContent || div.innerText || '';
}
