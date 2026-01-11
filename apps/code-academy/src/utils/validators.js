/**
 * Code Validation Utilities
 * Functions to validate user code submissions
 */

/**
 * Validates code against task requirements
 * @param {string} code - User's code submission
 * @param {Object} task - Task object with validation rules
 * @param {string} task.validate - Validation function as string (to be eval'd)
 * @param {Array<string>} [task.expectedContent] - Expected strings in code (fallback)
 * @returns {boolean} True if code is valid
 */
export function validateCode(code, task) {
  try {
    // Use Function constructor instead of eval for better security
    // Task validation is a string like "(code) => code.includes('<h1>')"
    if (task.validate) {
      // eslint-disable-next-line no-new-func
      const validateFn = new Function('return ' + task.validate)();
      return validateFn(code);
    }
  } catch (error) {
    console.warn('Validation function error, using fallback:', error);
  }

  // Fallback: check if code contains expected content
  if (task.expectedContent && Array.isArray(task.expectedContent)) {
    return task.expectedContent.every((content) => code.includes(content));
  }

  // No validation method provided - return false
  return false;
}

/**
 * Checks if code contains specific HTML tag
 * @param {string} code - Code to check
 * @param {string} tag - Tag name (e.g., 'h1', 'p')
 * @returns {boolean} True if tag found
 * @example
 * hasHTMLTag('<h1>Title</h1>', 'h1') // true
 * hasHTMLTag('<h1>Title', 'h1') // false (incomplete)
 */
export function hasHTMLTag(code, tag) {
  const regex = new RegExp(`<${tag}>.*</${tag}>`, 'is');
  return regex.test(code);
}

/**
 * Checks if code contains specific text
 * @param {string} code - Code to check
 * @param {string} text - Text to find
 * @returns {boolean} True if text found
 */
export function hasText(code, text) {
  return code.includes(text);
}

/**
 * Validates HTML syntax
 * @param {string} code - HTML code to validate
 * @returns {boolean} True if valid HTML
 */
export function isValidHTML(code) {
  try {
    const parser = new DOMParser();
    const doc = parser.parseFromString(code, 'text/html');

    // Check for parser errors
    const hasParseError = doc.querySelector('parsererror');
    if (hasParseError) {
      return false;
    }

    // Additional check: ensure opening tags have matching closing tags
    const openTags = code.match(/<([a-z][a-z0-9]*)\b[^>]*>/gi) || [];
    const closeTags = code.match(/<\/([a-z][a-z0-9]*)>/gi) || [];

    // Filter out self-closing tags like <img />, <br />
    const nonSelfClosing = openTags.filter(
      (tag) => !tag.endsWith('/>') && !/^<(img|br|hr|input|meta|link)/.test(tag)
    );

    // Basic check: should have same number of open and close tags
    if (nonSelfClosing.length > 0 && closeTags.length === 0) {
      return false;
    }

    return true;
  } catch (error) {
    return false;
  }
}

/**
 * Checks if code has both opening and closing tags
 * @param {string} code - Code to check
 * @param {string} tag - Tag name
 * @returns {boolean} True if has both
 */
export function hasMatchingTags(code, tag) {
  const openCount = (code.match(new RegExp(`<${tag}>`, 'g')) || []).length;
  const closeCount = (code.match(new RegExp(`</${tag}>`, 'g')) || []).length;
  return openCount > 0 && openCount === closeCount;
}

/**
 * Validates CSS syntax (basic)
 * @param {string} code - CSS code to validate
 * @returns {boolean} True if looks like valid CSS
 */
export function isValidCSS(code) {
  // Basic check: has selector and curly braces
  const hasSelector = /[a-zA-Z0-9#.[\]]+\s*{/.test(code);
  const hasClosingBrace = code.includes('}');
  return hasSelector && hasClosingBrace;
}

/**
 * Validates JavaScript syntax (basic)
 * @param {string} code - JS code to validate
 * @returns {boolean} True if valid JS syntax
 */
export function isValidJS(code) {
  try {
    // Try to parse as function body
    new Function(code);
    return true;
  } catch (error) {
    return false;
  }
}

/**
 * Checks quiz answer correctness
 * @param {number} selectedIndex - Index of selected option
 * @param {Array<Object>} options - Quiz options array
 * @param {boolean} options[].correct - Whether option is correct
 * @returns {boolean} True if correct answer selected
 */
export function checkQuizAnswer(selectedIndex, options) {
  if (selectedIndex < 0 || selectedIndex >= options.length) {
    return false;
  }
  return options[selectedIndex].correct === true;
}
