/**
 * Theme Utilities
 * Helper functions to get current theme colors from CSS variables
 */

/**
 * Get the current theme primary color
 * @returns {string} The current theme primary color (e.g., '#00ffff')
 */
export function getThemeColor() {
    return getComputedStyle(document.documentElement)
        .getPropertyValue('--theme-primary').trim() || '#00ffff';
}

/**
 * Get the current theme glow color
 * @returns {string} The current theme glow color (rgba format)
 */
export function getThemeGlow() {
    return getComputedStyle(document.documentElement)
        .getPropertyValue('--theme-primary-glow').trim() || 'rgba(0, 255, 255, 0.3)';
}

/**
 * Get the current theme fade color
 * @returns {string} The current theme fade color (rgba format)
 */
export function getThemeFade() {
    return getComputedStyle(document.documentElement)
        .getPropertyValue('--theme-primary-fade').trim() || 'rgba(0, 255, 255, 0.05)';
}

/**
 * Get the current theme dark color
 * @returns {string} The current theme dark color
 */
export function getThemeDark() {
    return getComputedStyle(document.documentElement)
        .getPropertyValue('--theme-primary-dark').trim() || '#00cccc';
}
