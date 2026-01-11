/**
 * Theme Manager for DVN Code Academy
 * Handles light/dark theme switching with localStorage persistence
 */

class ThemeManager {
  constructor() {
    this.currentTheme = this.loadTheme();
    this.init();
  }

  /**
   * Initialize theme system
   */
  init() {
    // Apply saved theme
    this.applyTheme(this.currentTheme);

    // Create theme toggle button
    this.createToggleButton();

    // Listen for system theme changes (optional)
    if (window.matchMedia) {
      window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
        if (!localStorage.getItem('dvn_academy_theme')) {
          // Only auto-switch if user hasn't manually set a preference
          this.setTheme(e.matches ? 'dark' : 'light');
        }
      });
    }
  }

  /**
   * Load theme from localStorage or detect system preference
   */
  loadTheme() {
    const saved = localStorage.getItem('dvn_academy_theme');
    if (saved) {
      return saved;
    }

    // Detect system preference
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      return 'dark';
    }

    return 'light'; // Default to light
  }

  /**
   * Apply theme to document
   */
  applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    this.currentTheme = theme;

    // Update toggle button if it exists
    const toggleBtn = document.getElementById('themeToggle');
    if (toggleBtn) {
      const icon = theme === 'dark' ? '☀️' : '🌙';
      const text = theme === 'dark' ? 'Light Mode' : 'Dark Mode';
      toggleBtn.innerHTML = `${icon} <span class="theme-toggle-text">${text}</span>`;
      toggleBtn.setAttribute('aria-label', `Switch to ${text}`);
    }
  }

  /**
   * Set and save theme
   */
  setTheme(theme) {
    this.applyTheme(theme);
    localStorage.setItem('dvn_academy_theme', theme);

    // Dispatch event for other components
    window.dispatchEvent(new CustomEvent('themeChanged', { detail: { theme } }));
  }

  /**
   * Toggle between light and dark
   */
  toggleTheme() {
    const newTheme = this.currentTheme === 'dark' ? 'light' : 'dark';
    this.setTheme(newTheme);
  }

  /**
   * Create theme toggle button in navbar
   */
  createToggleButton() {
    const navLinks = document.querySelector('.nav-links');
    if (!navLinks) {
      return;
    }

    const toggleBtn = document.createElement('button');
    toggleBtn.id = 'themeToggle';
    toggleBtn.className = 'theme-toggle-btn';
    toggleBtn.setAttribute('aria-label', 'Toggle theme');

    const icon = this.currentTheme === 'dark' ? '☀️' : '🌙';
    const text = this.currentTheme === 'dark' ? 'Light Mode' : 'Dark Mode';
    toggleBtn.innerHTML = `${icon} <span class="theme-toggle-text">${text}</span>`;

    toggleBtn.addEventListener('click', () => {
      this.toggleTheme();

      // Add ripple effect
      toggleBtn.classList.add('theme-toggle-active');
      setTimeout(() => {
        toggleBtn.classList.remove('theme-toggle-active');
      }, 300);
    });

    navLinks.appendChild(toggleBtn);
  }

  /**
   * Get current theme
   */
  getCurrentTheme() {
    return this.currentTheme;
  }
}

// Initialize theme manager
window.ThemeManager = new ThemeManager();
