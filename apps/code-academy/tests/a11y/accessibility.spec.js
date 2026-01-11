/**
 * Accessibility Tests
 * Uses axe-core to check for accessibility issues
 */

import AxeBuilder from '@axe-core/playwright';
import { test, expect } from '@playwright/test';

test.describe('Accessibility Tests', () => {
  test('homepage should have no automatically detectable accessibility issues', async ({
    page,
  }) => {
    await page.goto('http://localhost:8011/');

    const accessibilityScanResults = await new AxeBuilder({ page }).analyze();

    expect(accessibilityScanResults.violations).toEqual([]);
  });

  test('lesson selector should be accessible', async ({ page }) => {
    await page.goto('http://localhost:8011/');

    // Open lesson selector
    await page.click('[data-path-id="html"]');
    await page.waitForSelector('#lessonSelectorModal:not(.hidden)');

    const accessibilityScanResults = await new AxeBuilder({ page }).analyze();

    expect(accessibilityScanResults.violations).toEqual([]);
  });

  test('tutorial modal should be accessible', async ({ page }) => {
    await page.goto('http://localhost:8011/');

    // Open tutorial
    await page.click('[data-path-id="html"]');
    await page.click('.lesson-selector-card:first-child');
    await page.waitForSelector('#tutorialModal:not(.hidden)');

    const accessibilityScanResults = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
      .analyze();

    expect(accessibilityScanResults.violations).toEqual([]);
  });

  test('quiz component should be keyboard accessible', async ({ page }) => {
    await page.goto('http://localhost:8011/');

    // Navigate to lesson with quiz
    await page.click('[data-path-id="html"]');
    await page.click('.lesson-selector-card:first-child');
    await page.waitForSelector('.quiz-option');

    // Should be able to tab to quiz options
    await page.keyboard.press('Tab');
    const focusedElement = await page.evaluate(() => document.activeElement?.className);

    // Check that quiz options are in tab order
    expect(focusedElement).toContain('quiz-option');
  });

  test('code editor should be keyboard accessible', async ({ page }) => {
    await page.goto('http://localhost:8011/');

    // Navigate to code editor step
    await page.click('[data-path-id="html"]');
    await page.click('.lesson-selector-card:first-child');

    // Complete quiz steps to get to code editor
    for (let i = 0; i < 3; i++) {
      await page.click('.quiz-option:first-child');
      await page.click('#nextStep');
      await page.waitForTimeout(300);
    }

    // Code editor should be focusable
    const codeEditor = await page.locator('#codeInput');
    await codeEditor.focus();

    const isFocused = await page.evaluate(() => {
      return document.activeElement?.id === 'codeInput';
    });

    expect(isFocused).toBe(true);
  });

  test('navigation buttons should have descriptive labels', async ({ page }) => {
    await page.goto('http://localhost:8011/');

    await page.click('[data-path-id="html"]');
    await page.click('.lesson-selector-card:first-child');

    // Check button text is descriptive
    const nextBtn = await page.textContent('#nextStep');
    const prevBtn = await page.textContent('#prevStep');
    const hintBtn = await page.textContent('#showHint');

    expect(nextBtn).toBeTruthy();
    expect(prevBtn).toBeTruthy();
    expect(hintBtn).toBeTruthy();
  });
});
