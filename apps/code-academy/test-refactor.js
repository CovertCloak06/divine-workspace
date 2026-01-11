#!/usr/bin/env node
/**
 * Quick integration test for refactored TutorialEngine
 * Verifies that the application loads and initializes without errors
 */

import { chromium } from 'playwright';

async function testRefactor() {
  console.log('🧪 Testing refactored application...\n');

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  const errors = [];
  const logs = [];

  // Capture console messages
  page.on('console', (msg) => {
    const text = msg.text();
    logs.push(text);
    console.log(`   [Browser Console] ${text}`);
  });

  // Capture page errors
  page.on('pageerror', (error) => {
    errors.push(error.message);
    console.error(`   ❌ [Page Error] ${error.message}`);
  });

  try {
    // Load the page
    console.log('📄 Loading http://localhost:8011/...');
    await page.goto('http://localhost:8011/', { waitUntil: 'networkidle' });

    // Wait a moment for modules to initialize
    await page.waitForTimeout(2000);

    // Check if TutorialEngine loaded
    const tutorialEngineExists = await page.evaluate(() => {
      return typeof window.TutorialEngine !== 'undefined';
    });

    console.log('\n📊 Test Results:');
    console.log(`   TutorialEngine loaded: ${tutorialEngineExists ? '✅' : '❌'}`);
    console.log(`   Console logs: ${logs.length}`);
    console.log(`   Errors: ${errors.length}`);

    // Check for specific initialization messages
    const hasModularEngineLog = logs.some((log) => log.includes('Modular Tutorial Engine'));
    const hasTutorialEngineInit = logs.some((log) => log.includes('Tutorial Engine'));
    const hasAcademyReady = logs.some((log) => log.includes('DVN Code Academy ready'));

    console.log('\n✅ Success Indicators:');
    console.log(`   "Modular Tutorial Engine" log: ${hasModularEngineLog ? '✅' : '❌'}`);
    console.log(`   "Tutorial Engine" init log: ${hasTutorialEngineInit ? '✅' : '❌'}`);
    console.log(`   "DVN Code Academy ready" log: ${hasAcademyReady ? '✅' : '❌'}`);

    // Test path selection
    console.log('\n🎯 Testing path selection...');
    await page.click('[data-path-id="html"]');
    await page.waitForTimeout(1000);

    const lessonSelectorVisible = await page.isVisible('#lessonSelectorModal:not(.hidden)');
    console.log(`   Lesson selector opened: ${lessonSelectorVisible ? '✅' : '❌'}`);

    // Overall result
    console.log('\n' + '='.repeat(50));
    if (
      errors.length === 0 &&
      tutorialEngineExists &&
      hasModularEngineLog &&
      lessonSelectorVisible
    ) {
      console.log('✅ ALL TESTS PASSED - Refactor successful!');
      console.log('='.repeat(50));
      await browser.close();
      process.exit(0);
    } else {
      console.log('❌ SOME TESTS FAILED - See details above');
      console.log('='.repeat(50));
      await browser.close();
      process.exit(1);
    }
  } catch (error) {
    console.error(`\n❌ Test failed with error: ${error.message}`);
    await browser.close();
    process.exit(1);
  }
}

testRefactor();
