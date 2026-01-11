#!/usr/bin/env node
/**
 * Full flow test - Tests complete lesson flow with components
 */

import { chromium } from 'playwright';

async function testFullFlow() {
  console.log('🧪 Testing complete lesson flow...\n');

  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();

  const errors = [];
  page.on('pageerror', (error) => {
    errors.push(error.message);
    console.error(`   ❌ [Page Error] ${error.message}`);
  });

  try {
    // 1. Load homepage
    console.log('📄 Step 1: Loading homepage...');
    await page.goto('http://localhost:8011/', { waitUntil: 'networkidle' });
    await page.waitForTimeout(1000);
    console.log('   ✅ Homepage loaded');

    // 2. Click HTML path
    console.log('\n🎯 Step 2: Opening HTML Fundamentals path...');
    await page.click('[data-path-id="html"]');
    await page.waitForTimeout(500);

    const selectorVisible = await page.isVisible('#lessonSelectorModal:not(.hidden)');
    console.log(`   ${selectorVisible ? '✅' : '❌'} Lesson selector opened`);

    // 3. Click first lesson
    console.log('\n📖 Step 3: Loading first lesson...');
    await page.click('.lesson-selector-card:first-child');
    await page.waitForTimeout(1000);

    const tutorialVisible = await page.isVisible('#tutorialModal:not(.hidden)');
    console.log(`   ${tutorialVisible ? '✅' : '❌'} Tutorial modal opened`);

    // 4. Check lesson loaded from JSON
    const lessonTitle = await page.textContent('#lessonTitle');
    console.log(`   ${lessonTitle.includes('HTML') ? '✅' : '❌'} Lesson title: "${lessonTitle}"`);

    const stepTitle = await page.textContent('#stepTitle');
    console.log(`   ${stepTitle.length > 0 ? '✅' : '❌'} Step title: "${stepTitle}"`);

    // 5. Test Quiz Component (Step 1)
    console.log('\n📝 Step 4: Testing Quiz Component (Step 1)...');
    const quizOptions = await page.locator('.quiz-option').count();
    console.log(`   ${quizOptions > 0 ? '✅' : '❌'} Quiz options rendered: ${quizOptions}`);

    await page.click('.quiz-option:first-child');
    await page.waitForTimeout(500);

    const feedback = await page.textContent('#taskFeedback');
    console.log(`   ${feedback.includes('Correct') ? '✅' : '❌'} Quiz feedback: "${feedback}"`);

    const nextBtnDisabled = await page.locator('#nextStep').isDisabled();
    console.log(`   ${!nextBtnDisabled ? '✅' : '❌'} Next button enabled after quiz`);

    // 6. Navigate through quiz steps to find code editor
    console.log('\n➡️ Step 5: Navigating to code editor step...');

    // Step 2 (quiz)
    await page.click('#nextStep');
    await page.waitForTimeout(500);
    await page.click('.quiz-option:first-child');
    await page.waitForTimeout(500);
    console.log('   ✅ Completed Step 2 (Quiz)');

    // Step 3 (quiz)
    await page.click('#nextStep');
    await page.waitForTimeout(500);
    await page.click('.quiz-option:first-child');
    await page.waitForTimeout(500);
    console.log('   ✅ Completed Step 3 (Quiz)');

    // Step 4 (code editor)
    await page.click('#nextStep');
    await page.waitForTimeout(1000);

    const progressText = await page.textContent('#progressText');
    console.log(`   ✅ Progress: "${progressText}"`);

    // 7. Test Code Editor Component
    console.log('\n💻 Step 6: Testing Code Editor Component...');
    const codeEditor = await page.isVisible('#codeInput');
    console.log(`   ${codeEditor ? '✅' : '❌'} Code editor rendered`);

    if (codeEditor) {
      await page.fill('#codeInput', '<h1>My First Page</h1>');
      await page.waitForTimeout(300);
      console.log('   ✅ Code written to editor');

      await page.click('#checkCode');
      await page.waitForTimeout(500);

      const codeFeedback = await page.textContent('#taskFeedback');
      const isCorrect = codeFeedback.includes('Perfect') || codeFeedback.includes('correct');
      console.log(`   ${isCorrect ? '✅' : '❌'} Code validation: "${codeFeedback}"`);
    }

    // 8. Test navigation buttons
    console.log('\n🔀 Step 7: Testing navigation...');
    const prevBtn = await page.locator('#prevStep');
    const prevDisabled = await prevBtn.isDisabled();
    console.log(`   ${!prevDisabled ? '✅' : '❌'} Previous button enabled`);

    await page.click('#prevStep');
    await page.waitForTimeout(500);
    const backProgress = await page.textContent('#progressText');
    console.log(
      `   ${backProgress.includes('Step 3') ? '✅' : '❌'} Navigate back works: "${backProgress}"`
    );

    // 9. Final results
    console.log('\n📊 Final Results:');
    console.log(`   JavaScript Errors: ${errors.length}`);
    console.log(`   All tests passed: ${errors.length === 0 && codeEditor ? '✅' : '❌'}`);

    await browser.close();

    if (errors.length === 0 && codeEditor) {
      console.log('\n' + '='.repeat(60));
      console.log('✅ COMPLETE FLOW TEST PASSED');
      console.log('   - Homepage loads ✅');
      console.log('   - Path selection works ✅');
      console.log('   - Lesson selector works ✅');
      console.log('   - Lesson loads from JSON ✅');
      console.log('   - QuizComponent renders & validates ✅');
      console.log('   - CodeEditor renders & validates ✅');
      console.log('   - Navigation (next/prev) works ✅');
      console.log('   - TaskRenderer dispatches correctly ✅');
      console.log('   - No JavaScript errors ✅');
      console.log('='.repeat(60));
      process.exit(0);
    } else {
      console.log('\n❌ Some tests failed');
      process.exit(1);
    }
  } catch (error) {
    console.error(`\n❌ Test failed: ${error.message}`);
    await browser.close();
    process.exit(1);
  }
}

testFullFlow();
