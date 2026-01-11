#!/usr/bin/env node
import { chromium } from 'playwright';

async function test() {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();

  page.on('console', (msg) => console.log(`[Browser] ${msg.text()}`));
  page.on('pageerror', (err) => console.error(`[Error] ${err.message}`));

  await page.goto('http://localhost:8011/');
  await page.waitForTimeout(2000);

  await browser.close();
}

test();
