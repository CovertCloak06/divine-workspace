import assert from 'node:assert/strict';
import { test } from 'node:test';
import { loadConfig } from '../src/config.js';

const base = { PUSHOVER_TOKEN: 'aToken', PUSHOVER_USER: 'uUser' };

test('valid MAX_PRICE parses to a number', () => {
  const cfg = loadConfig({ ...base, MAX_PRICE: '200' } as NodeJS.ProcessEnv);
  assert.equal(cfg.maxPrice, 200);
});

test('blank MAX_PRICE means no cap (undefined)', () => {
  const cfg = loadConfig({ ...base, MAX_PRICE: '' } as NodeJS.ProcessEnv);
  assert.equal(cfg.maxPrice, undefined);
});

test('non-numeric MAX_PRICE is rejected rather than silently disabling the cap', () => {
  assert.throws(
    () => loadConfig({ ...base, MAX_PRICE: 'abc' } as NodeJS.ProcessEnv),
    /MAX_PRICE/,
  );
});

test('negative MAX_PRICE is rejected', () => {
  assert.throws(() => loadConfig({ ...base, MAX_PRICE: '-5' } as NodeJS.ProcessEnv), /MAX_PRICE/);
});

test('missing Pushover credentials is a clear error', () => {
  assert.throws(() => loadConfig({} as NodeJS.ProcessEnv), /PUSHOVER_TOKEN/);
});
