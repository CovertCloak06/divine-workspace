import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { Store } from '../src/store.js';

test('store persists and reloads state', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'sw-'));
  const path = join(dir, 'state.json');
  try {
    const a = new Store(path);
    await a.load();
    assert.equal(a.size(), 0);
    a.set('100', { soldOut: false, price: 48 });
    a.set('101', { soldOut: true, price: 168 });
    await a.save();

    const b = new Store(path);
    await b.load();
    assert.equal(b.size(), 2);
    assert.deepEqual(b.get('100'), { soldOut: false, price: 48 });
    assert.equal(b.has('101'), true);
    assert.equal(b.has('999'), false);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('missing file loads as empty without throwing', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'sw-'));
  try {
    const s = new Store(join(dir, 'does-not-exist.json'));
    await s.load();
    assert.equal(s.size(), 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
