import assert from 'node:assert/strict';
import { test } from 'node:test';
import { type Criteria, matches } from '../src/matcher.js';
import type { Listing } from '../src/sources/types.js';

const base: Listing = {
  id: '1',
  name: 'Box Logo Hooded Sweatshirt',
  category: 'Sweatshirts',
  price: 168,
  soldOut: false,
  url: 'https://example.com/shop/1',
};

const empty: Criteria = { keywords: [], categories: [], maxPrice: undefined };

test('empty criteria matches anything', () => {
  assert.equal(matches(base, empty), true);
});

test('keyword match is case-insensitive substring', () => {
  assert.equal(matches(base, { ...empty, keywords: ['box logo'] }), true);
  assert.equal(matches(base, { ...empty, keywords: ['beanie'] }), false);
});

test('any keyword may match (OR)', () => {
  assert.equal(matches(base, { ...empty, keywords: ['beanie', 'hooded'] }), true);
});

test('category filter is exact (lowercased)', () => {
  assert.equal(matches(base, { ...empty, categories: ['sweatshirts'] }), true);
  assert.equal(matches(base, { ...empty, categories: ['jackets'] }), false);
});

test('maxPrice caps inclusive', () => {
  assert.equal(matches(base, { ...empty, maxPrice: 168 }), true);
  assert.equal(matches(base, { ...empty, maxPrice: 167.99 }), false);
  assert.equal(matches(base, { ...empty, maxPrice: 200 }), true);
});

test('all provided filters must pass (AND)', () => {
  const c: Criteria = { keywords: ['box logo'], categories: ['jackets'], maxPrice: 200 };
  assert.equal(matches(base, c), false); // wrong category
  const c2: Criteria = { keywords: ['box logo'], categories: ['sweatshirts'], maxPrice: 200 };
  assert.equal(matches(base, c2), true);
});
