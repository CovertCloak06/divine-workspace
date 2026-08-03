#!/usr/bin/env node
// Frostline — art library backup.
//
// Fetches the live library from the site's public get-art endpoint and writes
// it into backups/ so GitHub always holds a copy that survives anything that
// happens to the Netlify account (suspension, billing lapse, deletion).
//
// SAFETY: this script must never be able to destroy the thing it protects.
// A suspended site returns an HTML 404 page, and a half-broken one can return
// a short library — writing either over a good backup would be worse than not
// running at all. So every fetch is validated hard, and any result that looks
// like data loss ABORTS with a non-zero exit instead of writing. The previous
// backup stays exactly where it is, and the scheduled run fails loudly.
//
// Usage:
//   node scripts/backup-art.mjs                 # backup from production
//   SITE=https://... node scripts/backup-art.mjs
//   ALLOW_SHRINK=1 node scripts/backup-art.mjs  # override the shrink guard
//                                               # (only after a real bulk delete)

import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const APP = dirname(HERE);
const BACKUPS = join(APP, 'backups');
const LATEST = join(BACKUPS, 'library-latest.json');
const STATUS = join(BACKUPS, 'status.json');

const SITE = process.env.SITE || 'https://frostline-art.netlify.app';
const ENDPOINT = `${SITE.replace(/\/$/, '')}/.netlify/functions/get-art`;

// A piece id the save-art endpoint would accept — anything else can't be
// restored, so it doesn't count toward a healthy backup.
const ID_RE = /^[A-Za-z0-9_.-]{1,200}$/;

// Guards. The floor catches "the API answered but the store is empty"; the
// shrink ratio catches partial loss that a floor alone would sail past.
const MIN_PIECES = 10;
const MAX_SHRINK = 0.2; // refuse if >20% of pieces disappeared since last backup

const fail = (msg) => {
  console.error(`::error::${msg}`);
  console.error('ABORTED — the existing backup was left untouched.');
  process.exit(1);
};

async function fetchLibrary() {
  let res;
  try {
    res = await fetch(ENDPOINT, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(30_000),
    });
  } catch (err) {
    fail(`Could not reach ${ENDPOINT} — ${err.message}`);
  }
  if (!res.ok) {
    fail(`${ENDPOINT} returned HTTP ${res.status}. If the site is suspended or `
      + 'down, that is exactly when the old backup matters most — not overwriting it.');
  }
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    fail('Response was not JSON (a suspended Netlify site serves an HTML error '
      + `page). First 120 chars: ${JSON.stringify(text.slice(0, 120))}`);
  }
  return data;
}

function validate(data) {
  if (!data || typeof data !== 'object') fail('Response JSON was not an object.');
  const { library, deletedIds, themeTags } = data;
  if (!Array.isArray(library)) fail('Response had no `library` array.');

  const good = library.filter(
    (p) => p && typeof p === 'object'
      && ID_RE.test(p.id || '')
      && typeof p.art === 'string' && p.art.length > 0,
  );
  const dropped = library.length - good.length;
  if (dropped > 0) {
    console.warn(`WARNING: ${dropped} piece(s) had no usable id/art and were skipped.`);
  }
  if (good.length < MIN_PIECES) {
    fail(`Only ${good.length} usable piece(s) came back (floor is ${MIN_PIECES}). `
      + 'That looks like a broken read, not a real library.');
  }
  return {
    library: good,
    deletedIds: Array.isArray(deletedIds) ? deletedIds.filter((id) => ID_RE.test(id)) : [],
    themeTags: themeTags ?? null,
  };
}

function guardAgainstShrink(fresh) {
  if (!existsSync(LATEST)) {
    console.log('No previous backup — this run establishes the baseline.');
    return;
  }
  let prev;
  try {
    prev = JSON.parse(readFileSync(LATEST, 'utf8'));
  } catch {
    console.warn('WARNING: previous backup was unreadable; treating this run as a new baseline.');
    return;
  }
  const before = Array.isArray(prev.library) ? prev.library.length : 0;
  const after = fresh.library.length;
  if (before === 0) return;
  const lost = before - after;
  if (lost > 0 && lost / before > MAX_SHRINK) {
    if (process.env.ALLOW_SHRINK === '1') {
      console.warn(`WARNING: library shrank ${before} -> ${after}; `
        + 'writing anyway because ALLOW_SHRINK=1.');
      return;
    }
    fail(`Library shrank from ${before} to ${after} pieces `
      + `(${((lost / before) * 100).toFixed(1)}% gone, limit is ${MAX_SHRINK * 100}%). `
      + 'If that deletion was intentional, re-run with ALLOW_SHRINK=1.');
  }
}

// Deterministic serialization: sorted by id with sorted keys, so an unchanged
// library produces a byte-identical file and therefore no commit churn.
function serialize({ library, deletedIds, themeTags }) {
  const pieces = [...library].sort((a, b) => String(a.id).localeCompare(String(b.id)));
  const sortKeys = (obj) => Object.fromEntries(
    Object.keys(obj).sort().map((k) => [k, obj[k]]),
  );
  return `${JSON.stringify({
    library: pieces.map(sortKeys),
    deletedIds: [...deletedIds].sort(),
    themeTags,
  }, null, 2)}\n`;
}

const data = validate(await fetchLibrary());
guardAgainstShrink(data);

mkdirSync(join(BACKUPS, 'snapshots'), { recursive: true });
const body = serialize(data);
const changed = !existsSync(LATEST) || readFileSync(LATEST, 'utf8') !== body;

writeFileSync(LATEST, body);

// One dated snapshot per month, rewritten within the month. Git history already
// holds every version of library-latest.json; these exist so a human under
// stress can grab a restore point without needing to know git.
const stamp = new Date().toISOString().slice(0, 7); // YYYY-MM
writeFileSync(join(BACKUPS, 'snapshots', `library-${stamp}.json`), body);

writeFileSync(STATUS, `${JSON.stringify({
  lastRunUtc: new Date().toISOString(),
  source: ENDPOINT,
  pieces: data.library.length,
  deletedIds: data.deletedIds.length,
  changed,
}, null, 2)}\n`);

console.log(`OK — ${data.library.length} pieces, ${data.deletedIds.length} tombstones.`);
console.log(changed ? 'Library changed since last backup.' : 'Library unchanged.');
