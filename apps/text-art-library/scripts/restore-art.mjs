#!/usr/bin/env node
// Frostline — restore the art library from a backup file.
//
// Pushes every piece from a backup into the live site via the authenticated
// save-art bulk endpoint. Restores are ADDITIVE: pieces are upserted and
// tombstones re-written; nothing that exists only on the live site is deleted.
// Running it against a healthy site is therefore harmless.
//
// Usage:
//   EDITOR_PASSWORD=... node scripts/restore-art.mjs                # latest backup -> production
//   EDITOR_PASSWORD=... node scripts/restore-art.mjs backups/snapshots/library-2026-08.json
//   EDITOR_PASSWORD=... SITE=https://... node scripts/restore-art.mjs
//
// The password is the site's editor password (same one the in-app editor uses).

import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const APP = dirname(HERE);

const SITE = process.env.SITE || 'https://frostline-art.netlify.app';
const PASSWORD = process.env.EDITOR_PASSWORD;
if (!PASSWORD) {
  console.error('Set EDITOR_PASSWORD (the in-app editor password) and re-run.');
  process.exit(1);
}

const file = resolve(process.argv[2] || join(APP, 'backups', 'library-latest.json'));
let data;
try {
  data = JSON.parse(readFileSync(file, 'utf8'));
} catch (err) {
  console.error(`Could not read backup ${file}: ${err.message}`);
  process.exit(1);
}
const { library, deletedIds = [] } = data;
if (!Array.isArray(library) || library.length === 0) {
  console.error('Backup has no pieces — refusing to run.');
  process.exit(1);
}

console.log(`Restoring ${library.length} pieces (+${deletedIds.length} tombstones)`);
console.log(`  from ${file}`);
console.log(`  to   ${SITE}`);

// Batch the bulk endpoint so one huge body can't hit function limits.
const BATCH = 50;
for (let i = 0; i < library.length; i += BATCH) {
  const pieces = library.slice(i, i + BATCH);
  const body = { pieces };
  if (i === 0) body.deletedIds = deletedIds; // tombstones once, first batch
  const res = await fetch(`${SITE.replace(/\/$/, '')}/.netlify/functions/save-art`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${PASSWORD}`,
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(60_000),
  });
  if (!res.ok) {
    console.error(`Batch ${i / BATCH + 1} failed: HTTP ${res.status} ${await res.text()}`);
    console.error('Fix the problem and re-run — restores are idempotent, so '
      + 'running again re-sends everything safely.');
    process.exit(1);
  }
  console.log(`  batch ${i / BATCH + 1}/${Math.ceil(library.length / BATCH)} ok`);
}

console.log('Restore complete. Open the site and hard-refresh to verify.');
