// Frostline — POST /save-tags  (ADMIN only)
//
// wos108: the theme-tab list is admin-managed. This stores the curated list
// (WITHOUT the built-in 'all') at config/theme-tags; get-art returns it to
// every visitor so all devices render the same tabs.
//
// Body: { tags: ['love', 'nature', ...] }   — order = tab order
//
// Renames are a CLIENT concern (the client bulk-rewrites piece tags via
// save-art); this function only persists the list itself.

import { connectLambda, getStore } from '@netlify/blobs';
import { verifyRequest } from './_auth.js';

// KEEP IN LOCKSTEP with TAG_INPUT_RE in app.js.
const TAG_RE = /^[a-z0-9][a-z0-9 &_-]{0,23}$/;
const MAX_TAGS = 40;

function json(status, body) {
  return { statusCode: status, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
}

export const handler = async (event) => {
  connectLambda(event);
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });
  if (!(await verifyRequest(event))) return json(401, { error: 'Unauthorized' });

  let body;
  try { body = JSON.parse(event.body || '{}'); }
  catch { return json(400, { error: 'Bad JSON' }); }

  const raw = body.tags;
  if (!Array.isArray(raw) || raw.length < 1 || raw.length > MAX_TAGS) {
    return json(400, { error: `tags must be an array of 1-${MAX_TAGS} strings` });
  }
  const tags = [];
  for (const t of raw) {
    if (typeof t !== 'string') return json(400, { error: 'tags must be strings' });
    const v = t.trim().toLowerCase();
    if (v === 'all') return json(400, { error: "'all' is built in and cannot be managed" });
    if (!TAG_RE.test(v)) {
      return json(400, { error: `Invalid tag "${t}" — lowercase letters/numbers, spaces, & _ - (max 24 chars)` });
    }
    if (!tags.includes(v)) tags.push(v);
  }

  try {
    const store = getStore('frostline');
    await store.set('config/theme-tags', JSON.stringify(tags));
    return json(200, { ok: true, tags });
  } catch (err) {
    return json(500, { error: 'Blob write failed', detail: String(err) });
  }
};
