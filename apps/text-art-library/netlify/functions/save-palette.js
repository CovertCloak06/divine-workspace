// Frostline — POST /save-palette
// Requires Bearer auth (Authorization: Bearer <password>). Stores the full
// custom palette JSON (array of { label, chars[], wide? }) under one Blob
// key. The client merges nothing — this single document IS the palette
// once saved. To reset to defaults, the admin can delete this key (not
// currently exposed via API; nuke via the Netlify dashboard if needed).

import { connectLambda, getStore } from '@netlify/blobs';
import { verifyRequest } from './_auth.js';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
};

const json = (statusCode, obj) => ({
  statusCode,
  headers: { 'Content-Type': 'application/json', ...CORS },
  body: JSON.stringify(obj),
});

const LABEL_RE = /^[\p{L}\p{N} &.,/'"()+\-]{1,60}$/u;

function validatePalette(groups) {
  if (!Array.isArray(groups)) return 'palette must be an array';
  if (groups.length === 0) return 'palette must have at least one group';
  if (groups.length > 60) return 'too many groups (max 60)';
  const seenLabels = new Set();
  for (const g of groups) {
    if (!g || typeof g !== 'object') return 'group must be an object';
    if (typeof g.label !== 'string') return 'group.label must be a string';
    if (!LABEL_RE.test(g.label)) return `invalid group label: "${g.label}"`;
    if (seenLabels.has(g.label)) return `duplicate group label: "${g.label}"`;
    seenLabels.add(g.label);
    if (!Array.isArray(g.chars)) return `group "${g.label}" chars must be an array`;
    if (g.chars.length > 500) return `group "${g.label}" has too many chars (max 500)`;
    for (const ch of g.chars) {
      if (typeof ch !== 'string') return `non-string char in "${g.label}"`;
      if (ch.length === 0 || ch.length > 80) return `bad char length in "${g.label}"`;
    }
    if ('wide' in g && typeof g.wide !== 'boolean') return `group "${g.label}" wide must be boolean`;
  }
  return null;
}

export const handler = async (event) => {
  connectLambda(event);
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: CORS };
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });

  const ok = await verifyRequest(event);
  if (!ok) return json(401, { error: 'Unauthorized' });

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return json(400, { error: 'Bad JSON' });
  }

  const groups = body.groups;
  const errMsg = validatePalette(groups);
  if (errMsg) return json(400, { error: errMsg });

  try {
    const store = getStore('frostline');
    const doc = { groups, updatedAt: Date.now() };
    await store.set('palette/custom', JSON.stringify(doc));
    return json(200, { ok: true, updatedAt: doc.updatedAt });
  } catch (err) {
    return json(500, { error: 'Blob write failed', detail: String(err).slice(0, 200) });
  }
};
