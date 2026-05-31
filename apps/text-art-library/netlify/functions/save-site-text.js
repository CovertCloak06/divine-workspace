// Frostline — POST /save-site-text
// Requires Bearer auth (Authorization: Bearer <password>). Stores the site
// chrome text customizations (header title, tagline, add-button label,
// search placeholder, footer) under one Blob key. The client applies
// whichever fields are present; missing fields fall back to the hardcoded
// defaults in index.html.

import { connectLambda, getStore } from '@netlify/blobs';

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

// Per-field length budgets. These are intentionally generous but bounded so
// nothing can blow up the layout or stuff arbitrary HTML into the page.
const FIELD_LIMITS = {
  siteTitle: 40,
  tagline: 140,
  addButtonLabel: 30,
  searchPlaceholder: 50,
  footerText: 150,
  shareUrlLabel: 80,
};

function validateSiteText(text) {
  if (!text || typeof text !== 'object') return 'site text must be an object';
  for (const [key, value] of Object.entries(text)) {
    if (!(key in FIELD_LIMITS)) return `unknown field: "${key}"`;
    if (typeof value !== 'string') return `field "${key}" must be a string`;
    if (value.length > FIELD_LIMITS[key]) {
      return `field "${key}" too long (max ${FIELD_LIMITS[key]} chars)`;
    }
    // Strip any control characters that would mangle the DOM. We don't
    // validate HTML here — the client uses textContent so tags are inert.
    if (/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(value)) {
      return `field "${key}" contains control characters`;
    }
  }
  return null;
}

export const handler = async (event) => {
  connectLambda(event);
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: CORS };
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });

  const expected = process.env.EDITOR_PASSWORD;
  if (!expected) return json(500, { error: 'EDITOR_PASSWORD not configured' });

  const auth = event.headers.authorization || event.headers.Authorization || '';
  if (auth.replace(/^Bearer\s+/i, '') !== expected) {
    return json(401, { error: 'Unauthorized' });
  }

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return json(400, { error: 'Bad JSON' });
  }

  const text = body.text;
  const errMsg = validateSiteText(text);
  if (errMsg) return json(400, { error: errMsg });

  try {
    const store = getStore('frostline');
    const doc = { text, updatedAt: Date.now() };
    await store.set('site-text/custom', JSON.stringify(doc));
    return json(200, { ok: true, updatedAt: doc.updatedAt });
  } catch (err) {
    return json(500, { error: 'Blob write failed', detail: String(err).slice(0, 200) });
  }
};
