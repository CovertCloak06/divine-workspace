// Frostline — GET /get-site-text
// Returns the admin's customized site chrome text (header title, tagline,
// button label, search placeholder, footer). Public read (no auth) — the
// customizations affect every visitor's view, not just the admin's.
// Returns 404 if no custom text has been saved yet, in which case the
// client uses the defaults baked into index.html.

import { connectLambda, getStore } from '@netlify/blobs';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

const json = (statusCode, obj) => ({
  statusCode,
  headers: { 'Content-Type': 'application/json', ...CORS },
  body: JSON.stringify(obj),
});

export const handler = async (event) => {
  connectLambda(event);
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: CORS };
  if (event.httpMethod !== 'GET') return json(405, { error: 'Method not allowed' });

  try {
    const store = getStore('frostline');
    const raw = await store.get('site-text/custom');
    if (!raw) return json(404, { error: 'no custom site text' });
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json', ...CORS },
      body: raw,
    };
  } catch (err) {
    return json(500, { error: 'Blob read failed', detail: String(err).slice(0, 200) });
  }
};
