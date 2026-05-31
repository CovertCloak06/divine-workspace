// Frostline — GET /get-palette
// Returns the admin's customized character palette as JSON. Public read
// (no auth) — the customizations affect every user's palette, not just the
// admin's. Returns 404 if no custom palette has been saved yet, in which
// case the client uses the bundled palette-data.js default.

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
    const raw = await store.get('palette/custom');
    if (!raw) return json(404, { error: 'no custom palette' });
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json', ...CORS },
      body: raw,
    };
  } catch (err) {
    return json(500, { error: 'Blob read failed', detail: String(err).slice(0, 200) });
  }
};
