// Frostline — POST /save-art
// Requires Bearer auth (Authorization: Bearer <password>).
// Body: { art: [...], deletedIds: [...] }
// Writes both to Netlify Blobs.

import { getStore } from '@netlify/blobs';

export const handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  const expected = process.env.EDITOR_PASSWORD;
  if (!expected) {
    return { statusCode: 500, body: JSON.stringify({ error: 'EDITOR_PASSWORD not configured' }) };
  }

  const auth = event.headers.authorization || event.headers.Authorization || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  if (token !== expected) {
    return { statusCode: 401, body: JSON.stringify({ error: 'Unauthorized' }) };
  }

  let body;
  try { body = JSON.parse(event.body || '{}'); }
  catch { return { statusCode: 400, body: JSON.stringify({ error: 'Bad JSON' }) }; }

  if (!Array.isArray(body.art) || !Array.isArray(body.deletedIds)) {
    return { statusCode: 400, body: JSON.stringify({ error: 'art and deletedIds must be arrays' }) };
  }

  try {
    const store = getStore('frostline');
    await Promise.all([
      store.set('art', JSON.stringify(body.art)),
      store.set('deletedIds', JSON.stringify(body.deletedIds)),
    ]);
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ok: true }),
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Blob write failed', detail: String(err) }),
    };
  }
};
