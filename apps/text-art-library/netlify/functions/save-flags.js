// Frostline — POST /save-flags
// No auth (anyone can flag — the editor sees the global flag list).
// Body: { id, action: 'toggle' | 'note', note?: string }
//   toggle: creates flag/{id} if absent, deletes it if present.
//   note:   updates flag/{id} note text without changing its existence.

import { connectLambda, getStore } from '@netlify/blobs';

export const handler = async (event) => {
  connectLambda(event);
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  let body;
  try { body = JSON.parse(event.body || '{}'); }
  catch { return { statusCode: 400, body: JSON.stringify({ error: 'Bad JSON' }) }; }

  const { id, action, note } = body;
  if (!id || typeof id !== 'string' || id.length > 200) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Missing or invalid id' }) };
  }
  if (action !== 'toggle' && action !== 'note') {
    return { statusCode: 400, body: JSON.stringify({ error: "action must be 'toggle' or 'note'" }) };
  }

  try {
    const store = getStore('frostline');
    const key = `flag/${id}`;

    if (action === 'toggle') {
      const existing = await store.get(key);
      if (existing === null) {
        await store.set(key, '');
        return {
          statusCode: 200,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ok: true, flagged: true, note: '' }),
        };
      } else {
        await store.delete(key);
        return {
          statusCode: 200,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ok: true, flagged: false }),
        };
      }
    }

    // action === 'note'
    await store.set(key, String(note || ''));
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ok: true, flagged: true, note: String(note || '') }),
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Blob op failed', detail: String(err) }),
    };
  }
};
