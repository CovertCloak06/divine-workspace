// Frostline — GET /get-art
// Reads art (user-created pieces) and deletedIds from Netlify Blobs.
// Returns { art: [...], deletedIds: [...] } or 404 if not yet seeded.

import { getStore } from '@netlify/blobs';

export const handler = async () => {
  try {
    const store = getStore('frostline');
    const [artRaw, delRaw] = await Promise.all([
      store.get('art'),
      store.get('deletedIds'),
    ]);

    if (artRaw === null && delRaw === null) {
      return { statusCode: 404, body: JSON.stringify({ error: 'Not seeded' }) };
    }

    const art = artRaw ? JSON.parse(artRaw) : [];
    const deletedIds = delRaw ? JSON.parse(delRaw) : [];

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
      body: JSON.stringify({ art, deletedIds }),
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Blob read failed', detail: String(err) }),
    };
  }
};
