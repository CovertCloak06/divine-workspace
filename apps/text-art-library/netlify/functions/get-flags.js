// Frostline — GET /get-flags
// Returns { flags: { [pieceId]: noteText } } across all flag/* blobs.

import { connectLambda, getStore } from '@netlify/blobs';

export const handler = async (event) => {
  connectLambda(event);
  try {
    const store = getStore('frostline');
    const { blobs } = await store.list({ prefix: 'flag/' });
    const flags = {};
    await Promise.all(
      (blobs || []).map(async ({ key }) => {
        const id = key.slice('flag/'.length);
        const note = await store.get(key);
        flags[id] = note === null ? '' : note;
      }),
    );
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
      body: JSON.stringify({ flags }),
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Blob list failed', detail: String(err) }),
    };
  }
};
