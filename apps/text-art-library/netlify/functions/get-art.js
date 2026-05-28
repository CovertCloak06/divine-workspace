// Frostline — GET /get-art
// Per-piece storage (concurrency-safe across devices/users):
//   piece/<id>   — one art piece (its own record)
//   deleted/<id> — tombstone (so deletes propagate + redeploys can't resurrect)
// Returns { library: [...], deletedIds: [...] }.
// If no per-piece records exist yet, falls back to the LEGACY aggregate keys
// (art / deletedIds) so the client can migrate them once. 404 when truly empty.

import { getStore } from '@netlify/blobs';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

export const handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: CORS };
  }
  try {
    const store = getStore('frostline');

    // Per-piece records
    const [{ blobs: pieceBlobs }, { blobs: delBlobs }] = await Promise.all([
      store.list({ prefix: 'piece/' }),
      store.list({ prefix: 'deleted/' }),
    ]);

    const deletedIds = (delBlobs || []).map((b) => b.key.slice('deleted/'.length));

    if (pieceBlobs && pieceBlobs.length) {
      const library = await Promise.all(
        pieceBlobs.map(async ({ key }) => {
          const raw = await store.get(key);
          try { return JSON.parse(raw); } catch { return null; }
        }),
      );
      return {
        statusCode: 200,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...CORS },
        body: JSON.stringify({ library: library.filter(Boolean), deletedIds }),
      };
    }

    // No per-piece records — try legacy aggregate keys for one-time migration.
    const [artRaw, legacyDelRaw] = await Promise.all([
      store.get('art'),
      store.get('deletedIds'),
    ]);
    if (artRaw === null && legacyDelRaw === null && deletedIds.length === 0) {
      return { statusCode: 404, headers: CORS, body: JSON.stringify({ error: 'Not seeded' }) };
    }
    const legacyDeleted = legacyDelRaw ? JSON.parse(legacyDelRaw) : [];
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...CORS },
      body: JSON.stringify({
        art: artRaw ? JSON.parse(artRaw) : [],
        deletedIds: [...new Set([...deletedIds, ...legacyDeleted])],
      }),
    };
  } catch (err) {
    return {
      statusCode: 500,
      headers: CORS,
      body: JSON.stringify({ error: 'Blob read failed', detail: String(err) }),
    };
  }
};
