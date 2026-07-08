// Frostline — POST /get-mine
// Returns the ids of LIVE pieces owned by the presenting device:
//   { ownerToken } → { liveIds: [...] }
// The server matches sha256(token) against owner/<id> records, so nobody can
// enumerate anyone else's ownership. POST (not GET) keeps the token out of
// URL/CDN/server logs. Used by the "My art" view; the client overlays its own
// just-published pieces while Blobs list() catches up.

import crypto from 'node:crypto';
import { connectLambda, getStore } from '@netlify/blobs';

const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

function json(status, body) {
  return { statusCode: status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, body: JSON.stringify(body) };
}

export const handler = async (event) => {
  connectLambda(event);
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });

  let body;
  try { body = JSON.parse(event.body || '{}'); }
  catch { return json(400, { error: 'Bad JSON' }); }

  const token = typeof body.ownerToken === 'string' ? body.ownerToken : '';
  if (token.length < 16) return json(400, { error: 'Missing owner token' });
  const ownerHash = sha256(token);

  try {
    const store = getStore('frostline');
    const { blobs } = await store.list({ prefix: 'owner/' });
    const liveIds = [];
    await Promise.all((blobs || []).map(async ({ key }) => {
      const h = await store.get(key);
      if (h !== ownerHash) return;
      const id = key.slice('owner/'.length);
      if ((await store.get(`piece/${id}`)) !== null) liveIds.push(id);
    }));
    return json(200, { liveIds });
  } catch (err) {
    return json(500, { error: 'Blob op failed', detail: String(err) });
  }
};
