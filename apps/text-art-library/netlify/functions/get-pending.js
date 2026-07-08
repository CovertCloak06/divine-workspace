// Frostline — POST /get-pending
// Two callers, one endpoint:
//   { ownerToken }            → ONLY that device's own submissions (pending +
//                               which of their ids are live). Server matches
//                               sha256(token) against owner/<id> — nobody can
//                               read anyone else's queue.
//   Authorization: Bearer     → the ADMIN moderation queue: every pending
//                               piece, held-first.
// POST (not GET) so the owner token never lands in URL/CDN/server logs.

import crypto from 'node:crypto';
import { connectLambda, getStore } from '@netlify/blobs';
import { verifyRequest } from './_auth.js';

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

  const isAdmin = await verifyRequest(event);
  const token = typeof body.ownerToken === 'string' ? body.ownerToken : '';
  if (!isAdmin && token.length < 16) return json(400, { error: 'Missing owner token' });
  const ownerHash = token ? sha256(token) : null;

  try {
    // Strong consistency so a submission made seconds ago appears in "My art"
    // and the admin queue immediately (default reads lag ~10-30s).
    const store = getStore({ name: 'frostline', consistency: 'strong' });
    const { blobs } = await store.list({ prefix: 'pending/' });

    const pending = [];
    await Promise.all((blobs || []).map(async ({ key }) => {
      const id = key.slice('pending/'.length);
      const raw = await store.get(key);
      if (raw === null) return;
      let rec;
      try { rec = JSON.parse(raw); } catch { return; }
      if (!isAdmin) {
        const owner = await store.get(`owner/${id}`);
        if (owner !== ownerHash) return;   // not yours — invisible
      }
      pending.push(rec);
    }));
    // Held (urgent-review) submissions first, then newest first.
    pending.sort((a, b) => (b.held ? 1 : 0) - (a.held ? 1 : 0) || (b.submittedAt || 0) - (a.submittedAt || 0));

    // For the owner view, also report which of their ids are LIVE (approved),
    // so "My art" can show live pieces they still own alongside pending ones.
    let liveIds = [];
    if (!isAdmin) {
      const { blobs: ownerBlobs } = await store.list({ prefix: 'owner/' });
      await Promise.all((ownerBlobs || []).map(async ({ key }) => {
        const h = await store.get(key);
        if (h !== ownerHash) return;
        const id = key.slice('owner/'.length);
        if ((await store.get(`piece/${id}`)) !== null) liveIds.push(id);
      }));
    }

    return json(200, { pending, liveIds });
  } catch (err) {
    return json(500, { error: 'Blob op failed', detail: String(err) });
  }
};
