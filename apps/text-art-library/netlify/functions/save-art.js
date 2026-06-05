// Frostline — POST /save-art
// Requires Bearer auth (Authorization: Bearer <password>).
// Per-piece writes so concurrent edits from different devices never clobber
// each other. Body is one of:
//   { piece: {...} }              upsert a single piece (clears its tombstone)
//   { deleteId: "<id>" }          delete a single piece (writes a tombstone)
//   { pieces: [...], deletedIds } bulk write (used once for seed/migration)

import { connectLambda, getStore } from '@netlify/blobs';
import { verifyRequest } from './_auth.js';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
};

const ID_RE = /^[A-Za-z0-9_.-]{1,200}$/;
const json = (statusCode, obj) => ({
  statusCode,
  headers: { 'Content-Type': 'application/json', ...CORS },
  body: JSON.stringify(obj),
});

export const handler = async (event) => {
  connectLambda(event);
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: CORS };
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });

  const ok = await verifyRequest(event);
  if (!ok) return json(401, { error: 'Unauthorized' });

  let body;
  try { body = JSON.parse(event.body || '{}'); }
  catch { return json(400, { error: 'Bad JSON' }); }

  const store = getStore('frostline');

  try {
    // Delete one piece
    if (typeof body.deleteId === 'string') {
      if (!ID_RE.test(body.deleteId)) return json(400, { error: 'Invalid id' });
      await Promise.all([
        store.delete(`piece/${body.deleteId}`),
        store.set(`deleted/${body.deleteId}`, String(Date.now())),
      ]);
      return json(200, { ok: true });
    }

    // Upsert one piece
    if (body.piece && typeof body.piece === 'object') {
      const p = body.piece;
      if (!ID_RE.test(p.id || '')) return json(400, { error: 'Invalid piece id' });
      await Promise.all([
        store.set(`piece/${p.id}`, JSON.stringify(p)),
        store.delete(`deleted/${p.id}`),
      ]);
      return json(200, { ok: true });
    }

    // Bulk write (seed / migration)
    if (Array.isArray(body.pieces)) {
      const ops = [];
      for (const p of body.pieces) {
        if (p && ID_RE.test(p.id || '')) ops.push(store.set(`piece/${p.id}`, JSON.stringify(p)));
      }
      for (const id of body.deletedIds || []) {
        if (ID_RE.test(id)) ops.push(store.set(`deleted/${id}`, String(Date.now())));
      }
      // Retire the legacy aggregate keys so they don't shadow per-piece records.
      ops.push(store.delete('art'), store.delete('library'), store.delete('deletedIds'));
      await Promise.all(ops);
      return json(200, { ok: true });
    }

    return json(400, { error: 'Expected piece, deleteId, or pieces' });
  } catch (err) {
    return json(500, { error: 'Blob write failed', detail: String(err) });
  }
};
