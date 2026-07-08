// Frostline — POST /moderate-art  (ADMIN ONLY; Bearer = editor password)
// The approval step of the user-submission pipeline:
//   { action:'approve', id } → pending/<id> becomes the live piece/<id>
//                              (public), clearing any tombstone. owner/<id> is
//                              KEPT so the submitter can still revise/delete
//                              their own live piece.
//   { action:'reject',  id } → pending/<id> is discarded. If the id has no
//                              live piece, owner/<id> is cleaned up too.

import { connectLambda, getStore } from '@netlify/blobs';
import { verifyRequest } from './_auth.js';

const ID_RE = /^[A-Za-z0-9_.-]{1,200}$/;

function json(status, body) {
  return { statusCode: status, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
}

export const handler = async (event) => {
  connectLambda(event);
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });
  if (!(await verifyRequest(event))) return json(401, { error: 'Unauthorized' });

  let body;
  try { body = JSON.parse(event.body || '{}'); }
  catch { return json(400, { error: 'Bad JSON' }); }

  const { action, id } = body;
  if (!ID_RE.test(id || '')) return json(400, { error: 'Invalid id' });

  try {
    const store = getStore('frostline');
    const raw = await store.get(`pending/${id}`);
    if (raw === null) return json(404, { error: 'No pending submission with that id' });

    if (action === 'approve') {
      let rec;
      try { rec = JSON.parse(raw); } catch { return json(500, { error: 'Corrupt pending record' }); }
      // Publish ONLY the public piece fields — server-side workflow markers
      // (held / submittedAt / revision) never leak into the live library.
      const piece = {
        id: rec.id, title: rec.title, tags: rec.tags || [],
        width: rec.width || 0, height: rec.height || 0, art: rec.art,
        wosVerified: false,
      };
      await Promise.all([
        store.set(`piece/${id}`, JSON.stringify(piece)),
        store.delete(`pending/${id}`),
        store.delete(`deleted/${id}`),   // clear any tombstone
      ]);
      return json(200, { ok: true, approved: true });
    }

    if (action === 'reject') {
      const hadLive = (await store.get(`piece/${id}`)) !== null;
      const ops = [store.delete(`pending/${id}`)];
      if (!hadLive) ops.push(store.delete(`owner/${id}`));
      await Promise.all(ops);
      return json(200, { ok: true, rejected: true });
    }

    return json(400, { error: "action must be 'approve' or 'reject'" });
  } catch (err) {
    return json(500, { error: 'Blob op failed', detail: String(err) });
  }
};
