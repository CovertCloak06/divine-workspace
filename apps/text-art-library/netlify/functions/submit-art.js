// Frostline — POST /submit-art  (PUBLIC — owner-token capability, no account)
//
// User submissions with server-enforced ownership. Every visitor device holds a
// secret random token (generated client-side, never shown to anyone); the
// server stores only sha256(token) per piece. Create/update/delete of a
// submission requires presenting the matching token — so users can manage ONLY
// their own art. The admin password (Bearer) overrides ownership everywhere.
//
// Body shapes:
//   { action:'create', ownerToken, piece:{id,title,tags,art,width,height} }
//   { action:'update', ownerToken, piece:{...} }     // owner or admin
//   { action:'delete', ownerToken, id }              // owner or admin
//
// Storage (store 'frostline'):
//   pending/<id> — JSON { ...piece, held?:true, submittedAt } awaiting approval
//                  (a revision of a live piece uses the same id; the live
//                   piece/<id> stays up until the revision is approved)
//   owner/<id>   — sha256 hex of the owner token (survives approval so the
//                  owner can still revise/delete their live piece)
//
// Nothing here is ever publicly visible: pending/* is only readable by its
// owner and the admin (get-pending.js); it becomes public only when the admin
// approves it (moderate-art.js) into piece/<id>.

import crypto from 'node:crypto';
import { connectLambda, getStore } from '@netlify/blobs';
import { verifyRequest } from './_auth.js';

const ID_RE = /^[A-Za-z0-9_.-]{1,200}$/;
const MAX_TITLE = 80;
const MAX_ART = 20000;       // chars — generous for text art, blocks abuse blobs
const MAX_TAGS = 8;
const MAX_TAG_LEN = 24;
const MAX_PENDING_PER_OWNER = 10;   // simple anti-spam rate cap

// Narrow PROHIBITED-content pre-screen — hard legal red lines only (terms that
// suggest minors in an adult gallery). This is NOT a maturity filter and NOT
// enforcement: a match only sets `held:true` so the submission surfaces at the
// top of the admin queue flagged for urgent human review. It is already
// private until approved either way.
const HOLD_TERMS = [
  'child', 'children', 'kid', 'kids', 'minor', 'minors', 'underage',
  'preteen', 'pre-teen', 'loli', 'lolita', 'shota', 'jailbait', 'toddler',
  'infant', 'baby girl', 'baby boy', 'schoolgirl', 'schoolboy', 'cp',
];
function needsHold(text) {
  const t = String(text || '').toLowerCase();
  return HOLD_TERMS.some((w) =>
    new RegExp('(^|[^a-z0-9])' + w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '($|[^a-z0-9])').test(t));
}

const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

function json(status, body) {
  return { statusCode: status, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
}

function validatePiece(p) {
  if (!p || typeof p !== 'object') return 'Missing piece';
  if (!ID_RE.test(p.id || '')) return 'Invalid id';
  if (typeof p.title !== 'string' || !p.title.trim() || p.title.length > MAX_TITLE) return 'Invalid title';
  if (typeof p.art !== 'string' || !p.art.trim() || p.art.length > MAX_ART) return 'Invalid art';
  if (p.tags != null) {
    if (!Array.isArray(p.tags) || p.tags.length > MAX_TAGS) return 'Invalid tags';
    for (const t of p.tags) {
      if (typeof t !== 'string' || !t.trim() || t.length > MAX_TAG_LEN) return 'Invalid tags';
    }
  }
  return null;
}

// The exact subset of fields a submission may carry — everything else
// (wosVerified, draft, held, ownerHash…) is server-controlled.
function sanitizePiece(p) {
  return {
    id: p.id,
    title: p.title.trim(),
    tags: Array.isArray(p.tags) ? p.tags.map((t) => String(t).trim().toLowerCase()).filter(Boolean).slice(0, MAX_TAGS) : [],
    width: Number.isFinite(+p.width) ? Math.max(0, Math.min(500, Math.round(+p.width))) : 0,
    height: Number.isFinite(+p.height) ? Math.max(0, Math.min(500, Math.round(+p.height))) : 0,
    art: p.art,
  };
}

export const handler = async (event) => {
  connectLambda(event);
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });

  let body;
  try { body = JSON.parse(event.body || '{}'); }
  catch { return json(400, { error: 'Bad JSON' }); }

  const action = body.action;
  const token = typeof body.ownerToken === 'string' ? body.ownerToken : '';
  const isAdmin = await verifyRequest(event);
  if (!isAdmin && (token.length < 16 || token.length > 128)) {
    return json(400, { error: 'Missing owner token' });
  }
  const ownerHash = token ? sha256(token) : null;

  try {
    // Strong consistency: reads reflect writes immediately, so an owner can
    // update/list a submission they created seconds ago (default 'eventual'
    // reads lag ~10-30s; older lib versions ignore the option gracefully).
    const store = getStore({ name: 'frostline', consistency: 'strong' });

    if (action === 'create') {
      const err = validatePiece(body.piece);
      if (err) return json(400, { error: err });
      const p = sanitizePiece(body.piece);

      // id must be fresh — no hijacking a live/pending id, and no reusing a
      // TOMBSTONED id (approval clears tombstones, so accepting one here would
      // let a submission resurrect admin-deleted art under its old id).
      const [livePiece, pendingPiece, tombstone] = await Promise.all([
        store.get(`piece/${p.id}`), store.get(`pending/${p.id}`), store.get(`deleted/${p.id}`),
      ]);
      if (livePiece !== null || pendingPiece !== null || tombstone !== null) {
        return json(409, { error: 'That id already exists' });
      }

      // Anti-spam: cap how many pending submissions one owner can stack up.
      if (!isAdmin) {
        const { blobs } = await store.list({ prefix: 'owner/' });
        let mine = 0;
        await Promise.all((blobs || []).map(async ({ key }) => {
          const h = await store.get(key);
          if (h === ownerHash && (await store.get(`pending/${key.slice('owner/'.length)}`)) !== null) mine++;
        }));
        if (mine >= MAX_PENDING_PER_OWNER) {
          return json(429, { error: `Limit of ${MAX_PENDING_PER_OWNER} pending submissions — wait for review` });
        }
      }

      const record = { ...p, submittedAt: Date.now() };
      if (needsHold(p.title + '\n' + p.art + '\n' + p.tags.join(' '))) record.held = true;
      await Promise.all([
        store.set(`pending/${p.id}`, JSON.stringify(record)),
        store.set(`owner/${p.id}`, ownerHash || 'admin'),
      ]);
      return json(200, { ok: true, pending: true, held: !!record.held });
    }

    if (action === 'update') {
      const err = validatePiece(body.piece);
      if (err) return json(400, { error: err });
      const p = sanitizePiece(body.piece);

      const storedOwner = await store.get(`owner/${p.id}`);
      const [livePiece, pendingPiece] = await Promise.all([
        store.get(`piece/${p.id}`), store.get(`pending/${p.id}`),
      ]);
      if (livePiece === null && pendingPiece === null) return json(404, { error: 'Not found' });
      // OWNERSHIP GATE: only the owner of this piece (or the admin) may touch it.
      if (!isAdmin && (!storedOwner || storedOwner !== ownerHash)) {
        return json(403, { error: 'Not your art' });
      }

      // An edit always goes (back) through review: write the new content to
      // pending/<id>; a live version stays public until the revision is approved.
      const record = { ...p, submittedAt: Date.now(), revision: livePiece !== null };
      if (needsHold(p.title + '\n' + p.art + '\n' + p.tags.join(' '))) record.held = true;
      await store.set(`pending/${p.id}`, JSON.stringify(record));
      return json(200, { ok: true, pending: true, held: !!record.held });
    }

    if (action === 'delete') {
      const id = body.id;
      if (!ID_RE.test(id || '')) return json(400, { error: 'Invalid id' });
      const storedOwner = await store.get(`owner/${id}`);
      if (!isAdmin && (!storedOwner || storedOwner !== ownerHash)) {
        return json(403, { error: 'Not your art' });
      }
      const hadLive = (await store.get(`piece/${id}`)) !== null;
      const ops = [store.delete(`pending/${id}`), store.delete(`owner/${id}`)];
      if (hadLive) {
        ops.push(store.delete(`piece/${id}`));
        ops.push(store.set(`deleted/${id}`, String(Date.now())));  // tombstone
      }
      await Promise.all(ops);
      return json(200, { ok: true });
    }

    return json(400, { error: "action must be 'create', 'update' or 'delete'" });
  } catch (err) {
    return json(500, { error: 'Blob op failed', detail: String(err) });
  }
};
