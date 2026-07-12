// Frostline — POST /submit-art  (PUBLIC — owner-token capability, no account)
//
// DIRECT-PUBLISH user submissions with server-enforced ownership. Every visitor
// device holds a secret random token (generated client-side); the server stores
// only sha256(token) per piece. A created piece goes STRAIGHT into the public
// library (no approval queue — Frostline is an adult gallery behind the 18+
// gate). Update/delete require presenting the matching token — so users can
// manage ONLY their own art. The admin password (Bearer) overrides ownership.
//
// Body shapes:
//   { action:'create', ownerToken, piece:{id,title,tags,art,width,height} }
//   { action:'update', ownerToken, piece:{...} }     // owner or admin
//   { action:'delete', ownerToken, id }              // owner or admin
//
// Storage (store 'frostline'):
//   piece/<id> — the live, public piece (same shape as admin-authored pieces)
//   owner/<id> — sha256 hex of the owner token (who may edit/delete it)
//
// NOTE: default (eventual) Blobs reads — strong consistency is unavailable in
// this Lambda-compat runtime (no uncachedEdgeURL, verified on deploy preview).
// Lag is SAFE for authorization: a not-yet-visible owner read yields null,
// which can only DENY, never grant. The client optimistically shows its own
// just-published art while list() catches up.

import crypto from 'node:crypto';
import { connectLambda, getStore } from '@netlify/blobs';
import { verifyRequest } from './_auth.js';

const ID_RE = /^[A-Za-z0-9_.-]{1,200}$/;
const MAX_TITLE = 80;
const MAX_ART = 20000;       // chars — generous for text art, blocks abuse blobs
const MAX_TAGS = 8;
const MAX_TAG_LEN = 24;
const MAX_PIECES_PER_OWNER = 20;   // simple anti-spam cap on live pieces

// Narrow PROHIBITED-content screen — hard legal red lines only (terms that
// suggest minors in an adult gallery). With no review queue, a match is
// REJECTED outright at submit time. This is NOT a maturity filter: adult
// content is the point of the gallery; only clearly-prohibited terms match.
const BLOCK_TERMS = [
  'child', 'children', 'kid', 'kids', 'minor', 'minors', 'underage',
  'preteen', 'pre-teen', 'loli', 'lolita', 'shota', 'jailbait', 'toddler',
  'infant', 'baby girl', 'baby boy', 'schoolgirl', 'schoolboy', 'cp',
];
function isProhibited(text) {
  const t = String(text || '').toLowerCase();
  return BLOCK_TERMS.some((w) =>
    new RegExp('(^|[^a-z0-9])' + w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '($|[^a-z0-9])').test(t));
}

/* wos112: the WoS-safety gate is REMOVED — its character whitelist was
 * heuristic and blocked a real user's art that works fine in game.
 * Publishing is ungated; curation + bug reports govern the gallery.
 * Only the invisible normalization below remains. */
/* Mirror of the client save path: NFC + spaces→NBSP + drop trailing blank
 * rows. Applied server-side so a direct API call can't skip normalization. */
function normalizeArt(a) {
  const art = String(a).normalize('NFC').replace(/ /g, '\u00A0');
  const lines = art.split('\n');
  const blank = (row) => [...row].every((c) => c === '\u00A0' || c === '\t' || c === ' ');
  while (lines.length && blank(lines[lines.length - 1])) lines.pop();
  return lines.join('\n');
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

// The exact public piece shape — identical to admin-authored pieces. Nothing
// else a submitter sends (draft, wosVerified, etc.) is honored.
function sanitizePiece(p) {
  return {
    id: p.id,
    title: p.title.trim(),
    tags: Array.isArray(p.tags) ? p.tags.map((t) => String(t).trim().toLowerCase()).filter(Boolean).slice(0, MAX_TAGS) : [],
    width: Number.isFinite(+p.width) ? Math.max(0, Math.min(500, Math.round(+p.width))) : 0,
    height: Number.isFinite(+p.height) ? Math.max(0, Math.min(500, Math.round(+p.height))) : 0,
    art: normalizeArt(p.art), // wos106: server-side normalization (NFC, NBSP, trim)
    wosVerified: false,
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
    const store = getStore('frostline');

    if (action === 'create') {
      const err = validatePiece(body.piece);
      if (err) return json(400, { error: err });
      const p = sanitizePiece(body.piece);

      // Public submissions live in the 'user-' id namespace (what the client's
      // newId() generates). Without this, a fresh/cleared Blob store would let
      // a direct request claim a curated bundled id (e.g. 'heart-small') that
      // exists only in art.js, shadowing the original. Admin is exempt.
      if (!isAdmin && !/^user-/.test(p.id)) {
        return json(400, { error: "Submission ids must start with 'user-'" });
      }

      if (isProhibited(p.title + '\n' + p.art + '\n' + p.tags.join(' '))) {
        return json(400, { error: 'This submission contains prohibited content and cannot be published' });
      }

      // id must be fresh — no hijacking a live id, and no reusing a TOMBSTONED
      // id (that would resurrect admin-deleted art under its old id).
      const [livePiece, tombstone] = await Promise.all([
        store.get(`piece/${p.id}`), store.get(`deleted/${p.id}`),
      ]);
      if (livePiece !== null || tombstone !== null) {
        return json(409, { error: 'That id already exists' });
      }

      // Anti-spam: cap how many live pieces one owner can publish.
      if (!isAdmin) {
        const { blobs } = await store.list({ prefix: 'owner/' });
        let mine = 0;
        await Promise.all((blobs || []).map(async ({ key }) => {
          const h = await store.get(key);
          if (h === ownerHash && (await store.get(`piece/${key.slice('owner/'.length)}`)) !== null) mine++;
        }));
        if (mine >= MAX_PIECES_PER_OWNER) {
          return json(429, { error: `Limit of ${MAX_PIECES_PER_OWNER} published pieces reached` });
        }
      }

      // DIRECT PUBLISH: the piece goes straight into the public library.
      await Promise.all([
        store.set(`piece/${p.id}`, JSON.stringify(p)),
        store.set(`owner/${p.id}`, ownerHash || 'admin'),
        store.delete(`deleted/${p.id}`),
      ]);
      return json(200, { ok: true, live: true });
    }

    if (action === 'update') {
      const err = validatePiece(body.piece);
      if (err) return json(400, { error: err });
      const p = sanitizePiece(body.piece);

      if (isProhibited(p.title + '\n' + p.art + '\n' + p.tags.join(' '))) {
        return json(400, { error: 'This update contains prohibited content and cannot be published' });
      }

      // OWNERSHIP GATE: only the owner of this id (or the admin) may touch it.
      // The owner record is the authority — if it doesn't exist, nothing was
      // ever published under this id via submissions (404).
      const storedOwner = await store.get(`owner/${p.id}`);
      if (!isAdmin) {
        if (!storedOwner) return json(404, { error: 'Not found' });
        if (storedOwner !== ownerHash) return json(403, { error: 'Not your art' });
        // TOMBSTONE VETO: an admin delete removes piece/<id> and writes
        // deleted/<id> but leaves owner/<id> behind — owner auth alone must not
        // let the submitter update (resurrect) an id the admin removed.
        if ((await store.get(`deleted/${p.id}`)) !== null) {
          return json(410, { error: 'This art was removed' });
        }
      }
      // Preserve an admin-granted wosVerified badge across owner edits.
      let prevVerified = false;
      try {
        const prevRaw = await store.get(`piece/${p.id}`);
        if (prevRaw !== null) prevVerified = !!JSON.parse(prevRaw).wosVerified;
      } catch { /* corrupt/missing previous record — treat as unverified */ }
      const record = { ...p, wosVerified: prevVerified };
      // NOTE: no tombstone clear here — only admin actions may undelete an id.
      await store.set(`piece/${p.id}`, JSON.stringify(record));
      return json(200, { ok: true, live: true });
    }

    if (action === 'delete') {
      const id = body.id;
      if (!ID_RE.test(id || '')) return json(400, { error: 'Invalid id' });
      const storedOwner = await store.get(`owner/${id}`);
      if (!isAdmin) {
        if (!storedOwner) return json(404, { error: 'Not found' });
        if (storedOwner !== ownerHash) return json(403, { error: 'Not your art' });
      }
      await Promise.all([
        store.delete(`piece/${id}`),
        store.delete(`owner/${id}`),
        store.set(`deleted/${id}`, String(Date.now())),  // tombstone
      ]);
      return json(200, { ok: true });
    }

    return json(400, { error: "action must be 'create', 'update' or 'delete'" });
  } catch (err) {
    return json(500, { error: 'Blob op failed', detail: String(err) });
  }
};
