// Cloudflare Pages Function — POST /api/save-art
// Requires Bearer auth. Per-piece writes (mirrors the durable Netlify function)
// so concurrent edits from different devices never clobber each other. Body:
//   { piece: {...} }              upsert a single piece (clears its tombstone)
//   { deleteId: "<id>" }          delete a single piece (writes a tombstone)
//   { pieces: [...], deletedIds } bulk write (used once for seed/migration)

const ID_RE = /^[A-Za-z0-9_.-]{1,200}$/;

export async function onRequestPost(context) {
  const { request, env } = context;
  if (!env.EDITOR_PASSWORD) return json({ error: 'EDITOR_PASSWORD not configured' }, 500);
  if (!env.FROSTLINE_KV) return json({ error: 'FROSTLINE_KV binding missing' }, 500);

  const auth = request.headers.get('authorization') || '';
  if (auth.replace(/^Bearer\s+/i, '') !== env.EDITOR_PASSWORD) {
    return json({ error: 'Unauthorized' }, 401);
  }

  let body;
  try { body = await request.json(); }
  catch { return json({ error: 'Bad JSON' }, 400); }

  const KV = env.FROSTLINE_KV;
  try {
    // Delete one piece
    if (typeof body.deleteId === 'string') {
      if (!ID_RE.test(body.deleteId)) return json({ error: 'Invalid id' }, 400);
      await Promise.all([
        KV.delete(`piece:${body.deleteId}`),
        KV.put(`deleted:${body.deleteId}`, String(Date.now())),
      ]);
      return json({ ok: true });
    }

    // Upsert one piece
    if (body.piece && typeof body.piece === 'object') {
      const p = body.piece;
      if (!ID_RE.test(p.id || '')) return json({ error: 'Invalid piece id' }, 400);
      await Promise.all([
        KV.put(`piece:${p.id}`, JSON.stringify(p)),
        KV.delete(`deleted:${p.id}`),
      ]);
      return json({ ok: true });
    }

    // Bulk write (seed / migration)
    if (Array.isArray(body.pieces)) {
      const ops = [];
      for (const p of body.pieces) {
        if (p && ID_RE.test(p.id || '')) ops.push(KV.put(`piece:${p.id}`, JSON.stringify(p)));
      }
      for (const id of body.deletedIds || []) {
        if (ID_RE.test(id)) ops.push(KV.put(`deleted:${id}`, String(Date.now())));
      }
      // Retire the legacy aggregate keys so they don't shadow per-piece records.
      ops.push(KV.delete('art'), KV.delete('library'), KV.delete('deletedIds'));
      await Promise.all(ops);
      return json({ ok: true });
    }

    return json({ error: 'Expected piece, deleteId, or pieces' }, 400);
  } catch (err) {
    return json({ error: 'KV write failed', detail: String(err) }, 500);
  }
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
