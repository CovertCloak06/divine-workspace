// Cloudflare Pages Function — GET /api/get-art
// Per-piece storage in FROSTLINE_KV (mirrors the durable Netlify function):
//   piece:<id>    — one art piece (its own record)
//   deleted:<id>  — tombstone (so deletes propagate + redeploys can't resurrect)
// Returns { library, deletedIds }. Falls back to the LEGACY aggregate keys
// (art / deletedIds) for one-time migration. 404 when truly empty.

export async function onRequestGet(context) {
  const { env } = context;
  if (!env.FROSTLINE_KV) return json({ error: 'FROSTLINE_KV binding missing' }, 500);
  try {
    const [pieceList, delList] = await Promise.all([
      env.FROSTLINE_KV.list({ prefix: 'piece:' }),
      env.FROSTLINE_KV.list({ prefix: 'deleted:' }),
    ]);
    const deletedIds = (delList.keys || []).map((k) => k.name.slice('deleted:'.length));

    if (pieceList.keys && pieceList.keys.length) {
      const library = await Promise.all(
        pieceList.keys.map(async ({ name }) => {
          const raw = await env.FROSTLINE_KV.get(name);
          try { return JSON.parse(raw); } catch { return null; }
        }),
      );
      return json({ library: library.filter(Boolean), deletedIds });
    }

    // No per-piece records — try legacy aggregate keys for one-time migration.
    const [artRaw, legacyDelRaw] = await Promise.all([
      env.FROSTLINE_KV.get('art'),
      env.FROSTLINE_KV.get('deletedIds'),
    ]);
    if (artRaw === null && legacyDelRaw === null && deletedIds.length === 0) {
      return json({ error: 'Not seeded' }, 404);
    }
    const legacyDeleted = legacyDelRaw ? JSON.parse(legacyDelRaw) : [];
    return json({
      art: artRaw ? JSON.parse(artRaw) : [],
      deletedIds: [...new Set([...deletedIds, ...legacyDeleted])],
    });
  } catch (err) {
    return json({ error: 'KV read failed', detail: String(err) }, 500);
  }
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}
