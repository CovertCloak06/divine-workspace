// Cloudflare Pages Function — GET /api/get-flags
// Returns { flags: { [pieceId]: noteText } } by listing all flag/* keys.

export async function onRequestGet(context) {
  const { env } = context;
  if (!env.FROSTLINE_KV) {
    return json({ error: 'FROSTLINE_KV binding missing' }, 500);
  }
  try {
    const flags = {};
    let cursor = undefined;
    do {
      const result = await env.FROSTLINE_KV.list({ prefix: 'flag/', cursor });
      await Promise.all(
        (result.keys || []).map(async ({ name }) => {
          const id = name.slice('flag/'.length);
          const note = await env.FROSTLINE_KV.get(name);
          flags[id] = note === null ? '' : note;
        }),
      );
      cursor = result.list_complete ? undefined : result.cursor;
    } while (cursor);
    return json({ flags });
  } catch (err) {
    return json({ error: 'KV list failed', detail: String(err) }, 500);
  }
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}
