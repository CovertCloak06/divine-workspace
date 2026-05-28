// Cloudflare Pages Function — POST /api/save-flags
// No auth (anyone can flag). Body: { id, action: 'toggle' | 'note', note?: string }

export async function onRequestPost(context) {
  const { request, env } = context;
  if (!env.FROSTLINE_KV) {
    return json({ error: 'FROSTLINE_KV binding missing' }, 500);
  }

  let body;
  try { body = await request.json(); }
  catch { return json({ error: 'Bad JSON' }, 400); }

  const { id, action, note } = body || {};
  if (!id || typeof id !== 'string' || id.length > 200) {
    return json({ error: 'Missing or invalid id' }, 400);
  }
  if (action !== 'toggle' && action !== 'note') {
    return json({ error: "action must be 'toggle' or 'note'" }, 400);
  }

  const key = `flag/${id}`;
  try {
    if (action === 'toggle') {
      const existing = await env.FROSTLINE_KV.get(key);
      if (existing === null) {
        await env.FROSTLINE_KV.put(key, '');
        return json({ ok: true, flagged: true, note: '' });
      }
      await env.FROSTLINE_KV.delete(key);
      return json({ ok: true, flagged: false });
    }
    await env.FROSTLINE_KV.put(key, String(note || ''));
    return json({ ok: true, flagged: true, note: String(note || '') });
  } catch (err) {
    return json({ error: 'KV op failed', detail: String(err) }, 500);
  }
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
