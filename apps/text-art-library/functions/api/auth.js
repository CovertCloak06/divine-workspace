// Cloudflare Pages Function — POST /api/auth
// Equivalent of netlify/functions/auth.js.
// Validates editor password against EDITOR_PASSWORD env var.

export async function onRequestPost(context) {
  const { request, env } = context;
  if (!env.EDITOR_PASSWORD) {
    return json({ error: 'EDITOR_PASSWORD not configured' }, 500);
  }
  let body;
  try { body = await request.json(); }
  catch { return json({ error: 'Bad JSON' }, 400); }

  if (body && body.password === env.EDITOR_PASSWORD) {
    return json({ ok: true });
  }
  return json({ error: 'Wrong password' }, 401);
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
