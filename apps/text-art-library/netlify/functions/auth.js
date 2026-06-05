// Frostline — POST /auth
// Validates the editor password. Source of truth: see _auth.js
// (blob `auth/password` if rotated, env var EDITOR_PASSWORD otherwise).
// Returns { ok: true } on success, 401 on failure.

import { verifyPassword } from './_auth.js';

export const handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  let body;
  try { body = JSON.parse(event.body || '{}'); }
  catch { return { statusCode: 400, body: JSON.stringify({ error: 'Bad JSON' }) }; }

  const ok = await verifyPassword(body.password);
  if (ok) {
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ok: true }),
    };
  }
  return {
    statusCode: 401,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ error: 'Wrong password' }),
  };
};
