// Frostline — POST /auth
// Validates the editor password against EDITOR_PASSWORD env var.
// Returns { ok: true } on success, 401 on failure.

export const handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  const expected = process.env.EDITOR_PASSWORD;
  if (!expected) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'EDITOR_PASSWORD not configured' }),
    };
  }

  let body;
  try { body = JSON.parse(event.body || '{}'); }
  catch { return { statusCode: 400, body: JSON.stringify({ error: 'Bad JSON' }) }; }

  if (body.password === expected) {
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
