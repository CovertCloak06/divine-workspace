const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Content-Type': 'application/json',
}

export const handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: CORS, body: '' }
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers: CORS, body: 'Method not allowed' }

  const password = (event.headers.authorization || '').replace('Bearer ', '').trim()
  const expected = process.env.EDITOR_PASSWORD

  if (!expected) return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: 'EDITOR_PASSWORD not set' }) }
  if (password !== expected) return { statusCode: 401, headers: CORS, body: JSON.stringify({ error: 'Wrong password' }) }

  return { statusCode: 200, headers: CORS, body: JSON.stringify({ ok: true }) }
}
