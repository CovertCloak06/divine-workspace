import { getStore } from '@netlify/blobs'

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Content-Type': 'application/json',
}

function isValidPiece(p) {
  return p && typeof p === 'object'
    && typeof p.id === 'string' && p.id.length > 0
    && typeof p.title === 'string'
    && typeof p.art === 'string'
}

export const handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: CORS, body: '' }
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers: CORS, body: 'Method not allowed' }

  const password = (event.headers.authorization || '').replace('Bearer ', '').trim()
  if (password !== process.env.EDITOR_PASSWORD) {
    return { statusCode: 401, headers: CORS, body: JSON.stringify({ error: 'Unauthorized' }) }
  }

  try {
    const { art, deletedIds } = JSON.parse(event.body)
    if (!Array.isArray(art)) return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'art must be array' }) }
    if (art.length > 5000) return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'art array too large' }) }
    const invalid = art.find(p => !isValidPiece(p))
    if (invalid) return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'invalid piece in art array' }) }

    const store = getStore('frostline')
    await store.set('art', JSON.stringify(art))
    if (Array.isArray(deletedIds)) await store.set('deletedIds', JSON.stringify(deletedIds))
    return { statusCode: 200, headers: CORS, body: JSON.stringify({ ok: true }) }
  } catch (err) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: err.message }) }
  }
}
