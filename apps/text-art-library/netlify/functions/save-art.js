const { getStore, connectLambda } = require('@netlify/blobs')

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Content-Type': 'application/json',
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: CORS, body: '' }
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers: CORS, body: 'Method not allowed' }
  connectLambda(event)

  const password = (event.headers.authorization || '').replace('Bearer ', '').trim()
  if (password !== process.env.EDITOR_PASSWORD) {
    return { statusCode: 401, headers: CORS, body: JSON.stringify({ error: 'Unauthorized' }) }
  }

  try {
    const { art } = JSON.parse(event.body)
    if (!Array.isArray(art)) return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'art must be array' }) }
    const store = getStore('frostline')
    await store.setJSON('art', art)
    return { statusCode: 200, headers: CORS, body: JSON.stringify({ ok: true }) }
  } catch (err) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: err.message }) }
  }
}
