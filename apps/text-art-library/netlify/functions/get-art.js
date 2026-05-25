const { getStore, connectLambda } = require('@netlify/blobs')

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Content-Type': 'application/json',
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: CORS, body: '' }
  if (event.httpMethod !== 'GET') return { statusCode: 405, headers: CORS, body: 'Method not allowed' }
  connectLambda(event)

  try {
    const store = getStore('frostline')
    const art = await store.get('art', { type: 'json' })
    if (!art) return { statusCode: 404, headers: CORS, body: JSON.stringify({ art: null }) }
    const deletedIds = await store.get('deletedIds', { type: 'json' }) || []
    return { statusCode: 200, headers: CORS, body: JSON.stringify({ art, deletedIds }) }
  } catch (err) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: err.message }) }
  }
}
