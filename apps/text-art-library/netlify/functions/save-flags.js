const { getStore } = require('@netlify/blobs')

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Content-Type': 'application/json',
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: CORS, body: '' }
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers: CORS, body: 'Method not allowed' }

  try {
    const { id } = JSON.parse(event.body)
    if (!id || typeof id !== 'string') return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'id required' }) }

    const store = getStore('frostline')
    const flags = (await store.get('flags', { type: 'json' })) || []

    const idx = flags.indexOf(id)
    if (idx >= 0) flags.splice(idx, 1)
    else flags.push(id)

    await store.setJSON('flags', flags)
    return { statusCode: 200, headers: CORS, body: JSON.stringify({ flags }) }
  } catch (err) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: err.message }) }
  }
}
