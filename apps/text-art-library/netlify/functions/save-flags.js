const { getStore, connectLambda } = require('@netlify/blobs')

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Content-Type': 'application/json',
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: CORS, body: '' }
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers: CORS, body: 'Method not allowed' }
  connectLambda(event)

  try {
    const { id, action = 'toggle', note = '' } = JSON.parse(event.body)
    if (!id || typeof id !== 'string') return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'id required' }) }

    const store = getStore('frostline')
    let flags = (await store.get('flags', { type: 'json' })) || {}

    // Normalize old array format to object
    if (Array.isArray(flags)) {
      flags = Object.fromEntries(flags.map(fid => [fid, '']))
    }

    if (action === 'note') {
      if (id in flags) flags[id] = note
    } else {
      if (id in flags) delete flags[id]
      else flags[id] = note
    }

    await store.setJSON('flags', flags)
    return { statusCode: 200, headers: CORS, body: JSON.stringify({ flags }) }
  } catch (err) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: err.message }) }
  }
}
