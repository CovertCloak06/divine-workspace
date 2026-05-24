const { getStore, connectLambda } = require('@netlify/blobs')

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Content-Type': 'application/json',
}

// Each flag stored as its own key: flag/{id} → note text
// This avoids the read-modify-write race condition that caused random flag resets
// when two operations hit the server concurrently (both read stale state, last write wins).
async function getAllFlags(store) {
  const { blobs } = await store.list({ prefix: 'flag/' })
  const flags = {}
  await Promise.all(blobs.map(async ({ key }) => {
    flags[key.slice('flag/'.length)] = (await store.get(key)) || ''
  }))
  return flags
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: CORS, body: '' }
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers: CORS, body: 'Method not allowed' }
  connectLambda(event)

  try {
    const { id, action = 'toggle', note = '' } = JSON.parse(event.body)
    if (!id || typeof id !== 'string') return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'id required' }) }

    const store = getStore('frostline')
    const key = `flag/${id}`

    if (action === 'note') {
      const existing = await store.get(key)
      if (existing !== null) await store.set(key, note)
    } else {
      const existing = await store.get(key)
      if (existing !== null) await store.delete(key)
      else await store.set(key, note)
    }

    const flags = await getAllFlags(store)
    return { statusCode: 200, headers: CORS, body: JSON.stringify({ flags }) }
  } catch (err) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: err.message }) }
  }
}
