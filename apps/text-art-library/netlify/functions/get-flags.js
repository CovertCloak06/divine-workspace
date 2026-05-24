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

    // Check for per-key flags (new format)
    const { blobs } = await store.list({ prefix: 'flag/' })

    let flags = {}

    if (blobs.length > 0) {
      await Promise.all(blobs.map(async ({ key }) => {
        flags[key.slice('flag/'.length)] = (await store.get(key)) || ''
      }))
    } else {
      // Migrate from legacy monolithic 'flags' blob if it exists
      const legacy = await store.get('flags', { type: 'json' })
      if (legacy) {
        const obj = Array.isArray(legacy)
          ? Object.fromEntries(legacy.map(id => [id, '']))
          : legacy
        // Write each entry to its own key
        await Promise.all(Object.entries(obj).map(([fid, fnote]) =>
          store.set(`flag/${fid}`, fnote || '')
        ))
        flags = obj
      }
    }

    return { statusCode: 200, headers: CORS, body: JSON.stringify({ flags }) }
  } catch (err) {
    return { statusCode: 200, headers: CORS, body: JSON.stringify({ flags: {} }) }
  }
}
