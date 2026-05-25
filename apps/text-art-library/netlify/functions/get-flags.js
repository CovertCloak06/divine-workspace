import { getStore } from '@netlify/blobs'

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Content-Type': 'application/json',
}

export const handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: CORS, body: '' }
  if (event.httpMethod !== 'GET') return { statusCode: 405, headers: CORS, body: 'Method not allowed' }

  try {
    const store = getStore('frostline')

    const { blobs } = await store.list({ prefix: 'flag/' })
    const flags = {}
    await Promise.all(blobs.map(async ({ key }) => {
      flags[key.slice('flag/'.length)] = (await store.get(key)) || ''
    }))

    // Migrate legacy blob format — idempotent, deletes legacy blob once all entries are confirmed
    const legacy = await store.get('flags', { type: 'json' })
    if (legacy) {
      const obj = Array.isArray(legacy)
        ? Object.fromEntries(legacy.map(id => [id, '']))
        : (typeof legacy === 'object' && legacy !== null ? legacy : {})
      const unmigrated = Object.entries(obj).filter(([id]) => !(id in flags))
      if (unmigrated.length > 0) {
        await Promise.all(unmigrated.map(([id, note]) =>
          store.set(`flag/${id}`, note || '')
        ))
        for (const [id, note] of unmigrated) flags[id] = note || ''
      }
      if (Object.keys(obj).every(id => id in flags)) {
        await store.delete('flags').catch(() => {})
      }
    }

    return { statusCode: 200, headers: CORS, body: JSON.stringify({ flags }) }
  } catch (err) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: err.message }) }
  }
}
