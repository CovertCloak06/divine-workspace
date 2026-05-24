const { getStore, connectLambda } = require('@netlify/blobs')

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Content-Type': 'application/json',
}

// Each flag stored as its own key: flag/{id} → note text.
// Returns a delta { id, flagged, note } instead of the full flags list
// so the server only does 2 Blob ops per save (read + write/delete) rather
// than N+1, which was causing rate limit hits and intermittent 500s.
exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: CORS, body: '' }
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers: CORS, body: 'Method not allowed' }
  connectLambda(event)

  try {
    const { id, action = 'toggle', note = '' } = JSON.parse(event.body)
    if (!id || typeof id !== 'string') return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'id required' }) }

    const store = getStore('frostline')
    const key = `flag/${id}`
    const existing = await store.get(key)

    let flagged, finalNote

    if (action === 'note') {
      // Always write the note — no read-before-write. A stale blob read returning
      // null for a real key caused the old check to silently drop notes and
      // report flagged:false, which made the client delete the flag from memory.
      await store.set(key, note)
      flagged = true
      finalNote = note
    } else {
      if (existing !== null) {
        await store.delete(key)
        flagged = false
        finalNote = ''
      } else {
        await store.set(key, note)
        flagged = true
        finalNote = note
      }
    }

    return { statusCode: 200, headers: CORS, body: JSON.stringify({ id, flagged, note: finalNote }) }
  } catch (err) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: err.message }) }
  }
}
