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
    const artRaw = await store.get('art')
    if (!artRaw) return { statusCode: 404, headers: CORS, body: JSON.stringify({ art: null }) }
    const art = JSON.parse(artRaw)
    const deletedIdsRaw = await store.get('deletedIds')
    const deletedIds = deletedIdsRaw ? JSON.parse(deletedIdsRaw) : []
    return { statusCode: 200, headers: CORS, body: JSON.stringify({ art, deletedIds }) }
  } catch (err) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: err.message }) }
  }
}
