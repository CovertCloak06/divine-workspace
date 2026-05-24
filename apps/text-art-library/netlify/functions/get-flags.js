const { getStore } = require('@netlify/blobs')

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Content-Type': 'application/json',
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: CORS, body: '' }
  if (event.httpMethod !== 'GET') return { statusCode: 405, headers: CORS, body: 'Method not allowed' }

  try {
    const store = getStore('frostline')
    const flags = await store.get('flags', { type: 'json' })
    return { statusCode: 200, headers: CORS, body: JSON.stringify({ flags: flags || [] }) }
  } catch (err) {
    return { statusCode: 200, headers: CORS, body: JSON.stringify({ flags: [] }) }
  }
}
