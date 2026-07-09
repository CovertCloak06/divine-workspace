// Frostline — GET /get-popular  (PUBLIC)
// Powers the "🔥 Popular" discovery rail: the most-copied piece ids, from the
// same stat/copy/<id> counters the (admin-only) analytics use. Copy counts are
// non-sensitive aggregates; visit stats and totals stay behind get-stats.js.
// 60s CDN cache absorbs the blob list() fan-out across public pageviews.

import { connectLambda, getStore } from '@netlify/blobs';

function json(status, body, cache) {
  return {
    statusCode: status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': cache || 'no-store' },
    body: JSON.stringify(body),
  };
}

export const handler = async (event) => {
  connectLambda(event);
  if (event.httpMethod !== 'GET') return json(405, { error: 'Method not allowed' });

  try {
    const store = getStore('frostline');
    const { blobs } = await store.list({ prefix: 'stat/copy/' });
    const topCopied = [];
    await Promise.all((blobs || []).map(async ({ key }) => {
      const id = key.slice('stat/copy/'.length);
      if (id === 'total' || !id) return;
      const n = parseInt(await store.get(key), 10) || 0;
      if (n > 0) topCopied.push({ id, n });
    }));
    topCopied.sort((a, b) => b.n - a.n);
    return json(200, { topCopied: topCopied.slice(0, 12) }, 'public, max-age=60');
  } catch (err) {
    return json(500, { error: 'Blob op failed', detail: String(err) });
  }
};
