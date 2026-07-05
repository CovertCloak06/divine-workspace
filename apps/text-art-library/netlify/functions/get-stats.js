// Frostline — GET /get-stats  (ADMIN ONLY; Bearer = editor password)
// Returns { visitsByDay: {date:n}, visitsTotal, topCopied: [{id,n}], copyTotal }
//
// Private analytics for the editor drawer — never exposed publicly. All numbers
// are anonymous aggregates written by /track.

import { connectLambda, getStore } from '@netlify/blobs';
import { verifyRequest } from './_auth.js';

export const handler = async (event) => {
  connectLambda(event);

  if (!(await verifyRequest(event))) {
    return { statusCode: 401, body: JSON.stringify({ error: 'Unauthorized' }) };
  }

  try {
    const store = getStore('frostline');

    // Visits per day
    const visitsByDay = {};
    const { blobs: dayBlobs } = await store.list({ prefix: 'stat/visit-day/' });
    await Promise.all((dayBlobs || []).map(async ({ key }) => {
      const date = key.slice('stat/visit-day/'.length);
      visitsByDay[date] = parseInt(await store.get(key), 10) || 0;
    }));

    // Most-copied pieces
    const topCopied = [];
    const { blobs: copyBlobs } = await store.list({ prefix: 'stat/copy/' });
    await Promise.all((copyBlobs || []).map(async ({ key }) => {
      const id = key.slice('stat/copy/'.length);
      topCopied.push({ id, n: parseInt(await store.get(key), 10) || 0 });
    }));
    topCopied.sort((a, b) => b.n - a.n);

    const visitsTotal = parseInt(await store.get('stat/visit-total'), 10) || 0;
    const copyTotal = parseInt(await store.get('stat/copy-total'), 10) || 0;

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
      body: JSON.stringify({ visitsByDay, visitsTotal, topCopied: topCopied.slice(0, 25), copyTotal }),
    };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: 'Blob op failed', detail: String(err) }) };
  }
};
