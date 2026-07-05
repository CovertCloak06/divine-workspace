// Frostline — POST /track  (no auth; anonymous usage counters)
// Body: { event: 'visit' | 'copy', id?: string }
//   visit -> bumps stat/visit-day/<UTC-date> + stat/visit-total
//   copy  -> bumps stat/copy/<id> + stat/copy-total
//
// Counters are anonymous aggregate numbers only — no IPs, no identifiers, no
// per-user data. Increments are best-effort read-modify-write, which is fine
// for this app's volume (a small alliance tool). The day is stamped SERVER-side
// so a client can't backfill arbitrary dates.

import { connectLambda, getStore } from '@netlify/blobs';

async function bump(store, key) {
  const cur = await store.get(key);
  const n = (parseInt(cur, 10) || 0) + 1;
  await store.set(key, String(n));
  return n;
}

function utcDay() {
  return new Date().toISOString().slice(0, 10); // YYYY-MM-DD (UTC)
}

function ok() {
  return {
    statusCode: 200,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ok: true }),
  };
}

export const handler = async (event) => {
  connectLambda(event);
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  let body;
  try { body = JSON.parse(event.body || '{}'); }
  catch { return { statusCode: 400, body: JSON.stringify({ error: 'Bad JSON' }) }; }

  try {
    const store = getStore('frostline');

    if (body.event === 'visit') {
      await bump(store, `stat/visit-day/${utcDay()}`);
      await bump(store, 'stat/visit-total');
      return ok();
    }

    if (body.event === 'copy') {
      const id = body.id;
      if (!id || typeof id !== 'string' || id.length > 200) {
        return { statusCode: 400, body: JSON.stringify({ error: 'Missing or invalid id' }) };
      }
      await bump(store, `stat/copy/${id}`);
      await bump(store, 'stat/copy-total');
      return ok();
    }

    return { statusCode: 400, body: JSON.stringify({ error: "event must be 'visit' or 'copy'" }) };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: 'Blob op failed', detail: String(err) }) };
  }
};
