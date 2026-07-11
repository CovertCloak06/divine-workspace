// Frostline — POST /track  (no auth; anonymous usage counters)
// Body: { event: 'visit' | 'copy', id?: string, device?: string }
//   visit -> bumps stat/visit-day/<UTC-date> + stat/visit-total
//            wos98: with a device id, also bumps stat/device/<id> (visits by
//            that device) and — the first time a device is ever seen —
//            stat/device-total + stat/new-device-day/<UTC-date>.
//   copy  -> bumps stat/copy/<id> + stat/copy-total
//
// Counters are anonymous aggregate numbers only — no IPs, no fingerprints, no
// per-user data. The device id is a client-minted random opaque string; it
// links visits from one browser together and nothing else. Increments are
// best-effort read-modify-write, which is fine for this app's volume (a small
// alliance tool). The day is stamped SERVER-side so a client can't backfill
// arbitrary dates.

import { connectLambda, getStore } from '@netlify/blobs';

// Client ids look like d<hex>; accept a slightly wider shape for headroom but
// stay strict enough that a device key can never smuggle path separators or
// markup into the store / admin panel.
const DEVICE_RE = /^[A-Za-z0-9-]{8,64}$/;
// Blob-spam backstop: past this many unique devices, stop minting NEW device
// counters (visits still count). Orders of magnitude above legit usage.
const MAX_DEVICES = 5000;

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
      // wos98: per-device counters. Invalid/absent device (old clients, blocked
      // storage) still counts the visit above — never a 400.
      const device = typeof body.device === 'string' && DEVICE_RE.test(body.device)
        ? body.device : null;
      if (device) {
        const devKey = `stat/device/${device}`;
        const cur = await store.get(devKey);
        if (cur === null) {
          const total = parseInt(await store.get('stat/device-total'), 10) || 0;
          if (total < MAX_DEVICES) {
            await store.set(devKey, '1');
            await store.set('stat/device-total', String(total + 1));
            await bump(store, `stat/new-device-day/${utcDay()}`);
          }
        } else {
          await store.set(devKey, String((parseInt(cur, 10) || 0) + 1));
        }
      }
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
