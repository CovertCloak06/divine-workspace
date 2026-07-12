// Frostline — GET /get-stats  (ADMIN ONLY; Bearer = editor password)
// Returns { visitsByDay: {date:n}, visitsTotal, topCopied: [{id,n}], copyTotal,
//           copiesByDay: {date:n},                                    // wos104
//           devicesTotal, newDevicesByDay: {date:n},
//           topDevices: [{id, n, first?, last?}] }                    // wos104 first/last
//
// Private analytics for the editor drawer — never exposed publicly. All numbers
// are anonymous aggregates written by /track; device ids are opaque random
// client-minted strings (no PII, no fingerprints).

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

    // wos104: copies per day (mirrors visit-day; powers the copies-over-time chart)
    const copiesByDay = {};
    const { blobs: copyDayBlobs } = await store.list({ prefix: 'stat/copy-day/' });
    await Promise.all((copyDayBlobs || []).map(async ({ key }) => {
      const date = key.slice('stat/copy-day/'.length);
      copiesByDay[date] = parseInt(await store.get(key), 10) || 0;
    }));

    // wos98: new devices per day (first-ever sighting of a device id)
    const newDevicesByDay = {};
    const { blobs: newDevBlobs } = await store.list({ prefix: 'stat/new-device-day/' });
    await Promise.all((newDevBlobs || []).map(async ({ key }) => {
      const date = key.slice('stat/new-device-day/'.length);
      newDevicesByDay[date] = parseInt(await store.get(key), 10) || 0;
    }));

    // wos98: per-device visit counts — powers "top returning devices"
    const topDevices = [];
    const { blobs: devBlobs } = await store.list({ prefix: 'stat/device/' });
    await Promise.all((devBlobs || []).map(async ({ key }) => {
      const id = key.slice('stat/device/'.length);
      if (!id) return;
      topDevices.push({ id, n: parseInt(await store.get(key), 10) || 0 });
    }));
    topDevices.sort((a, b) => b.n - a.n);
    const topDevicesSliced = topDevices.slice(0, 25);
    // wos104: attach each top device's activity window (first/last seen). Only
    // the sliced top 25 are read, so the fan-out stays bounded. Legacy devices
    // (seen before wos104) simply have no meta and omit first/last.
    await Promise.all(topDevicesSliced.map(async (d) => {
      try {
        const meta = JSON.parse(await store.get(`stat/device-meta/${d.id}`));
        if (meta && meta.first) { d.first = meta.first; d.last = meta.last || meta.first; }
      } catch { /* no meta for this device */ }
    }));

    const visitsTotal = parseInt(await store.get('stat/visit-total'), 10) || 0;
    const copyTotal = parseInt(await store.get('stat/copy-total'), 10) || 0;
    const devicesTotal = parseInt(await store.get('stat/device-total'), 10) || 0;

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
      body: JSON.stringify({
        visitsByDay, visitsTotal,
        topCopied: topCopied.slice(0, 25), copyTotal, copiesByDay,
        devicesTotal, newDevicesByDay, topDevices: topDevicesSliced,
      }),
    };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: 'Blob op failed', detail: String(err) }) };
  }
};
