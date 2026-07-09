// Frostline — POST /bugs-inbox  (ADMIN ONLY; Bearer = editor password)
// The read/manage side of the bug-report pipeline. Reports are written by the
// public submit-bug.js into the 'frostline-feedback' store as bug/<id>.json
// (description, reporter, AI triage {severity, area, summary, likely_cause,
// suggested_fix}, context {appVersion, url, userAgent, viewport}, createdAt).
//
// Actions:
//   { action:'list' }          → { reports: [...] } open-first, newest-first
//   { action:'resolve', id }   → sets status:'resolved' on the stored record
//   { action:'reopen',  id }   → sets status back to 'open'
//   { action:'delete',  id }   → removes the record permanently

import { connectLambda, getStore } from '@netlify/blobs';
import { verifyRequest } from './_auth.js';

const ID_RE = /^[A-Za-z0-9.-]{1,80}$/;

function json(status, body) {
  return { statusCode: status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, body: JSON.stringify(body) };
}

export const handler = async (event) => {
  connectLambda(event);
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });
  if (!(await verifyRequest(event))) return json(401, { error: 'Unauthorized' });

  let body;
  try { body = JSON.parse(event.body || '{}'); }
  catch { return json(400, { error: 'Bad JSON' }); }

  const { action, id } = body;

  try {
    const store = getStore('frostline-feedback');

    if (action === 'list') {
      const { blobs } = await store.list({ prefix: 'bug/' });
      const reports = [];
      await Promise.all((blobs || []).map(async ({ key }) => {
        const raw = await store.get(key);
        if (raw === null) return;
        try {
          const r = JSON.parse(raw);
          // Slim the payload for the inbox: drop noisy integration receipts.
          reports.push({
            id: r.id,
            description: r.description,
            reporter: r.reporter || null,
            status: r.status === 'resolved' ? 'resolved' : 'open',
            createdAt: r.createdAt || 0,
            triage: (r.triage && !r.triage.error && !r.triage.skipped) ? {
              severity: r.triage.severity,
              area: r.triage.area,
              summary: r.triage.summary,
              likely_cause: r.triage.likely_cause,
              suggested_fix: r.triage.suggested_fix,
            } : null,
            context: {
              appVersion: r.context?.appVersion,
              viewport: r.context?.viewport,
              url: r.context?.url,
            },
            issueUrl: r.issue?.url || null,
          });
        } catch { /* corrupt record — skip */ }
      }));
      // Open before resolved, then newest first.
      reports.sort((a, b) =>
        (a.status === 'resolved' ? 1 : 0) - (b.status === 'resolved' ? 1 : 0)
        || (b.createdAt || 0) - (a.createdAt || 0));
      return json(200, { reports });
    }

    if (action === 'resolve' || action === 'reopen' || action === 'delete') {
      if (!ID_RE.test(id || '')) return json(400, { error: 'Invalid id' });
      const key = `bug/${id}.json`;
      if (action === 'delete') {
        await store.delete(key);
        return json(200, { ok: true });
      }
      const raw = await store.get(key);
      if (raw === null) return json(404, { error: 'No such report' });
      let r;
      try { r = JSON.parse(raw); } catch { return json(500, { error: 'Corrupt record' }); }
      r.status = action === 'resolve' ? 'resolved' : 'open';
      r.statusChangedAt = Date.now();
      await store.set(key, JSON.stringify(r));
      return json(200, { ok: true, status: r.status });
    }

    return json(400, { error: "action must be 'list', 'resolve', 'reopen' or 'delete'" });
  } catch (err) {
    return json(500, { error: 'Blob op failed', detail: String(err) });
  }
};
