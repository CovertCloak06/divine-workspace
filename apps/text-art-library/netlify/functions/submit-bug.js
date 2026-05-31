// Frostline — POST /submit-bug
// Public endpoint (no auth) — anyone using the app can submit a bug report.
// Pipeline: validate input -> Anthropic triage -> Netlify Blobs storage ->
// GitHub Issue creation -> Discord webhook notification. Each external
// integration is OPTIONAL and degrades gracefully: missing env vars skip that
// step rather than failing the request, so the form keeps working even if a
// single integration is misconfigured.

import { connectLambda, getStore } from '@netlify/blobs';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

const json = (statusCode, obj) => ({
  statusCode,
  headers: { 'Content-Type': 'application/json', ...CORS },
  body: JSON.stringify(obj),
});

const MAX_DESC = 4000;
const MAX_REPORTER = 80;

const TRIAGE_SYSTEM = `You are a triage assistant for the Frostline text-art app — a curated character-art library for the Whiteout Survival mobile-game alliance chat. The app's main surfaces are:
- A grid of art cards filterable by theme tags
- A hamburger Settings drawer (accordion with sections; Themes is the first)
- An editor modal with Text and Draw modes, toggled by a switch in the modal head
- A character palette in Draw mode, grouped (Hearts / Stars / Eyes / Mouths / etc.) with a dynamic group-name label that tracks scroll position
- A favorites bar above the palette
- Save / lock / export buttons in the bottom bar
- Editor unlock is gated behind a 7-tap snowflake gesture + password modal

Given a user's bug report, respond with ONLY a JSON object — no prose before or after, no markdown fence. Schema:
{
  "severity": "P1" | "P2" | "P3" | "cosmetic",
  "area": "<short feature area, e.g. 'Editor / Draw mode' or 'Settings drawer / accordion'>",
  "summary": "<one short sentence summarizing the problem>",
  "likely_cause": "<one short sentence: your best hypothesis>",
  "suggested_fix": "<short bullet on where to look — file or function area if you can infer it>",
  "needs_clarification": <true or false>,
  "clarifying_questions": [<zero to two short questions to ask the reporter, or empty array>]
}

Severity guide: P1 = broken core flow (can't save, can't open); P2 = significant feature broken or unusable on the reporter's device; P3 = noticeable but workable; cosmetic = visual only.`;

async function triage(description, context) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return { skipped: 'ANTHROPIC_API_KEY not configured' };

  const userPrompt = `Bug report:
"""
${description}
"""

Reporter context:
${JSON.stringify(context, null, 2)}`;

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 600,
        system: [
          {
            type: 'text',
            text: TRIAGE_SYSTEM,
            cache_control: { type: 'ephemeral' },
          },
        ],
        messages: [{ role: 'user', content: userPrompt }],
      }),
    });
    if (!response.ok) {
      return { error: `anthropic ${response.status}` };
    }
    const data = await response.json();
    const text = data.content?.[0]?.text || '';
    const match = text.match(/\{[\s\S]*\}/);
    if (!match) return { error: 'no JSON in triage response', raw: text.slice(0, 200) };
    try {
      return JSON.parse(match[0]);
    } catch (err) {
      return { error: 'invalid JSON in triage response', raw: text.slice(0, 200) };
    }
  } catch (err) {
    return { error: 'triage call threw', detail: String(err).slice(0, 200) };
  }
}

const SEV_COLOR = { P1: 0xff4d4d, P2: 0xff9933, P3: 0xffd633, cosmetic: 0x66b3ff };
const SEV_EMOJI = { P1: '🔴', P2: '🟠', P3: '🟡', cosmetic: '🔵' };

async function postToDiscord(report) {
  const url = process.env.DISCORD_WEBHOOK_URL;
  if (!url) return { skipped: 'DISCORD_WEBHOOK_URL not configured' };

  const t = report.triage && !report.triage.error && !report.triage.skipped ? report.triage : null;
  const sev = t?.severity || 'untriaged';
  const emoji = SEV_EMOJI[sev] || '⚪';
  const color = SEV_COLOR[sev] || 0x999999;

  const fields = [
    { name: 'Reporter', value: report.reporter || 'anonymous', inline: true },
    { name: 'Area', value: t?.area || '—', inline: true },
  ];
  if (t?.likely_cause) fields.push({ name: 'Likely cause', value: t.likely_cause.slice(0, 1024) });
  if (t?.suggested_fix) fields.push({ name: 'Suggested fix', value: t.suggested_fix.slice(0, 1024) });
  if (report.issue?.url) fields.push({ name: 'GitHub issue', value: report.issue.url });
  if (t?.needs_clarification && Array.isArray(t.clarifying_questions) && t.clarifying_questions.length) {
    fields.push({ name: 'Open questions', value: t.clarifying_questions.map((q) => `• ${q}`).join('\n').slice(0, 1024) });
  }

  const embed = {
    title: `${emoji} ${sev} — ${t?.summary || report.description.slice(0, 80)}`,
    description: report.description.slice(0, 2000),
    color,
    fields,
    footer: { text: `frostline · ${report.context?.appVersion || 'unknown'} · ${report.id}` },
    timestamp: new Date(report.createdAt).toISOString(),
  };

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ embeds: [embed] }),
    });
    if (!res.ok) return { error: `discord ${res.status}` };
    return { ok: true };
  } catch (err) {
    return { error: 'discord call threw', detail: String(err).slice(0, 200) };
  }
}

async function createGitHubIssue(report) {
  const token = process.env.GITHUB_TOKEN;
  const repo = process.env.GITHUB_REPO;
  if (!token || !repo) return { skipped: !token ? 'GITHUB_TOKEN not configured' : 'GITHUB_REPO not configured' };

  const t = report.triage && !report.triage.error && !report.triage.skipped ? report.triage : null;
  const sev = t?.severity || 'untriaged';

  const labels = ['bug', `triage:${sev.toLowerCase()}`];

  const lines = [];
  lines.push(`**Reported via in-app feedback** · \`${report.id}\``);
  if (report.reporter) lines.push(`**Reporter:** ${report.reporter}`);
  lines.push('');
  lines.push('> ' + report.description.split('\n').join('\n> '));
  lines.push('');
  if (t) {
    lines.push('---');
    lines.push('');
    lines.push('### Triage');
    lines.push('');
    lines.push('| | |');
    lines.push('|---|---|');
    lines.push(`| Severity | ${t.severity || '—'} |`);
    lines.push(`| Area | ${t.area || '—'} |`);
    lines.push(`| Summary | ${t.summary || '—'} |`);
    lines.push(`| Likely cause | ${t.likely_cause || '—'} |`);
    lines.push(`| Suggested fix | ${t.suggested_fix || '—'} |`);
    if (t.needs_clarification && Array.isArray(t.clarifying_questions) && t.clarifying_questions.length) {
      lines.push(`| Open questions | ${t.clarifying_questions.map((q) => '• ' + q).join('<br>')} |`);
    }
    lines.push('');
  }
  lines.push('### Reporter context');
  lines.push('');
  lines.push('```json');
  lines.push(JSON.stringify(report.context || {}, null, 2));
  lines.push('```');
  lines.push('');
  lines.push('---');
  lines.push('');
  lines.push('_Add the `auto-fix` label to this issue to have Claude attempt a fix automatically and open a PR._');

  const title = `[Bug] ${t?.summary || report.description.slice(0, 80).replace(/\s+/g, ' ').trim()}`;

  try {
    const response = await fetch(`https://api.github.com/repos/${repo}/issues`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github+json',
        'Content-Type': 'application/json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'frostline-bug-bot',
      },
      body: JSON.stringify({ title, body: lines.join('\n'), labels }),
    });
    if (!response.ok) {
      const errBody = await response.text();
      return { error: `github ${response.status}`, detail: errBody.slice(0, 200) };
    }
    const data = await response.json();
    return { number: data.number, url: data.html_url };
  } catch (err) {
    return { error: 'github call threw', detail: String(err).slice(0, 200) };
  }
}

export const handler = async (event) => {
  connectLambda(event);
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: CORS };
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return json(400, { error: 'Bad JSON' });
  }

  const description = String(body.description || '').trim();
  if (!description) return json(400, { error: 'description required' });
  if (description.length > MAX_DESC) {
    return json(400, { error: `description too long (max ${MAX_DESC} chars)` });
  }

  const reporter = String(body.reporter || '').trim().slice(0, MAX_REPORTER) || null;
  const context = body.context && typeof body.context === 'object' ? body.context : {};

  const id = `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  const createdAt = Date.now();
  const report = { id, description, reporter, context, createdAt };

  // 1. Triage (graceful if no API key)
  report.triage = await triage(description, context);

  // 2. Create GitHub Issue first so we can include its URL in the Discord embed
  const issue = await createGitHubIssue(report);
  if (issue && issue.number) report.issue = issue;
  else report.issueResult = issue;

  // 3. Discord notification
  const discord = await postToDiscord(report);
  report.discord = discord;

  // 4. Persist final record (best-effort)
  try {
    const store = getStore('frostline-feedback');
    await store.set(`bug/${id}.json`, JSON.stringify(report));
  } catch (err) {
    report.storeError = String(err).slice(0, 200);
  }

  return json(200, {
    ok: true,
    id,
    triage: report.triage,
    issue: report.issue || null,
    notified: discord?.ok === true,
  });
};
