import { createServer } from 'node:http';
import { readFile, writeFile } from 'node:fs/promises';
import { log } from './logger.js';
import { notifyPushover } from './notify/pushover.js';

/**
 * First-run setup server. Serves a small mobile-friendly form so a
 * non-technical person can enter their Pushover keys (and optional filters),
 * send a test notification, and write the .env file — without touching a
 * command line. Started by `npm run setup` / the installer on first run.
 */

const PORT = Number(process.env.SETUP_PORT || 8787);
const ENV_PATH = process.env.ENV_PATH || '.env';

function page(msg = '', ok = false): string {
  const banner = msg
    ? `<div class="banner ${ok ? 'ok' : 'err'}">${msg}</div>`
    : '';
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Supreme Watcher — Setup</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin:0; font-family:-apple-system,system-ui,"Segoe UI",Roboto,sans-serif;
    background:#0d1a2e; color:#e8eef7; padding:24px; line-height:1.5; }
  .card { max-width:460px; margin:0 auto; background:#152540; border:1px solid #2a3f63;
    border-radius:16px; padding:24px; }
  h1 { font-size:22px; margin:0 0 4px; }
  p.sub { margin:0 0 20px; color:#9fb3d0; font-size:14px; }
  label { display:block; font-size:13px; font-weight:600; margin:14px 0 6px; color:#c3d3ea; }
  input { width:100%; padding:12px; border-radius:10px; border:1px solid #2a3f63;
    background:#0d1a2e; color:#e8eef7; font-size:16px; }
  .hint { font-size:12px; color:#7d93b4; margin-top:4px; }
  .row { display:flex; gap:10px; margin-top:22px; }
  button { flex:1; padding:14px; border:0; border-radius:10px; font-size:16px;
    font-weight:700; cursor:pointer; }
  .test { background:#274a74; color:#dbe8fb; }
  .save { background:#3f8de0; color:#fff; }
  .banner { padding:12px 14px; border-radius:10px; margin-bottom:18px; font-size:14px; }
  .banner.ok { background:#12402a; border:1px solid #2f7d55; color:#b6f0cf; }
  .banner.err { background:#40211f; border:1px solid #8a4038; color:#ffc9c2; }
  a { color:#7fb4ef; }
</style></head>
<body><div class="card">
  <h1>❄️ Supreme Watcher</h1>
  <p class="sub">One-time setup. Enter your Pushover keys, tap <b>Test</b> to
    make your phone buzz, then <b>Save &amp; Start</b>.</p>
  ${banner}
  <form method="POST" action="/save">
    <label>Pushover User Key</label>
    <input name="user" required placeholder="u...." autocomplete="off">
    <div class="hint">On the Pushover app's main screen.</div>

    <label>Pushover API Token</label>
    <input name="token" required placeholder="a...." autocomplete="off">
    <div class="hint">Create at pushover.net → Create an Application.</div>

    <label>Keywords to watch (optional)</label>
    <input name="keywords" placeholder="box logo, tee, hoodie">
    <div class="hint">Comma-separated. Leave blank to alert on everything.</div>

    <label>Max price in USD (optional)</label>
    <input name="maxPrice" inputmode="numeric" placeholder="e.g. 200">

    <div class="row">
      <button class="test" formaction="/test">Test</button>
      <button class="save">Save &amp; Start</button>
    </div>
  </form>
</div></body></html>`;
}

function parseBody(body: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const pair of body.split('&')) {
    if (!pair) continue;
    const [k, v = ''] = pair.split('=');
    if (!k) continue;
    out[decodeURIComponent(k)] = decodeURIComponent(v.replace(/\+/g, ' ')).trim();
  }
  return out;
}

async function readBody(req: import('node:http').IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

function envContents(f: Record<string, string>): string {
  const lines = [
    `PUSHOVER_USER=${f.user ?? ''}`,
    `PUSHOVER_TOKEN=${f.token ?? ''}`,
    'SUPREME_BASE_URL=https://www.supremenewyork.com',
    'POLL_INTERVAL_MS=60000',
    'JITTER_MS=15000',
    `WATCH_KEYWORDS=${f.keywords ?? ''}`,
    'WATCH_CATEGORIES=',
    `MAX_PRICE=${f.maxPrice ?? ''}`,
    'ALERT_ON_RESTOCK=true',
    'ALERT_ON_PRICE_DROP=false',
    'DRY_RUN=false',
    'STORE_PATH=./data/state.json',
  ];
  return `${lines.join('\n')}\n`;
}

const server = createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html' }).end(page());
      return;
    }
    if (req.method === 'POST' && (req.url === '/save' || req.url === '/test')) {
      const f = parseBody(await readBody(req));
      if (!f.user || !f.token) {
        res.writeHead(200, { 'Content-Type': 'text/html' }).end(
          page('Please enter both the User Key and API Token.', false),
        );
        return;
      }

      if (req.url === '/test') {
        try {
          await notifyPushover({ token: f.token, user: f.user }, 'new', {
            id: 'test',
            name: 'Test alert — Supreme Watcher is working!',
            category: 'Setup',
            price: 0,
            soldOut: false,
            url: 'https://www.supremenewyork.com',
          });
          res.writeHead(200, { 'Content-Type': 'text/html' }).end(
            page('✅ Test sent! Check your phone for a notification.', true),
          );
        } catch (err) {
          res.writeHead(200, { 'Content-Type': 'text/html' }).end(
            page(`❌ Test failed: ${(err as Error).message}. Double-check your keys.`, false),
          );
        }
        return;
      }

      // /save
      await writeFile(ENV_PATH, envContents(f), 'utf8');
      log.info(`Configuration written to ${ENV_PATH}`);
      res.writeHead(200, { 'Content-Type': 'text/html' }).end(
        page('✅ Saved! The watcher is starting. You can close this page.', true),
      );
      // Give the response time to flush, then exit so the installer starts the bot.
      setTimeout(() => process.exit(0), 500);
      return;
    }
    res.writeHead(404).end('Not found');
  } catch (err) {
    log.error('Setup server error', err);
    res.writeHead(500).end('Server error');
  }
});

server.listen(PORT, () => {
  log.info('─'.repeat(52));
  log.info('Supreme Watcher setup is ready. Open this on the device:');
  log.info(`   http://localhost:${PORT}`);
  log.info('(or from another device on the same Wi-Fi: http://<this-device-ip>:' + PORT + ')');
  log.info('─'.repeat(52));
});

// If a .env already exists with real keys, note it (don't block re-config).
readFile(ENV_PATH, 'utf8')
  .then((c) => {
    if (/PUSHOVER_USER=\S/.test(c)) log.info('An existing .env was found — saving will overwrite it.');
  })
  .catch(() => {});
