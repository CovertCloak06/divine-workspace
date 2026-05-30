# supreme-watcher

A small, always-on bot that monitors the official Supreme store
(`supremenewyork.com`) for **new items** and **restocks**, and sends
**real-time Pushover alerts** to an iPhone (or any device running the Pushover
app).

It is intentionally a **monitor + alerter**, not an auto-checkout bot — it never
adds to cart or purchases. It polls the store's public catalog feed politely and
notifies you when something matching your filters appears or comes back in stock.

---

## How it works

```
┌──────────────┐    poll every ~60s    ┌──────────────┐
│ supreme-     │ ────────────────────▶ │  Supreme     │  /mobile_stock.json
│ watcher loop │                       │  store feed  │
└──────┬───────┘ ◀──── listings ────── └──────────────┘
       │
       │ compare to saved state (data/state.json)
       │   • id never seen  → "new"
       │   • was sold out, now in stock → "restock"
       │   • price dropped (optional)   → "price-drop"
       ▼
   apply filters (keywords / categories / max price)
       ▼
┌──────────────┐     HTTPS POST        ┌──────────────┐
│  Pushover    │ ────────────────────▶ │  iPhone push │
└──────────────┘                       └──────────────┘
```

On the **first run** the store is empty, so it silently records the current
catalog (no alert spam) and only alerts on changes from then on.

---

## Quick start (the person running it)

Requirements: Node.js 20+.

```bash
# 1. Install dependencies
npm install

# 2. Configure
cp env.example .env
#    then edit .env and set PUSHOVER_TOKEN and PUSHOVER_USER (see below)

# 3. Try it without sending notifications
#    (set DRY_RUN=true in .env first), then:
npm run dev

# 4. Run for real
npm run build
npm start
```

### Getting Pushover credentials (one-time, ~3 min)

1. Sign up at <https://pushover.net> → your **User Key** is on the dashboard.
2. Create an application token at <https://pushover.net/apps/build> → that's your
   **Application API Token**.
3. Install the **Pushover** app on the iPhone from the App Store and log in with
   the same account. (Pushover is a one-time ~$5 purchase per platform after a
   trial — the cheapest, most reliable iOS push option.)
4. Put both values in `.env`.

That's the entire setup for the recipient — no bot registration, no scraping
keys, nothing that breaks on an iOS update.

---

## Configuration

All settings live in `.env` (see `env.example` for the annotated list):

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `PUSHOVER_TOKEN` | ✅ | — | Pushover application API token |
| `PUSHOVER_USER` | ✅ | — | Pushover user key |
| `SUPREME_BASE_URL` | | `https://www.supremenewyork.com` | US or EU (`https://uk.supremenewyork.com`) store |
| `POLL_INTERVAL_MS` | | `60000` | Base time between checks (min 10000) |
| `JITTER_MS` | | `15000` | Random extra delay per cycle |
| `WATCH_KEYWORDS` | | _(any)_ | Comma-separated name substrings, e.g. `box logo,tee` |
| `WATCH_CATEGORIES` | | _(any)_ | Comma-separated categories, e.g. `Jackets,Accessories` |
| `MAX_PRICE` | | _(none)_ | Only alert at/below this USD price |
| `ALERT_ON_RESTOCK` | | `true` | Alert when a sold-out item returns |
| `ALERT_ON_PRICE_DROP` | | `false` | Alert when a watched item's price drops |
| `DRY_RUN` | | `false` | Log matches instead of sending |

---

## Running it 24/7 (host options — pick any)

The bot is just a long-running Node process, so any always-on host works. The
iPhone only **receives** alerts; it does not run the bot.

- **Docker** (anywhere): `docker build -t supreme-watcher . && docker run -d --env-file .env -v $PWD/data:/app/data supreme-watcher`
- **Raspberry Pi / spare Android (Termux) / home server**: `npm run build && npm start`, kept alive with `pm2` or a `systemd` service.
- **Tiny VPS** (Fly.io, Oracle free tier, a $4 droplet): same as above or via the Dockerfile.
- **Cloudflare Workers + Cron Triggers**: swap `src/store.ts` for a KV/D1-backed
  store and invoke `runCycle` from a scheduled handler. The source/matcher/notify
  code is reused as-is.

---

## Development

```bash
npm run dev     # watch mode
npm test        # run unit tests (matcher + store)
npm run check   # typecheck only
```

### Project layout

```
src/
  index.ts          # main poll loop + alert classification
  config.ts         # env parsing/validation (zod)
  env.ts            # tiny zero-dep .env loader
  matcher.ts        # pure filter logic (keywords/categories/price)
  store.ts          # JSON-file state (dedupe + restock detection)
  logger.ts         # minimal leveled logger
  sources/
    types.ts        # Listing + Source interfaces
    supreme.ts      # supremenewyork.com adapter
  notify/
    pushover.ts     # Pushover delivery
tests/              # node:test unit tests
```

### Adding another marketplace

Implement the `Source` interface in `src/sources/` (return normalized
`Listing[]`), then add it to the loop in `index.ts`. The matcher, store, and
notifier are all source-agnostic.

---

## Notes & etiquette

- Keep `POLL_INTERVAL_MS` reasonable (≥ 60s). Aggressive polling risks rate
  limiting and is rude to the origin.
- This tool only **reads** the public catalog and **notifies** you. It does not
  automate purchases or attempt to bypass any protections.
