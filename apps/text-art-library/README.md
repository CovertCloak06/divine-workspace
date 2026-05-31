# Frostline — Text Art Library

Curated text art for one Whiteout Survival alliance. Tap, copy, paste into chat.

## Local preview

This app runs **in this preview** without any backend — it falls back to `localStorage` when neither Netlify Functions nor Cloudflare Pages Functions are reachable. The dev fallback password is `0022`.

To open the live preview, just view `index.html`.

## Deploy options

The client auto-detects whichever backend is live: it probes `/.netlify/functions/get-art` first, falls back to `/api/get-art` (Cloudflare Pages Functions). So either deploy path works without code changes.

### A. Cloudflare Pages + Workers + KV (recommended — generous free tier)

1. **Install Wrangler** locally if you don't have it: `npm i -g wrangler`
2. **Authenticate**: `npx wrangler login`
3. **Create the KV namespace** (one-time):
   ```sh
   npx wrangler kv namespace create FROSTLINE_KV
   ```
   Note the `id` it prints, paste it into `wrangler.toml` under `[[kv_namespaces]]`.
4. **Create the Pages project** (one-time, via dashboard or CLI):
   ```sh
   npx wrangler pages project create frostline-art --production-branch main
   ```
5. **Set the editor password** in the Cloudflare dashboard:
   *Pages → frostline-art → Settings → Environment variables → Production*
   - `EDITOR_PASSWORD` = your chosen password
   *Then bind the KV namespace*:
   - Settings → Functions → KV namespace bindings → Variable name `FROSTLINE_KV` → select the namespace
6. **Deploy**:
   ```sh
   cd apps/text-art-library
   npx wrangler pages deploy . --project-name=frostline-art
   ```

### B. Netlify Functions + Blobs

1. **Install function dependencies** once:
   ```sh
   cd apps/text-art-library
   npm install
   ```
2. **Set the editor password** in the Netlify dashboard:
   *Site config → Environment variables → Functions scope*
   - `EDITOR_PASSWORD` = your chosen password
3. **Deploy from the CLI**:
   ```sh
   npx netlify-cli@latest deploy --prod --dir . --functions ./netlify/functions --no-build
   ```

## Bug feedback pipeline

There's an in-app feedback form in the Settings drawer (Send Feedback section) that anyone using the site can submit. Each submission flows through `netlify/functions/submit-bug.js`, which does four things in order — all of them optional and skipped silently if their env var is missing:

1. **AI triage** via Anthropic's API (model `claude-haiku-4-5`). Reads the report, returns severity / area / summary / likely-cause / suggested-fix area as JSON. Costs pennies per report.
2. **GitHub Issue** created in `CovertCloak06/divine-workspace` with the triage analysis pre-filled in the body, labeled `bug` + `triage:<sev>`.
3. **Discord push** to your phone via the Discord mobile app (a webhook URL = a push notification).
4. **Storage** in Netlify Blobs (`frostline-feedback` store) under `bug/<id>.json` for the full report + everything that happened.

To enable any of the four, add these env vars in *Netlify Site config → Environment variables*:

| Variable | What it enables | Where to get it |
|---|---|---|
| `ANTHROPIC_API_KEY` | AI triage on every report | https://console.anthropic.com/ |
| `DISCORD_WEBHOOK_URL` | Push notifications to your phone | Discord server → Server Settings → Integrations → Webhooks |
| `GITHUB_TOKEN` | Tracking issue creation | https://github.com/settings/tokens (classic, `repo` scope) |
| `GITHUB_REPO` | Target repo for issues | Just `CovertCloak06/divine-workspace` |

(`.env.example` also lists these — add them to your local `.env` for `netlify dev`.)

### Auto-fix loop (optional but slick)

If `GITHUB_TOKEN` is set, every bug report becomes a tracking Issue. From there, you can add the `auto-fix` label to any issue and a GitHub Action (`.github/workflows/claude-auto-fix.yml`) spawns a Claude Code session that reads the issue, makes a surgical fix, and opens a draft PR.

To enable the auto-fix loop:

1. Add `ANTHROPIC_API_KEY` to *GitHub repo → Settings → Secrets and variables → Actions* (same key as above).
2. Install the GitHub App referenced by the action (run `claude /install-github-app` once if you haven't, or follow the action's setup docs).
3. That's it. Add the `auto-fix` label to a triaged issue and watch the PR appear.

You stay in the loop: the PRs are draft, so nothing merges without you reviewing on your phone.

## File layout

```
apps/text-art-library/
├── index.html            # page structure
├── style.css             # main styles
├── art.js                # global const ART = [...] — bundled source of truth
├── app.js                # all client-side JS (auto-detects backend)
├── tweaks-panel.jsx      # Tweaks panel React shell + form controls
├── README.md
│
├── netlify.toml          # Netlify build config
├── package.json          # @netlify/blobs dependency
├── netlify/functions/    # Netlify Functions backend
│   ├── auth.js
│   ├── get-art.js
│   ├── save-art.js
│   ├── get-flags.js
│   └── save-flags.js
│
├── wrangler.toml         # Cloudflare Pages config
└── functions/api/        # Cloudflare Pages Functions backend (parallel)
    ├── auth.js
    ├── get-art.js
    ├── save-art.js
    ├── get-flags.js
    └── save-flags.js
```

You can ship with either or both backends in the folder — the client picks whichever responds.

## How the data layer works

- **`art.js`** is the bundled source of truth. Always committed.
- **Backend store** holds runtime state under these keys:
  - `art` — user-created pieces added through the editor
  - `deletedIds` — IDs of bundled pieces the editor removed
  - `flag/<id>` — per-piece flag note (one key per flagged piece)
  - Netlify uses Blobs, Cloudflare uses KV — same semantics.
- On load, the client merges: bundle → filter by deletedIds → overlay `wosVerified` from store → append user-created.
- When you've accumulated user-created pieces, the editor can hit **⬇ Download updated art.js**, commit that, then clear the store (or just leave it — still valid).

## Editor mode

- There is no lock button anywhere in the chrome.
- Tap the **snowflake icon** in the header **7 times within 3 seconds** to open the auth modal.
- Editor mode lasts until the tab is closed or refreshed.

## WoS rules (cheat-sheet)

Whiteout Survival chat renders in a CJK-aware proportional font. The art audit uses two width thresholds:

- **Soft warn (⚠)** at **27 graphemes** — wide characters (emoji, fullwidth, box-drawing) may clip past this.
- **Hard warn (⛔)** at **58 graphemes** — narrow ASCII-only art can fit up to here, anything beyond will definitely break.

The audit also flags:
- regular spaces (auto-converted to NBSP on save)
- Unicode outside known-safe ranges

Safe character families:
- Pure emoji rows
- Block + box-drawing (`█ ▓ ▒ ░ ─ │ ┌ ┐ └ ┘ ╔ ╗ ╚ ╝ ═ ║`)
- Fullwidth chars where empty cells use `　` (U+3000)

Avoid ASCII `/ \ - | # * +` for shape-building — they're proportional and will drift.
