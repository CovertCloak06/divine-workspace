# Frostline — Text Art Library

Curated text art for one Whiteout Survival alliance. Tap, copy, paste into chat.

## Local preview

This app runs **in this preview** without any backend — it falls back to `localStorage` when the Netlify Functions aren't reachable. The dev fallback password is `0022`.

To open the live preview, just view `index.html`.

## Deploy to Netlify

This folder is designed to drop into `apps/text-art-library/` inside a Netlify-hosted repo (e.g. `CovertCloak06/divine-workspace`). Netlify auto-detects `netlify.toml`.

1. **Install function dependencies** once:
   ```sh
   cd apps/text-art-library
   npm install
   ```
2. **Set the editor password** in the Netlify dashboard:
   *Site config → Environment variables → Functions scope*
   - `EDITOR_PASSWORD` = your chosen password
3. **Push to GitHub.** Netlify will auto-build and deploy.

## File layout

```
apps/text-art-library/
├── index.html            # page structure
├── style.css             # main styles
├── draw-mode.css         # draw-mode-specific styles
├── art.js                # global const ART = [...] — source of truth
├── app.js                # all client-side JS
├── netlify.toml          # build config
├── package.json          # @netlify/blobs dependency for functions
├── README.md             # this file
└── netlify/functions/
    ├── auth.js
    ├── get-art.js
    ├── save-art.js
    ├── get-flags.js
    └── save-flags.js
```

## How the data layer works

- **`art.js`** is the bundled source of truth. Always committed.
- **Netlify Blobs (`frostline` store)** holds runtime state:
  - `art` — user-created pieces added through the editor
  - `deletedIds` — IDs of bundled pieces the editor removed
  - `flag/<id>` — per-piece flag note (one key per flagged piece)
- On load, the client merges all three: bundle → filter by deletedIds → overlay `wosVerified` from Blob → append user-created.
- When you've accumulated user-created pieces in Blobs, the editor can hit **⬇ Download updated art.js**, commit that, then clear Blobs (or just leave them — they're still valid).

## Editor mode

- There is no lock button anywhere in the chrome.
- Tap the **snowflake icon** in the header **7 times within 3 seconds** to open the auth modal.
- Editor mode lasts until the tab is closed or refreshed.

## WoS rules (cheat-sheet)

Whiteout Survival chat renders in a **proportional font** with a soft **27-character width limit**. The art audit warns when:
- art contains regular spaces (auto-converted to NBSP on save)
- any line exceeds 27 graphemes (size badge turns orange + ⚠)
- art contains Unicode outside the known-safe ranges

Safe character families:
- Pure emoji rows
- Block + box-drawing (`█ ▓ ▒ ░ ─ │ ┌ ┐ └ ┘ ╔ ╗ ╚ ╝ ═ ║`)
- Fullwidth chars where empty cells use `　` (U+3000)

Avoid ASCII `/ \ - | # * +` — variable width in proportional fonts.
