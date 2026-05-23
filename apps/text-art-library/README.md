# Frostline — Text Art Library

A static webpage hosting hand-curated text art for pasting into Whiteout Survival
chat (and other proportional-font apps).

**Live URL (after enabling GitHub Pages):**
`https://covertcloak06.github.io/divine-workspace/apps/text-art-library/`

## Local preview

```bash
cd apps/text-art-library
python3 -m http.server 8080
# open http://localhost:8080
```

Or just double-click `index.html` (works fully offline — clipboard included).

## Enable GitHub Pages (one-time)

```bash
# Pick ONE branch+path to serve from. Simplest: main branch, root.
gh api -X POST repos/CovertCloak06/divine-workspace/pages \
  -f source[branch]=main -f source[path]=/
```

Or via the web UI: **Repo Settings → Pages → Source: Deploy from a branch → main → / (root)**.

After Pages builds (usually <1 min), the library is live at the URL above.

## Adding new art

Edit `art.js`. Copy an existing entry, change the fields:

```js
{
  id: 'my-piece',                 // unique kebab-case
  title: 'My Piece',              // display name
  tags: ['love', 'banners'],      // pick from: love, nature, banners,
                                  // decorative, animals, borders,
                                  // celebration, symbols
  width: 13, height: 3,           // shown as a size badge
  art: `line 1
line 2
line 3`,
}
```

## Character compatibility rules

Whiteout's chat font is **proportional**, so ASCII chars (`#*+/\|-`) misalign.
Pick ONE character family per piece:

| Family | Examples | Notes |
|---|---|---|
| **Pure emoji** | `❤️💛💚` | Most reliable. Each emoji is consistent width. **Don't mix** with non-emoji in the same row. |
| **Block + box-drawing** | `█ ▓ ░ ╔ ═ ║ ─ │` | Works well in monospace; usually aligned in proportional fonts too. |
| **Single decorative line** | `✦ ━━━━ ✦` | Forgiving — small alignment errors are invisible. |

## Submit-your-own (planned)

Footer link opens a pre-filled GitHub issue. User pastes their art + tags, we
review and merge.
