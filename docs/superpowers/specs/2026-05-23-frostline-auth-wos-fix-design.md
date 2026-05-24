# Frostline — Auth + WoS Fix Design
**Date:** 2026-05-23
**Status:** Awaiting user approval

---

## Overview

Two independent improvements to the Frostline text art gallery at `frostline-art.netlify.app`:

1. **Editor auth + global persistence** — password-gated edit mode for the wife, changes commit directly to GitHub and deploy globally via Netlify
2. **WoS chat compatibility** — fix preview font, pre-flag high-risk pieces, add community flag + tested-badge system

---

## Feature 1: Auth + Global Persistence

### How it works

A lock icon (🔒) sits in the header. Tapping it opens a password prompt. On correct entry:
- Edit buttons (✎ 🗑 + Add) appear on all cards
- The lock icon changes to 🔓
- The session stays unlocked until the tab is closed

### Save flow

When she saves an edit or new piece:
1. JS calls the GitHub Contents API directly (`PUT /repos/CovertCloak06/divine-workspace/contents/apps/text-art-library/art.js`)
2. Commits the updated `art.js` to master
3. Netlify auto-deploys — live for everyone in ~30 seconds
4. No backend server required

### Security

A GitHub Personal Access Token (PAT) with `contents:write` scope scoped to only the `divine-workspace` repo is generated once and **encrypted with AES-GCM using her password as the key** via the browser's Web Crypto API. The encrypted token is embedded in `index.html`. It never exists in plain text in source code.

- **Worst-case exposure:** Someone with her password can commit to `art.js` in this one repo
- **Acceptable risk:** This is a personal art gallery, not a financial system

### Password reset

No self-service reset. If she forgets: user tells owner → owner tells Claude → Claude re-encrypts token with new password and pushes. ~2 minutes.

### Delete behavior

Delete is editor-only (behind the password gate). Deleting a built-in piece removes it from `art.js` permanently via GitHub API commit. No localStorage overlay needed — the source of truth is the repo.

---

## Feature 2: WoS Chat Compatibility

### Problem

- WoS chat uses a **proportional font** — spacing-sensitive art made with regular text characters misaligns
- Some Unicode ranges are not in WoS's embedded font — those characters show as blank/missing

### Fix A: Preview font

Change the card preview and modal preview `font-family` from monospace (`Menlo/Consolas`) to a proportional system font (`system-ui, -apple-system, "Segoe UI", Roboto`). What she sees in Frostline now matches what WoS renders.

### Fix B: Pre-flag high-risk pieces

The following pieces in `art.js` use characters from Unicode ranges confirmed absent or unreliable in WoS chat and will be **pre-flagged ⚠️** on first load:

| Piece ID | Problem characters | Unicode range |
|---|---|---|
| `aes-tiny-flowers` | `𓇢𓆸` | Egyptian Hieroglyphs (U+13000+) |
| `gothic-skull` | `𓆩𓆪` | Egyptian Hieroglyphs |
| `gothic-fang` | `𓆩𓆪` | Egyptian Hieroglyphs |
| `aes-flourish` | `𓊝𓂁` | Egyptian Hieroglyphs |
| `aes-double-frame` | Mixed spacing decorative | Alignment risk |
| `comm-fcku-bunny` | `ᶠᶜᵏᵧₒᵤ` | Modifier Letters (U+1D00+) |
| `kao-stars-eyes` | `(☆▽☆)` | Needs WoS test |
| `comm-cats-hugging` | `ｎｏ` fullwidth | Fullwidth Latin (needs test) |

These are flagged, not deleted — the wife confirms in-game and we fix or remove per her feedback.

### Fix C: Flag system

**Any visitor** can flag a piece. **Editor** sees flagged pieces highlighted and can filter to "Flagged only."

**Flag data storage:**
- Regular visitors: flag stored in localStorage (per-device)  
- Editor view: flags stored in a small `flags.json` file in the repo, read via GitHub API. This gives her a global view of what the alliance has flagged across all devices.

**Flag UI:**
- 🚩 button on every card (always visible)
- Flagged cards show red ⚠️ badge
- "Flagged (N)" filter tab in the tag bar (editor-only)

### Fix D: WoS Tested badge

Editor can mark a piece as **✅ WoS Tested** after confirming it works in-game. This status is stored in `art.js` as a `wosVerified: true` field and shows as a small green checkmark on the card.

---

## Data Model Changes

```js
// art.js piece shape — new optional fields
{
  id: 'heart-small',
  title: 'Heart (small)',
  tags: ['love', 'symbols'],
  width: 7, height: 6,
  art: `...`,
  wosVerified: true,   // optional — editor-toggled
  wosRisk: true,       // optional — pre-flagged high-risk pieces
}
```

`flags.json` (new file in repo, editor-managed):
```json
{ "flagged": ["aes-tiny-flowers", "gothic-skull", "comm-fcku-bunny"] }
```

---

## Files Changed

| File | Change |
|---|---|
| `apps/text-art-library/index.html` | Auth UI, lock icon, flag buttons, tested badges, proportional preview font, GitHub API calls |
| `apps/text-art-library/art.js` | Add `wosRisk: true` to high-risk pieces, `wosVerified: true` to safe ones |
| `apps/text-art-library/flags.json` | New file — global flag state |

---

## Out of Scope

- Multi-user auth (only one editor: the wife)
- Comment system
- Versioning/undo history for edits
- Mobile-specific UI changes beyond what already works
