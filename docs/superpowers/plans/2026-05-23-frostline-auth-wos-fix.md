# Frostline Auth + WoS Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add password-gated editor mode with instant global saves via Netlify Functions + Blob storage, WoS compatibility flags, and proportional font preview.

**Architecture:** Five Netlify Functions handle auth validation, art read/write, and flag read/write against Netlify Blob storage. The client JS is extracted from index.html into app.js. Art loads from Blob on startup (falls back to bundled ART). Editor saves push full art array to Blob instantly — no GitHub commit delay.

**Tech Stack:** Netlify Functions (CommonJS Node 18), @netlify/blobs, vanilla JS, HTML/CSS

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `apps/text-art-library/netlify.toml` | Create | Build config + functions directory |
| `apps/text-art-library/netlify/functions/auth.js` | Create | Validate editor password |
| `apps/text-art-library/netlify/functions/get-art.js` | Create | Read art array from Blob |
| `apps/text-art-library/netlify/functions/save-art.js` | Create | Write art array to Blob (auth required) |
| `apps/text-art-library/netlify/functions/get-flags.js` | Create | Read flags array from Blob |
| `apps/text-art-library/netlify/functions/save-flags.js` | Create | Toggle flag in Blob (no auth) |
| `apps/text-art-library/app.js` | Create | All application JS (extracted from index.html) |
| `apps/text-art-library/index.html` | Modify | Remove inline JS, add auth/flag/badge HTML+CSS, reference app.js |
| `apps/text-art-library/art.js` | Modify | Add `wosRisk: true` to 8 high-risk pieces |

---

## Task 1: netlify.toml

**Files:**
- Create: `apps/text-art-library/netlify.toml`

- [ ] **Create netlify.toml**

```toml
[build]
  publish = "."
  functions = "netlify/functions"

[functions]
  node_bundler = "esbuild"
```

- [ ] **Commit**

```bash
cd /home/gh0st/dvn/divine-workspace
git add apps/text-art-library/netlify.toml
git commit -m "Frostline: add netlify.toml with functions config"
git push origin master
```

---

## Task 2: auth.js — password validation endpoint

**Files:**
- Create: `apps/text-art-library/netlify/functions/auth.js`

- [ ] **Create the functions directory and auth.js**

```js
// netlify/functions/auth.js
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Content-Type': 'application/json',
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: CORS, body: '' }
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers: CORS, body: 'Method not allowed' }

  const password = (event.headers.authorization || '').replace('Bearer ', '').trim()
  const expected = process.env.EDITOR_PASSWORD

  if (!expected) return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: 'EDITOR_PASSWORD not set' }) }
  if (password !== expected) return { statusCode: 401, headers: CORS, body: JSON.stringify({ error: 'Wrong password' }) }

  return { statusCode: 200, headers: CORS, body: JSON.stringify({ ok: true }) }
}
```

- [ ] **Commit**

```bash
git add apps/text-art-library/netlify/functions/auth.js
git commit -m "Frostline: add auth function"
git push origin master
```

---

## Task 3: get-art.js + save-art.js

**Files:**
- Create: `apps/text-art-library/netlify/functions/get-art.js`
- Create: `apps/text-art-library/netlify/functions/save-art.js`

- [ ] **Create get-art.js**

```js
// netlify/functions/get-art.js
const { getStore } = require('@netlify/blobs')

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Content-Type': 'application/json',
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: CORS, body: '' }
  if (event.httpMethod !== 'GET') return { statusCode: 405, headers: CORS, body: 'Method not allowed' }

  try {
    const store = getStore('frostline')
    const art = await store.get('art', { type: 'json' })
    if (!art) return { statusCode: 404, headers: CORS, body: JSON.stringify({ art: null }) }
    return { statusCode: 200, headers: CORS, body: JSON.stringify({ art }) }
  } catch (err) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: err.message }) }
  }
}
```

- [ ] **Create save-art.js**

```js
// netlify/functions/save-art.js
const { getStore } = require('@netlify/blobs')

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Content-Type': 'application/json',
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: CORS, body: '' }
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers: CORS, body: 'Method not allowed' }

  const password = (event.headers.authorization || '').replace('Bearer ', '').trim()
  if (password !== process.env.EDITOR_PASSWORD) {
    return { statusCode: 401, headers: CORS, body: JSON.stringify({ error: 'Unauthorized' }) }
  }

  try {
    const { art } = JSON.parse(event.body)
    if (!Array.isArray(art)) return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'art must be array' }) }
    const store = getStore('frostline')
    await store.setJSON('art', art)
    return { statusCode: 200, headers: CORS, body: JSON.stringify({ ok: true }) }
  } catch (err) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: err.message }) }
  }
}
```

- [ ] **Commit**

```bash
git add apps/text-art-library/netlify/functions/get-art.js apps/text-art-library/netlify/functions/save-art.js
git commit -m "Frostline: add get-art and save-art functions"
git push origin master
```

---

## Task 4: get-flags.js + save-flags.js

**Files:**
- Create: `apps/text-art-library/netlify/functions/get-flags.js`
- Create: `apps/text-art-library/netlify/functions/save-flags.js`

- [ ] **Create get-flags.js**

```js
// netlify/functions/get-flags.js
const { getStore } = require('@netlify/blobs')

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Content-Type': 'application/json',
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: CORS, body: '' }
  if (event.httpMethod !== 'GET') return { statusCode: 405, headers: CORS, body: 'Method not allowed' }

  try {
    const store = getStore('frostline')
    const flags = await store.get('flags', { type: 'json' })
    return { statusCode: 200, headers: CORS, body: JSON.stringify({ flags: flags || [] }) }
  } catch (err) {
    return { statusCode: 200, headers: CORS, body: JSON.stringify({ flags: [] }) }
  }
}
```

- [ ] **Create save-flags.js — anyone can flag, no auth**

```js
// netlify/functions/save-flags.js
const { getStore } = require('@netlify/blobs')

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Content-Type': 'application/json',
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: CORS, body: '' }
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers: CORS, body: 'Method not allowed' }

  try {
    const { id } = JSON.parse(event.body)
    if (!id || typeof id !== 'string') return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'id required' }) }

    const store = getStore('frostline')
    const flags = (await store.get('flags', { type: 'json' })) || []

    const idx = flags.indexOf(id)
    if (idx >= 0) flags.splice(idx, 1)
    else flags.push(id)

    await store.setJSON('flags', flags)
    return { statusCode: 200, headers: CORS, body: JSON.stringify({ flags }) }
  } catch (err) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: err.message }) }
  }
}
```

- [ ] **Commit**

```bash
git add apps/text-art-library/netlify/functions/get-flags.js apps/text-art-library/netlify/functions/save-flags.js
git commit -m "Frostline: add get-flags and save-flags functions"
git push origin master
```

---

## Task 5: Set EDITOR_PASSWORD in Netlify dashboard

**This is a manual step — cannot be done via code.**

- [ ] **Go to Netlify dashboard**

Navigate to: `app.netlify.com` → select `frostline-art` site → **Site configuration** → **Environment variables** → **Add a variable**

- Key: `EDITOR_PASSWORD`
- Value: choose a strong password (write it down — no self-service reset)
- Scope: **Functions**

Click **Save**.

- [ ] **Trigger a redeploy so the env var takes effect**

In Netlify dashboard: **Deploys** → **Trigger deploy** → **Deploy site**

Wait for deploy to complete (green checkmark).

- [ ] **Verify auth function works**

```bash
curl -s -X POST https://frostline-art.netlify.app/.netlify/functions/auth \
  -H "Authorization: Bearer YOURPASSWORD"
# Expected: {"ok":true}

curl -s -X POST https://frostline-art.netlify.app/.netlify/functions/auth \
  -H "Authorization: Bearer wrongpassword"
# Expected: {"error":"Wrong password"} with HTTP 401
```

---

## Task 6: Extract JS to app.js + wire API art loading

**Files:**
- Create: `apps/text-art-library/app.js`
- Modify: `apps/text-art-library/index.html`

- [ ] **Create app.js with state, API layer, and art loading**

```js
// app.js
// ── Constants ──────────────────────────────────────────────────────────────
const TAGS = ['all','love','nature','animals','banners','borders','decorative',
  'celebration','symbols','aesthetic','kawaii','gothic','memes','sayings',
  'minimalist','nsfw']
const STORAGE_KEY = 'frostline.userdata.v1'
const API = {
  getArt:   '/.netlify/functions/get-art',
  saveArt:  '/.netlify/functions/save-art',
  getFlags: '/.netlify/functions/get-flags',
  saveFlags:'/.netlify/functions/save-flags',
  auth:     '/.netlify/functions/auth',
}

// ── State ──────────────────────────────────────────────────────────────────
const state = { activeTag: 'all', search: '', showFlagged: false }
const authState = { unlocked: false, password: '' }
let artData = []      // loaded from Blob, fallback to bundled ART
let globalFlags = []  // loaded from Blob

// ── Grapheme utils ─────────────────────────────────────────────────────────
const segmenter = (typeof Intl !== 'undefined' && Intl.Segmenter)
  ? new Intl.Segmenter(undefined, { granularity: 'grapheme' }) : null
function graphemeCount(s) {
  return segmenter ? [...segmenter.segment(s)].length : s.length
}
function autoDimensions(art) {
  const lines = art.split('\n')
  return { width: Math.max(1, ...lines.map(l => graphemeCount(l))), height: lines.length }
}

// ── API layer ──────────────────────────────────────────────────────────────
async function apiFetch(url, opts = {}) {
  try {
    const res = await fetch(url, opts)
    return { ok: res.ok, status: res.status, data: await res.json().catch(() => null) }
  } catch (e) {
    return { ok: false, status: 0, data: null }
  }
}

async function loadArt() {
  const { ok, data } = await apiFetch(API.getArt)
  artData = (ok && Array.isArray(data?.art)) ? data.art : [...ART]
}

async function loadFlags() {
  const { ok, data } = await apiFetch(API.getFlags)
  globalFlags = (ok && Array.isArray(data?.flags)) ? data.flags : []
}

async function saveArt() {
  return apiFetch(API.saveArt, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${authState.password}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ art: artData }),
  })
}

async function saveFlag(id) {
  const { ok, data } = await apiFetch(API.saveFlags, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id }),
  })
  if (ok && Array.isArray(data?.flags)) globalFlags = data.flags
  return ok
}

// ── Auth ───────────────────────────────────────────────────────────────────
const $authModal   = document.getElementById('auth-modal')
const $authInput   = document.getElementById('auth-password')
const $authError   = document.getElementById('auth-error')
const $lockBtn     = document.getElementById('lock-btn')

function openAuthModal() {
  $authInput.value = ''
  $authError.textContent = ''
  $authModal.classList.add('open')
  setTimeout(() => $authInput.focus(), 50)
}
function closeAuthModal() { $authModal.classList.remove('open') }

async function attemptUnlock() {
  const pw = $authInput.value.trim()
  if (!pw) return
  $authError.textContent = 'Checking…'
  const { ok } = await apiFetch(API.auth, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${pw}` },
  })
  if (ok) {
    authState.unlocked = true
    authState.password = pw
    $lockBtn.textContent = '🔓'
    closeAuthModal()
    renderTags()
    renderGrid()
  } else {
    $authError.textContent = 'Wrong password'
    $authInput.select()
  }
}

$lockBtn.onclick = () => authState.unlocked ? (() => {
  authState.unlocked = false; authState.password = ''
  $lockBtn.textContent = '🔒'; renderTags(); renderGrid()
})() : openAuthModal()

document.getElementById('auth-submit').onclick = attemptUnlock
$authInput.addEventListener('keydown', e => { if (e.key === 'Enter') attemptUnlock() })
document.getElementById('auth-modal-close').onclick = closeAuthModal
$authModal.addEventListener('click', e => { if (e.target === $authModal) closeAuthModal() })
```

- [ ] **Commit (partial — rest of app.js follows in next tasks)**

Hold commit until Task 7 is done to avoid a broken intermediate state.

---

## Task 7: Auth UI in index.html + password modal HTML/CSS

**Files:**
- Modify: `apps/text-art-library/index.html`

- [ ] **Add CSS for auth, flags, and WoS badges to the `<style>` block** (insert before the closing `</style>`)

```css
  /* ── Auth ── */
  header { position: relative; }
  .lock-btn {
    position: absolute; right: 20px; top: 50%; transform: translateY(-50%);
    background: none; border: none; font-size: 22px; cursor: pointer;
    color: var(--ink-dim); line-height: 1;
  }
  .lock-btn:hover { color: var(--accent); }

  /* ── Flag button ── */
  .flag-btn {
    width: 28px; height: 28px; border-radius: 6px;
    border: 1px solid var(--border); background: var(--bg);
    color: var(--ink-dim); cursor: pointer; display: flex;
    align-items: center; justify-content: center; font-size: 13px; padding: 0;
  }
  .flag-btn:hover { color: #fbbf24; border-color: #fbbf24; }
  .flag-btn.flagged { color: #ef4444; border-color: #ef4444; }

  /* ── WoS badges ── */
  .wos-badge {
    font-size: 10px; padding: 1px 5px; border-radius: 4px;
    font-weight: 600; flex-shrink: 0; cursor: default;
  }
  .wos-verified { background: var(--good); color: #0b1020; }
  .wos-risk { background: #fbbf24; color: #0b1020; }
  .wos-verified.editor-toggle, .wos-risk.editor-toggle { cursor: pointer; }

  /* ── Auth modal ── */
  .auth-form { display: flex; flex-direction: column; gap: 12px; }
  .auth-form input {
    width: 100%; padding: 10px 12px; background: var(--bg);
    border: 1px solid var(--border); color: var(--ink);
    border-radius: 8px; font-size: 15px; outline: none; box-sizing: border-box;
  }
  .auth-form input:focus { border-color: var(--accent); }
  .auth-error { color: var(--bad); font-size: 13px; min-height: 18px; }
  .auth-submit {
    padding: 10px; background: var(--accent); color: #0b1020;
    border: none; border-radius: 8px; font-weight: 700; font-size: 15px; cursor: pointer;
  }
  .auth-submit:hover { background: var(--accent-press); }
```

- [ ] **Add lock button to `<header>` and auth modal HTML** (after the share-bar div, before `</header>`)

```html
  <button class="lock-btn" id="lock-btn" title="Editor login">🔒</button>
</header>

<div class="modal-backdrop" id="auth-modal" role="dialog" aria-modal="true">
  <div class="modal" style="max-width:400px">
    <div class="modal-head">
      <h2 class="modal-title">Editor Login</h2>
      <button class="modal-close" id="auth-modal-close" aria-label="Close">✕</button>
    </div>
    <div class="auth-form">
      <input id="auth-password" type="password" placeholder="Password" autocomplete="current-password" />
      <div class="auth-error" id="auth-error"></div>
      <button class="auth-submit" id="auth-submit">Unlock</button>
    </div>
  </div>
</div>
```

- [ ] **Replace `<script src="art.js"></script>` and the inline `<script>` block at the bottom of index.html with:**

```html
<script src="art.js"></script>
<script src="app.js"></script>
```

All JS now lives in app.js.

---

## Task 8: Flag system in app.js

**Files:**
- Modify: `apps/text-art-library/app.js`

- [ ] **Add flag helpers and updated renderGrid to app.js**

Append to app.js:

```js
// ── Flag helpers ───────────────────────────────────────────────────────────
function isFlagged(id) { return globalFlags.includes(id) }

async function toggleFlag(id, btn) {
  btn.disabled = true
  const ok = await saveFlag(id)
  if (ok) {
    btn.classList.toggle('flagged', isFlagged(id))
    renderTags() // update flagged count in tab
  }
  btn.disabled = false
}

// ── Clipboard ──────────────────────────────────────────────────────────────
function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent
    btn.textContent = '✓ Copied!'
    btn.classList.add('copied')
    setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied') }, 1500)
  }).catch(() => { btn.textContent = '✗ Copy failed' })
}

// ── Tags ───────────────────────────────────────────────────────────────────
const $tags   = document.getElementById('tags')
const $grid   = document.getElementById('grid')
const $search = document.getElementById('search')

function renderTags() {
  $tags.innerHTML = ''
  const tagList = [...TAGS]
  if (authState.unlocked && globalFlags.length > 0) tagList.push(`flagged (${globalFlags.length})`)
  for (const t of tagList) {
    const el = document.createElement('div')
    const isActive = state.activeTag === t || (t.startsWith('flagged') && state.showFlagged)
    el.className = 'tag' + (isActive ? ' active' : '')
    el.textContent = t
    el.onclick = () => {
      if (t.startsWith('flagged')) {
        state.showFlagged = !state.showFlagged
        state.activeTag = 'all'
      } else {
        state.activeTag = t
        state.showFlagged = false
      }
      renderTags()
      renderGrid()
    }
    $tags.appendChild(el)
  }
}

// ── Visibility ─────────────────────────────────────────────────────────────
function visible(piece) {
  if (state.showFlagged) return isFlagged(piece.id)
  if (state.activeTag !== 'all' && !piece.tags.includes(state.activeTag)) return false
  if (state.search) {
    const q = state.search.toLowerCase()
    if (!(piece.title + ' ' + piece.tags.join(' ')).toLowerCase().includes(q)) return false
  }
  return true
}

// ── WoS badge ──────────────────────────────────────────────────────────────
function makeBadge(piece) {
  if (piece.wosVerified) {
    const b = document.createElement('span')
    b.className = 'wos-badge wos-verified' + (authState.unlocked ? ' editor-toggle' : '')
    b.textContent = '✅ WoS'
    b.title = authState.unlocked ? 'Click to un-verify' : 'Verified works in WoS chat'
    if (authState.unlocked) b.onclick = (e) => { e.stopPropagation(); toggleWosBadge(piece, 'verified') }
    return b
  }
  if (piece.wosRisk) {
    const b = document.createElement('span')
    b.className = 'wos-badge wos-risk' + (authState.unlocked ? ' editor-toggle' : '')
    b.textContent = '⚠️ WoS?'
    b.title = authState.unlocked ? 'Click to mark verified' : 'May not render in WoS chat'
    if (authState.unlocked) b.onclick = (e) => { e.stopPropagation(); toggleWosBadge(piece, 'risk') }
    return b
  }
  if (authState.unlocked) {
    const b = document.createElement('span')
    b.className = 'wos-badge wos-risk editor-toggle'
    b.textContent = '+ WoS'
    b.title = 'Mark as verified in WoS chat'
    b.onclick = (e) => { e.stopPropagation(); toggleWosBadge(piece, 'none') }
    return b
  }
  return null
}

async function toggleWosBadge(piece, current) {
  const idx = artData.findIndex(p => p.id === piece.id)
  if (idx < 0) return
  if (current === 'verified') {
    delete artData[idx].wosVerified
  } else {
    artData[idx].wosVerified = true
    delete artData[idx].wosRisk
  }
  const { ok } = await saveArt()
  if (ok) renderGrid()
  else alert('Save failed — check your connection')
}

// ── Render grid ────────────────────────────────────────────────────────────
function renderGrid() {
  $grid.innerHTML = ''

  if (authState.unlocked) {
    const addRow = document.createElement('div')
    addRow.className = 'add-card-row'
    const addBtn = document.createElement('button')
    addBtn.className = 'add-btn'
    addBtn.textContent = '+ Add New Art'
    addBtn.onclick = () => openEditModal(null)
    addRow.appendChild(addBtn)
    $grid.appendChild(addRow)
  }

  const filtered = artData.filter(visible)
  if (filtered.length === 0) {
    const empty = document.createElement('div')
    empty.className = 'empty'
    empty.textContent = 'No art matches that filter.'
    $grid.appendChild(empty)
    return
  }

  for (const piece of filtered) {
    const card = document.createElement('article')
    card.className = 'card'
    card.innerHTML = `
      <div class="card-head">
        <h3 class="card-title"></h3>
        <span class="card-size"></span>
        <div class="card-actions"></div>
      </div>
      <div class="preview"><pre></pre></div>
      <div class="card-tags"></div>
      <button class="copy-btn">📋 Copy</button>
    `
    card.querySelector('.card-title').textContent = piece.title
    card.querySelector('.card-size').textContent = `${piece.width}×${piece.height}`
    card.querySelector('.preview pre').textContent = piece.art

    const tagBox = card.querySelector('.card-tags')
    for (const t of piece.tags) {
      const tEl = document.createElement('span')
      tEl.className = 'card-tag'
      tEl.textContent = t
      tagBox.appendChild(tEl)
    }

    const actions = card.querySelector('.card-actions')

    // WoS badge
    const badge = makeBadge(piece)
    if (badge) actions.appendChild(badge)

    // Flag button
    const flagBtn = document.createElement('button')
    flagBtn.className = 'flag-btn' + (isFlagged(piece.id) ? ' flagged' : '')
    flagBtn.title = isFlagged(piece.id) ? 'Unflag' : 'Flag for WoS review'
    flagBtn.textContent = '🚩'
    flagBtn.onclick = (e) => { e.stopPropagation(); toggleFlag(piece.id, flagBtn) }
    actions.appendChild(flagBtn)

    // Edit/delete (editor only)
    if (authState.unlocked) {
      const editBtn = document.createElement('button')
      editBtn.className = 'card-action edit-btn'
      editBtn.title = 'Edit'
      editBtn.textContent = '✎'
      editBtn.onclick = (e) => { e.stopPropagation(); openEditModal(piece) }
      actions.appendChild(editBtn)

      const delBtn = document.createElement('button')
      delBtn.className = 'card-action danger del-btn'
      delBtn.title = 'Delete'
      delBtn.textContent = '🗑'
      delBtn.onclick = (e) => { e.stopPropagation(); deletePiece(piece.id) }
      actions.appendChild(delBtn)
    }

    const btn = card.querySelector('.copy-btn')
    btn.onclick = (e) => { e.stopPropagation(); copyToClipboard(piece.art, btn) }
    card.onclick = () => openModal(piece)
    $grid.appendChild(card)
  }
  setTimeout(fitAllPreviews, 50)
}
```

---

## Task 9: Edit modal + delete + preview fit in app.js

**Files:**
- Modify: `apps/text-art-library/app.js`

- [ ] **Append edit modal, delete, and preview fit logic to app.js**

```js
// ── Delete ─────────────────────────────────────────────────────────────────
async function deletePiece(id) {
  if (!confirm('Delete this piece?')) return
  artData = artData.filter(p => p.id !== id)
  const { ok } = await saveArt()
  if (ok) renderGrid()
  else alert('Save failed — check your connection')
}

// ── Preview fit ────────────────────────────────────────────────────────────
function fitPreview(container, pre, opts = {}) {
  const padding  = opts.padding  ?? 24
  const maxH     = opts.maxHeight ?? 220
  const setHeight = opts.setHeight !== false
  pre.style.transform = 'none'
  const containerW = container.clientWidth - padding
  const naturalW   = pre.scrollWidth
  const naturalH   = pre.scrollHeight
  if (naturalW <= 0) return
  const scale = Math.min(1, containerW / naturalW, maxH / naturalH)
  pre.style.transform = `scale(${scale})`
  if (setHeight) container.style.height = Math.max(90, naturalH * scale) + 'px'
}

function fitAllPreviews() {
  document.querySelectorAll('.preview').forEach(prev => {
    const pre = prev.querySelector('pre')
    if (pre) fitPreview(prev, pre)
  })
  if ($modal.classList.contains('open')) fitModalPreview()
}

function fitModalPreview() {
  fitPreview($modalPreviewWrap, $modalPreview, {
    padding: 48,
    maxHeight: Math.min(window.innerHeight * 0.55, 520),
    setHeight: false,
  })
}

window.addEventListener('resize', () => requestAnimationFrame(fitAllPreviews))

// ── Edit modal ─────────────────────────────────────────────────────────────
const $editModal      = document.getElementById('edit-modal')
const $editModalTitle = document.getElementById('edit-modal-title')
const $editTitle      = document.getElementById('edit-title')
const $editTags       = document.getElementById('edit-tags')
const $editArt        = document.getElementById('edit-art')
let editTarget = null

function openEditModal(piece) {
  editTarget = piece
  if (piece) {
    $editModalTitle.textContent = `Edit: ${piece.title}`
    $editTitle.value = piece.title
    $editTags.value  = piece.tags.join(', ')
    $editArt.value   = piece.art
  } else {
    $editModalTitle.textContent = 'Add New Art'
    $editTitle.value = $editTags.value = $editArt.value = ''
  }
  $editModal.classList.add('open')
  setTimeout(() => $editTitle.focus(), 50)
}
function closeEditModal() { $editModal.classList.remove('open'); editTarget = null }

document.getElementById('edit-modal-close').onclick = closeEditModal
document.getElementById('edit-cancel').onclick = closeEditModal
$editModal.addEventListener('click', e => { if (e.target === $editModal) closeEditModal() })

document.getElementById('edit-save').onclick = async () => {
  const title = $editTitle.value.trim()
  const tags  = $editTags.value.split(',').map(t => t.trim()).filter(Boolean)
  const art   = $editArt.value
  if (!title) { alert('Title is required'); return }
  if (!art.trim()) { alert('Art is required'); return }
  const dim = autoDimensions(art)
  const payload = { title, tags, art, width: dim.width, height: dim.height }

  if (editTarget) {
    const idx = artData.findIndex(p => p.id === editTarget.id)
    if (idx >= 0) artData[idx] = { ...artData[idx], ...payload }
  } else {
    const id = 'user-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 6)
    artData.push({ id, ...payload })
  }

  const { ok } = await saveArt()
  if (ok) { closeEditModal(); renderGrid() }
  else alert('Save failed — check your connection')
}

// ── Lightbox modal ─────────────────────────────────────────────────────────
const $modal            = document.getElementById('modal')
const $modalTitle       = document.getElementById('modal-title')
const $modalPreviewWrap = document.getElementById('modal-preview-wrap')
const $modalPreview     = document.getElementById('modal-preview')
const $modalSize        = document.getElementById('modal-size')
const $modalTags        = document.getElementById('modal-tags')
const $modalCopy        = document.getElementById('modal-copy')

function openModal(piece) {
  $modalTitle.textContent  = piece.title
  $modalPreview.textContent = piece.art
  $modalSize.textContent   = `${piece.width} × ${piece.height}`
  $modalTags.innerHTML = ''
  for (const t of piece.tags) {
    const tEl = document.createElement('span')
    tEl.className = 'card-tag'
    tEl.textContent = t
    $modalTags.appendChild(tEl)
  }
  $modalCopy.textContent = '📋 Copy to Clipboard'
  $modalCopy.classList.remove('copied')
  $modalCopy.onclick = () => copyToClipboard(piece.art, $modalCopy)
  $modal.classList.add('open')
  requestAnimationFrame(fitModalPreview)
}
function closeModal() { $modal.classList.remove('open') }
document.getElementById('modal-close').onclick = closeModal
$modal.addEventListener('click', e => { if (e.target === $modal) closeModal() })
document.addEventListener('keydown', e => { if (e.key === 'Escape') { closeModal(); closeAuthModal() } })

// ── Search ─────────────────────────────────────────────────────────────────
$search.addEventListener('input', e => { state.search = e.target.value; renderGrid() })

// ── Export ─────────────────────────────────────────────────────────────────
document.getElementById('export-btn').onclick = () => {
  const escape = s => s.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$\{/g, '\\${')
  const entries = artData.map(p =>
`  {
    id: '${p.id.replace(/'/g, "\\'")}',
    title: ${JSON.stringify(p.title)},
    tags: ${JSON.stringify(p.tags)},
    width: ${p.width}, height: ${p.height},${p.wosVerified ? '\n    wosVerified: true,' : ''}${p.wosRisk ? '\n    wosRisk: true,' : ''}
    art: \`${escape(p.art)}\`
  }`).join(',\n')
  const out = `// Frostline art library — exported ${new Date().toISOString()}\nconst ART = [\n${entries}\n];\n`
  const blob = new Blob([out], { type: 'text/javascript' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = 'art.js'
  document.body.appendChild(a); a.click()
  document.body.removeChild(a); URL.revokeObjectURL(url)
}

// ── Share bar ──────────────────────────────────────────────────────────────
document.getElementById('share-bar').onclick = () => {
  const url = 'https://frostline-art.netlify.app'
  const label = document.getElementById('share-label')
  navigator.clipboard.writeText(url).then(() => {
    label.textContent = '✓ Copied!'
    setTimeout(() => { label.textContent = 'Copy link' }, 2000)
  })
}

// ── Init ───────────────────────────────────────────────────────────────────
async function initApp() {
  await Promise.all([loadArt(), loadFlags()])
  renderTags()
  renderGrid()
}

initApp()
```

- [ ] **Commit app.js**

```bash
git add apps/text-art-library/app.js
git commit -m "Frostline: add app.js with auth, flags, WoS badges, API layer"
git push origin master
```

---

## Task 10: Update index.html — proportional font + remove inline JS

**Files:**
- Modify: `apps/text-art-library/index.html`

- [ ] **Change preview font from monospace to proportional in the `<style>` block**

Find and replace both `.preview pre` and `.modal-preview pre` font-family:

```css
/* BEFORE */
font-family: "Menlo", "Consolas", "Liberation Mono", monospace;

/* AFTER — in both .preview pre and .modal-preview pre */
font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
```

Also remove the monospace font from `.edit-form textarea` — keep that one as monospace since it's a code editor, not a preview.

- [ ] **Remove the entire `<script>` inline block** (everything between `<script src="art.js"></script>` and `</body>`) and replace with:

```html
<script src="art.js"></script>
<script src="app.js"></script>
```

- [ ] **Commit**

```bash
git add apps/text-art-library/index.html
git commit -m "Frostline: proportional preview font + wire app.js"
git push origin master
```

---

## Task 11: Update art.js — add wosRisk fields

**Files:**
- Modify: `apps/text-art-library/art.js`

- [ ] **Add `wosRisk: true` to the 8 high-risk pieces**

Find each piece by ID and add `wosRisk: true` after the `height:` field:

| ID | Characters to find for context |
|---|---|
| `aes-tiny-flowers` | `𓇢𓆸` |
| `gothic-skull` | `𓆩𓆪` |
| `gothic-fang` | `𓆩♱𓆪` |
| `aes-flourish` | `𓊝𓂁` |
| `aes-double-frame` | `·:·.✧` |
| `comm-fcku-bunny` | `ᶠᶜᵏᵧₒᵤ` |
| `kao-stars-eyes` | `☆▽☆` |
| `comm-cats-hugging` | fullwidth `ｎｏ` |

Example change for `aes-tiny-flowers`:

```js
// BEFORE
  {
    id: 'aes-tiny-flowers',
    title: 'Tiny Flowers',
    tags: ['aesthetic', 'minimalist'],
    width: 12, height: 1,
    art: `𓇢𓆸 ⋆｡˚ 𓇢𓆸`,
  },

// AFTER
  {
    id: 'aes-tiny-flowers',
    title: 'Tiny Flowers',
    tags: ['aesthetic', 'minimalist'],
    width: 12, height: 1,
    wosRisk: true,
    art: `𓇢𓆸 ⋆｡˚ 𓇢𓆸`,
  },
```

Apply the same pattern to all 8 IDs listed above.

- [ ] **Commit**

```bash
git add apps/text-art-library/art.js
git commit -m "Frostline: flag 8 high-risk WoS pieces with wosRisk: true"
git push origin master
```

---

## Task 12: Verify full deployment

- [ ] **Check Netlify deploy succeeded**

Go to `app.netlify.com` → frostline-art → Deploys. Latest deploy should be green.

- [ ] **Test get-art returns art**

```bash
curl -s https://frostline-art.netlify.app/.netlify/functions/get-art | python3 -m json.tool | head -5
# Expected: {"art": null} on first call (Blob empty — seeded on first editor save)
# OR {"art": [...]} if already seeded
```

- [ ] **Open the site and verify it loads art**

Navigate to `https://frostline-art.netlify.app`. Gallery should show all art (loaded from bundled ART fallback since Blob is empty).

- [ ] **Test auth flow**

Click 🔒 → enter wrong password → should see "Wrong password". Enter correct password → 🔓 appears, Add/Edit/Delete buttons appear on cards.

- [ ] **Test save flow**

While unlocked: edit a piece title → Save. Wait 1-2 seconds. Open new incognito tab → navigate to site → verify edited title is visible (loaded from Blob).

- [ ] **Test flag flow**

Click 🚩 on any card → flag toggles red. Open new tab → flag should still show (loaded from Blob). As editor: "flagged (N)" tab appears in tag bar.

- [ ] **Test WoS badges**

Cards with `wosRisk: true` should show ⚠️ WoS? badge. As editor, click badge → toggles to ✅ WoS. Save persists.

- [ ] **Test proportional preview**

Verify card previews use a proportional font (no monospace letter-spacing).

- [ ] **Final commit if any fixes needed**

```bash
git add -p  # stage only intentional changes
git commit -m "Frostline: post-deploy fixes"
git push origin master
```

---

## Notes

- **First editor save seeds the Blob** — on first unlock + save, the full bundled ART array is written to Netlify Blob. All subsequent visitors load from Blob.
- **Blob persistence** — Netlify Blobs persist across deploys. Changing `art.js` in the repo only affects the fallback for visitors who hit the function before any editor save. After first editor save, Blob is the source of truth.
- **Password reset** — if forgotten: update `EDITOR_PASSWORD` env var in Netlify dashboard → Trigger redeploy. No code change needed.
