/**
 * Frostline — app.js
 * Client-side logic for the text-art library.
 *
 * Talks to Netlify Functions when deployed; falls back to localStorage for
 * local preview. The dev fallback password is "frostline".
 *
 * Sections:
 *   01  Constants & DOM refs
 *   02  Utilities (graphemes, NBSP, audit, escaping)
 *   03  API layer (functions + localStorage fallback)
 *   04  State + boot
 *   05  Rendering — tag strip, grid, cards
 *   06  Filtering + search
 *   07  Lightbox
 *   08  Copy with NBSP conversion
 *   09  Share bar
 *   10  Auth (7-tap snowflake unlock)
 *   11  Add/Edit modal — text mode + audit
 *   12  Add/Edit modal — draw mode
 *   13  Save / delete / flag / verified
 *   14  Export art.js
 *   15  Init
 */

/* ============ 01  Constants & DOM refs ============ */
const TAGS = [
  'all', 'love', 'nature', 'animals', 'banners', 'borders',
  'decorative', 'celebration', 'symbols', 'aesthetic', 'kawaii',
  'gothic', 'memes', 'sayings', 'minimalist', 'nsfw',
];
const WOS_MAX_WIDTH = 27;       // soft warn (⚠) — wide chars may clip
const WOS_HARD_LIMIT = 58;      // hard warn (⛔) — likely to break in chat
const DEV_FALLBACK_PASSWORD = '0022';


// WoS-safe Unicode ranges, per handoff.
const SAFE_RANGES = [
  [0x000A, 0x000A], // newline
  [0x00A0, 0x00A0], // NBSP
  [0x3000, 0x3000], // ideographic space
  [0x0021, 0x007E], // printable ASCII
  [0x2500, 0x27BF],
  [0x2600, 0x26FF],
  [0xFF00, 0xFFEF],
  [0x1F100, 0x1FAFF],
];

const $ = (id) => document.getElementById(id);

const els = {
  snowflake: $('snowflake'),
  shareBar: $('share-bar'),
  search: $('search'),
  tagStrip: $('tag-strip'),
  stripLeft: $('strip-left'),
  stripRight: $('strip-right'),
  btnAdd: $('btn-add'),
  grid: $('grid'),
  btnExport: $('btn-export'),

  lightbox: $('lightbox'),
  lbTitle: $('lb-title'),
  lbClose: $('lb-close'),
  lbPre: $('lb-pre'),
  lbDim: $('lb-dim'),
  lbPills: $('lb-pills'),
  lbCopy: $('lb-copy'),

  auth: $('auth'),
  authClose: $('auth-close'),
  authPassword: $('auth-password'),
  authError: $('auth-error'),
  authSubmit: $('auth-submit'),
  authRemember: $('auth-remember'),
  btnLock: $('btn-lock'),
  hamburger: $('hamburger'),
  drawer: $('themes-drawer'),
  drawerScrim: $('drawer-scrim'),
  drawerClose: $('drawer-close'),
  drawerList: $('drawer-list'),
  activeThemeRow: $('active-theme-row'),
  activeThemeChip: $('active-theme-chip'),
  activeThemeLabel: $('active-theme-label'),

  edit: $('edit'),
  editTitle: $('edit-title'),
  editClose: $('edit-close'),
  editTitleInput: $('edit-title-input'),
  editTagsInput: $('edit-tags-input'),
  editArtInput: $('edit-art-input'),
  editPreview: $('edit-preview'),
  editAudit: $('edit-audit'),
  editCancel: $('edit-cancel'),
  editSave: $('edit-save'),

  favoritesBar: $('favorites-bar'),
  charPalette: $('char-palette'),

  sketchView: $('sketch-view'),
  sketchActiveChar: $('sketch-active-char'),
  sketchUndo: $('sketch-undo'),
  sketchEraser: $('sketch-eraser'),
  sketchFill: $('sketch-fill'),
  sketchClear: $('sketch-clear'),
};

/* ============ 02  Utilities ============ */
const segmenter =
  typeof Intl !== 'undefined' && Intl.Segmenter
    ? new Intl.Segmenter(undefined, { granularity: 'grapheme' })
    : null;

function graphemes(s) {
  if (!s) return [];
  return segmenter ? [...segmenter.segment(s)].map((x) => x.segment) : [...s];
}
function graphemeCount(s) {
  return graphemes(s).length;
}

function measure(art) {
  const lines = art.split('\n');
  let width = 0;
  for (const line of lines) width = Math.max(width, graphemeCount(line));
  return { width, height: lines.length };
}

// Does this art wrap inside the WoS chat bubble? WoS uses a proportional font,
// so a character count can't predict wrapping \u2014 we measure the REAL render in a
// hidden .art-render element (same font/width/wrap as the game).
let _wrapMeasure = null;
function wrapsInWoS(art) {
  if (!art) return false;
  if (!_wrapMeasure) {
    _wrapMeasure = document.createElement('div');
    _wrapMeasure.className = 'art-render';
    _wrapMeasure.setAttribute('aria-hidden', 'true');
    _wrapMeasure.style.cssText = 'position:absolute;left:-9999px;top:0;visibility:hidden;font-size:16px;';
    document.body.appendChild(_wrapMeasure);
  }
  _wrapMeasure.style.fontSize = '16px';
  _wrapMeasure.textContent = art;
  const lh = parseFloat(getComputedStyle(_wrapMeasure).lineHeight) || 20;
  const srcRows = art.split('\n').length;
  return _wrapMeasure.scrollHeight > Math.ceil(srcRows * lh) + 1;
}

function spacesToNbsp(s) {
  return s.replace(/ /g, '\u00A0');
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function isSafeCode(cp) {
  for (const [lo, hi] of SAFE_RANGES) {
    if (cp >= lo && cp <= hi) return true;
  }
  return false;
}

function auditArt(text) {
  const issues = [];
  if (/ /.test(text)) {
    issues.push({
      level: 'warn',
      msg: 'Contains regular spaces — auto-converted on save. Copy from the gallery, not the text editor, to get the WoS-safe version.',
    });
  }
  // Width audit — does it ACTUALLY wrap in WoS's bubble? WoS is proportional,
  // so a raw character count is meaningless (e.g. a 42-char line of narrow glyphs
  // fits fine). We measure the real render instead.
  if (wrapsInWoS(text)) {
    issues.push({
      level: 'warn',
      msg: 'A line is too wide and wraps in the WoS chat bubble. Shorten it until the preview shows no wrapping.',
    });
  }
  const unsafe = new Set();
  for (const g of graphemes(text)) {
    for (const ch of g) {
      const cp = ch.codePointAt(0);
      if (!isSafeCode(cp)) unsafe.add(g);
    }
  }
  if (unsafe.size) {
    const list = [...unsafe].slice(0, 12).map((g) => {
      const cp = g.codePointAt(0).toString(16).toUpperCase().padStart(4, '0');
      return `${g} (U+${cp})`;
    }).join('  ·  ');
    issues.push({
      level: 'error',
      msg: `Unverified in WoS: <code>${escapeHtml(list)}</code> — test in chat before publishing.`,
    });
  }
  return issues;
}

function debounce(fn, wait) {
  let t;
  return (...a) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...a), wait);
  };
}

/* ============ 03  API layer ============ */
// Resolve function URL prefix once at boot. Tries Netlify Functions first,
// falls back to Cloudflare Pages Functions at /api/*.
let fnPrefix = null;
async function getFnPrefix() {
  if (fnPrefix !== null) return fnPrefix;
  try {
    const r = await fetch('/.netlify/functions/get-art', { method: 'GET' });
    if (r.status !== 404 && r.status < 500) { fnPrefix = '/.netlify/functions'; return fnPrefix; }
  } catch { /* ignore */ }
  fnPrefix = '/api';
  return fnPrefix;
}
async function fnUrl(name) {
  const prefix = await getFnPrefix();
  return `${prefix}/${name}`;
}

// localStorage is a last-known-good CACHE only (never a competing store), so an
// unreachable backend shows your real library instead of the bundled seed.
const CACHE_KEY = 'frostline:cache:v2';
const LEGACY_KEY = 'frostline:art';

function readCache() {
  try {
    const raw = localStorage.getItem(CACHE_KEY);
    if (raw) return JSON.parse(raw);
  } catch { /* ignore */ }
  // Migration path: the old fallback stored only user pieces + deletedIds.
  try {
    const raw = localStorage.getItem(LEGACY_KEY);
    if (raw) {
      const o = JSON.parse(raw);
      return { legacy: true, art: o.art || [], deletedIds: o.deletedIds || [] };
    }
  } catch { /* ignore */ }
  return null;
}

function writeCache(library, deletedIds) {
  const payload = JSON.stringify({ library, deletedIds, ts: Date.now() });
  try { localStorage.setItem(CACHE_KEY, payload); }
  catch { /* quota hit (large art) — server stays source of truth */ }
}

const API = {
  // Returns the raw server payload: { library?, art?, deletedIds? } when online,
  // { empty: true } on 404, or { offline: true } when unreachable. resolveLibrary
  // decides what becomes authoritative (server > legacy-migrate > cache > bundle).
  async getArt() {
    try {
      const res = await fetch(await fnUrl('get-art'), { cache: 'no-store' });
      if (res.ok) return await res.json();
      if (res.status === 404) return { empty: true };
    } catch { /* offline / unreachable */ }
    return { offline: true };
  },
  async _post(payload, password) {
    const res = await fetch(await fnUrl('save-art'), {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + password, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (res.ok) return { ok: true };
    const err = await res.json().catch(() => ({}));
    if (res.status === 404) throw new Error('not deployed');
    return { ok: false, error: err.error || `HTTP ${res.status}`, status: res.status };
  },
  // Per-piece writes: two devices saving different pieces never overwrite each
  // other (only the same piece edited at once is last-write-wins).
  async savePiece(piece, password) {
    try { return await this._post({ piece }, password); }
    catch { return { ok: true, local: true }; }
  },
  async deletePiece(id, password) {
    try { return await this._post({ deleteId: id }, password); }
    catch { return { ok: true, local: true }; }
  },
  async savePieces(pieces, deletedIds, password) {
    try { return await this._post({ pieces, deletedIds }, password); }
    catch { return { ok: true, local: true }; }
  },
  async getFlags() {
    try {
      const res = await fetch(await fnUrl('get-flags'));
      if (res.ok) return (await res.json()).flags || {};
    } catch { /* fall through */ }
    const stored = localStorage.getItem('frostline:flags');
    return stored ? JSON.parse(stored) : {};
  },
  async saveFlag(id, action, note) {
    try {
      const res = await fetch(await fnUrl('save-flags'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, action, note: note || '' }),
      });
      if (res.ok) return await res.json();
      if (res.status === 404) throw new Error('not deployed');
    } catch {
      const flags = JSON.parse(localStorage.getItem('frostline:flags') || '{}');
      if (action === 'toggle') {
        if (id in flags) delete flags[id];
        else flags[id] = '';
      } else {
        flags[id] = note || '';
      }
      localStorage.setItem('frostline:flags', JSON.stringify(flags));
      return { ok: true, flagged: id in flags, note: flags[id] || '' };
    }
  },
  async authenticate(password) {
    try {
      const res = await fetch(await fnUrl('auth'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      if (res.ok) return { ok: true };
      if (res.status === 401) return { ok: false, error: 'Wrong password' };
      if (res.status === 404) throw new Error('not deployed');
      return { ok: false, error: 'Server error' };
    } catch {
      return password === DEV_FALLBACK_PASSWORD
        ? { ok: true, fallback: true }
        : { ok: false, error: 'Wrong password' };
    }
  },
};

/* ============ 03.5  Session + persistent auth ============ */
// All client-only — no secrets leave the browser. The password is held in
// localStorage so the user can refresh / leave & return without re-entering
// it. Use the "Lock editor" button to drop it.
const SESSION_KEY = 'frostline:session';      // { query, activeTag, scrollY, lightboxId }
const REMEMBER_KEY = 'frostline:remember';    // password string when "stay unlocked" is on

function loadSession() {
  try {
    const raw = localStorage.getItem(SESSION_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch { return {}; }
}
const _saveSession = () => {
  try {
    localStorage.setItem(SESSION_KEY, JSON.stringify({
      query: state.query || '',
      activeTag: state.activeTag || 'all',
      scrollY: Math.round(window.scrollY || 0),
      lightboxId: (els.lightbox && els.lightbox.classList.contains('open'))
        ? (els.lightbox.dataset.openId || null)
        : null,
    }));
  } catch { /* quota etc. — ignore */ }
};
const saveSession = debounce(_saveSession, 250);
// Persist immediately when the user leaves the page — debounce may not flush.
window.addEventListener('pagehide', _saveSession);
window.addEventListener('beforeunload', _saveSession);
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden') _saveSession();
});
window.addEventListener('scroll', saveSession, { passive: true });

function showToast(msg, ms = 2200) {
  let t = document.getElementById('session-toast');
  if (!t) {
    t = document.createElement('div');
    t.id = 'session-toast';
    t.className = 'session-toast';
    document.body.appendChild(t);
  }
  t.textContent = msg;
  // force reflow so the transition replays on repeat toasts
  void t.offsetWidth;
  t.classList.add('show');
  clearTimeout(t._hideTimer);
  t._hideTimer = setTimeout(() => t.classList.remove('show'), ms);
}

/* ============ 04  State + boot ============ */
const state = {
  bundled: [],           // copy of ART (seed/backup only — never overrides runtime)
  library: [],           // authoritative full list (from Netlify Blobs)
  deletedIds: new Set(), // tombstones — stop bundle adds from resurrecting deletes
  flags: {},             // { pieceId: noteText }
  merged: [],            // computed display list
  activeTag: 'all',
  query: '',
  editor: false,
  password: null,
  booted: false,
};

async function boot() {
  state.bundled = (window.ART || []).slice();

  // --- Restore session state before first render so the tag strip / search
  //     box reflect where the user left off.
  const sess = loadSession();
  if (sess.query) {
    state.query = sess.query;
    els.search.value = sess.query;
  }
  if (sess.activeTag && (TAGS.includes(sess.activeTag) || sess.activeTag === '__flagged')) {
    state.activeTag = sess.activeTag;
  }

  buildTagStrip();
  renderEmpty('Loading…');

  // --- Auto-unlock if the user previously chose "stay unlocked". We don't
  //     await this — boot can render the gallery while auth happens.
  const remembered = (() => {
    try { return localStorage.getItem(REMEMBER_KEY); } catch { return null; }
  })();
  if (remembered) {
    API.authenticate(remembered).then((r) => {
      if (r.ok) {
        state.editor = true;
        state.password = remembered;
        document.body.classList.add('editor');
        els.btnExport.disabled = false;
        render();
        showToast('Editor mode restored');
      } else {
        // password no longer valid — drop it silently
        try { localStorage.removeItem(REMEMBER_KEY); } catch {}
      }
    }).catch(() => { /* offline / 404 — try again next load */ });
  }

  const [artData, flags] = await Promise.all([API.getArt(), API.getFlags()]);
  state.flags = flags || {};
  resolveLibrary(artData);
  state.booted = true;
  recomputeMerged();
  render();

  // --- Restore scroll position + reopen the lightbox the user was viewing.
  if (typeof sess.scrollY === 'number' && sess.scrollY > 0) {
    // Two RAFs: one for layout, one for the grid's per-card fitPreview pass.
    requestAnimationFrame(() => requestAnimationFrame(() => {
      window.scrollTo(0, sess.scrollY);
    }));
  }
  if (sess.lightboxId) {
    const piece = state.merged.find((p) => p.id === sess.lightboxId);
    if (piece) openLightbox(piece);
  }
}

function bundleSeed() {
  return state.bundled.map((p) => ({ ...p }));
}

// One-time merge when migrating legacy data (user pieces + deletedIds layered
// over the bundle) into the flat library.
function migrateMerge(bundled, userPieces, deletedSet) {
  const out = [];
  const userById = new Map((userPieces || []).map((p) => [p.id, p]));
  for (const p of bundled) {
    if (deletedSet.has(p.id)) continue;
    const overlay = userById.get(p.id);
    if (overlay) { out.push({ ...p, ...overlay }); userById.delete(p.id); }
    else out.push({ ...p });
  }
  for (const p of userById.values()) {
    if (deletedSet.has(p.id)) continue;
    out.push({ ...p });
  }
  return out;
}

// Decide the authoritative library, in priority order: the server's flat
// `library`, an OLD server payload to migrate, the local cache, then the bundle.
// The bundle can only ADD genuinely-new ids — it never overrides or resurrects.
function resolveLibrary(data) {
  let library = null;
  let deletedIds = [];
  let needsPersist = false;

  if (data && Array.isArray(data.library)) {
    library = data.library.map((p) => ({ ...p }));
    deletedIds = data.deletedIds || [];
  } else if (data && !data.offline && (Array.isArray(data.art) || Array.isArray(data.deletedIds))) {
    deletedIds = data.deletedIds || [];
    library = migrateMerge(state.bundled, data.art || [], new Set(deletedIds));
    needsPersist = true; // fold legacy server format into the new library
  } else {
    // offline / empty / 404 → cache, then bundle seed. Never the bare bundle
    // if we have a cached real library.
    const cache = readCache();
    if (cache && Array.isArray(cache.library)) {
      library = cache.library.map((p) => ({ ...p }));
      deletedIds = cache.deletedIds || [];
    } else if (cache && cache.legacy) {
      deletedIds = cache.deletedIds || [];
      library = migrateMerge(state.bundled, cache.art || [], new Set(deletedIds));
    } else {
      library = bundleSeed();
    }
  }

  // Tombstones are STICKY: union the server's list with any we already hold in
  // memory. Netlify Blobs list() is eventually consistent, so the refresh() we
  // fire right after a delete usually reads a stale list that doesn't yet show
  // the tombstone (or still shows the piece). Without this union the bundle-seed
  // fold-in below would resurrect the just-deleted piece — the "disappears then
  // reappears" bug. A full page reload starts from an empty set and re-reads the
  // (by then consistent) server state, so this never permanently hides anything.
  const tomb = new Set(deletedIds);
  if (state.deletedIds) for (const id of state.deletedIds) tomb.add(id);
  state.deletedIds = tomb;

  // The piece-list may also lag our delete — drop anything tombstoned so a stale
  // server read can't leave the deleted piece sitting in the library.
  library = library.filter((p) => !tomb.has(p.id));

  // Fold in genuinely-new bundled pieces (curated art added in a later deploy)
  // without resurrecting anything the editor deleted.
  const known = new Set(library.map((p) => p.id));
  for (const p of state.bundled) {
    if (!known.has(p.id) && !tomb.has(p.id)) {
      library.push({ ...p });
      needsPersist = true;
    }
  }

  state.library = library;
  writeCache(state.library, [...state.deletedIds]);

  // Persist migrations / new-bundle fold-ins, but only with write access.
  if (needsPersist && state.editor && state.password) {
    API.savePieces(state.library, [...state.deletedIds], state.password);
  }
}

function recomputeMerged() {
  // The library is authoritative; the tombstone filter is belt-and-suspenders.
  state.merged = state.library.filter((p) => !state.deletedIds.has(p.id));
}

function cacheNow() {
  writeCache(state.library, [...state.deletedIds]);
}

// Pull the authoritative library from the shared store so this device converges
// with edits made elsewhere. Safe to call any time after boot.
let _refreshing = false;
async function refresh() {
  if (!state.booted || _refreshing) return;
  _refreshing = true;
  try {
    const data = await API.getArt();
    if (data && (Array.isArray(data.library) || Array.isArray(data.art))) {
      resolveLibrary(data);
      recomputeMerged();
      render();
    }
  } finally {
    _refreshing = false;
  }
}

/* ============ 05  Rendering ============ */
function buildTagStrip() {
  els.tagStrip.innerHTML = '';
  for (const tag of TAGS) {
    const b = document.createElement('button');
    b.className = 'tag';
    b.textContent = tag;
    b.dataset.tag = tag;
    if (tag === state.activeTag) b.classList.add('active');
    b.addEventListener('click', () => setActiveTag(tag === state.activeTag ? 'all' : tag));
    els.tagStrip.appendChild(b);
  }
  buildDrawerList();
  syncFlaggedTab();
  syncActiveThemeChip();
}

/* Themes drawer — replaces the inline tag strip. Same labels, same handler,
   different surface: a slide-in panel triggered by the hamburger button. */
function buildDrawerList() {
  if (!els.drawerList) return;
  els.drawerList.innerHTML = '';
  for (const tag of TAGS) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'drawer-item';
    b.textContent = tag;
    b.dataset.tag = tag;
    b.setAttribute('role', 'listitem');
    if (tag === state.activeTag) b.classList.add('active');
    b.addEventListener('click', () => {
      const next = tag === state.activeTag ? 'all' : tag;
      setActiveTag(next);
      closeDrawer();
    });
    els.drawerList.appendChild(b);
  }
}

function syncActiveThemeChip() {
  if (!els.activeThemeRow) return;
  const t = state.activeTag;
  const isDefault = !t || t === 'all';
  if (isDefault) {
    els.activeThemeRow.hidden = true;
    return;
  }
  els.activeThemeRow.hidden = false;
  const flagged = t === '__flagged';
  els.activeThemeChip.classList.toggle('flagged', flagged);
  const flagCount = Object.keys(state.flags || {}).length;
  els.activeThemeLabel.textContent = flagged ? `flagged (${flagCount})` : t;
}

function syncFlaggedTab() {
  let existing = els.tagStrip.querySelector('.tag.flagged-tab');
  const flagCount = Object.keys(state.flags).length;
  const shouldShow = state.editor && flagCount > 0;
  if (shouldShow) {
    if (!existing) {
      existing = document.createElement('button');
      existing.className = 'tag flagged-tab';
      existing.dataset.tag = '__flagged';
      existing.addEventListener('click', () =>
        setActiveTag(state.activeTag === '__flagged' ? 'all' : '__flagged'),
      );
      els.tagStrip.appendChild(existing);
    }
    existing.textContent = `flagged (${flagCount})`;
    existing.classList.toggle('active', state.activeTag === '__flagged');
  } else if (existing) {
    existing.remove();
    if (state.activeTag === '__flagged') state.activeTag = 'all';
  }

  // Mirror into the drawer (editor-only entry)
  if (els.drawerList) {
    let drawerFlagged = els.drawerList.querySelector('.drawer-item.flagged-tab');
    if (shouldShow) {
      if (!drawerFlagged) {
        drawerFlagged = document.createElement('button');
        drawerFlagged.type = 'button';
        drawerFlagged.className = 'drawer-item flagged-tab';
        drawerFlagged.dataset.tag = '__flagged';
        drawerFlagged.setAttribute('role', 'listitem');
        drawerFlagged.addEventListener('click', () => {
          setActiveTag(state.activeTag === '__flagged' ? 'all' : '__flagged');
          closeDrawer();
        });
        els.drawerList.appendChild(drawerFlagged);
      }
      drawerFlagged.textContent = `flagged (${flagCount})`;
      drawerFlagged.classList.toggle('active', state.activeTag === '__flagged');
    } else if (drawerFlagged) {
      drawerFlagged.remove();
    }
  }
  syncActiveThemeChip();
}

function setActiveTag(tag) {
  state.activeTag = tag;
  for (const b of els.tagStrip.querySelectorAll('.tag')) {
    b.classList.toggle('active', b.dataset.tag === tag);
  }
  if (els.drawerList) {
    for (const b of els.drawerList.querySelectorAll('.drawer-item')) {
      b.classList.toggle('active', b.dataset.tag === tag);
    }
  }
  syncActiveThemeChip();
  render();
  saveSession();
  setTimeout(updateStripArrows, 0);
}

function renderEmpty(msg) {
  els.grid.innerHTML = `<div class="grid-empty">${escapeHtml(msg)}</div>`;
}

function filtered() {
  let list = state.merged;
  if (state.activeTag === '__flagged') {
    list = list.filter((p) => p.id in state.flags);
  } else if (state.activeTag !== 'all') {
    list = list.filter((p) => Array.isArray(p.tags) && p.tags.includes(state.activeTag));
  }
  const q = state.query.trim().toLowerCase();
  if (q) {
    list = list.filter((p) => {
      const hay = (p.title + ' ' + (p.tags || []).join(' ')).toLowerCase();
      return hay.includes(q);
    });
  }
  return list;
}

function render() {
  syncFlaggedTab();
  const list = filtered();
  if (!list.length) {
    renderEmpty(state.query || state.activeTag !== 'all'
      ? 'No art matches.'
      : 'No art yet. Add some!');
    return;
  }
  els.grid.innerHTML = '';
  for (const p of list) els.grid.appendChild(renderCard(p));
}

function renderCard(p) {
  const card = document.createElement('article');
  card.className = 'card';
  card.dataset.id = p.id;
  if (p.id in state.flags) card.classList.add('flagged');

  // head
  const head = document.createElement('div');
  head.className = 'card-head';
  const title = document.createElement('div');
  title.className = 'card-title';
  title.textContent = p.title || 'Untitled';
  head.appendChild(title);

  // Width warning is decided after layout (in the fit pass below) from the ACTUAL
  // render — WoS is proportional, so a character count can't predict wrapping.
  const warn = document.createElement('span');
  warn.className = 'card-warn';
  warn.textContent = '⚠';
  warn.title = 'Too wide — wraps in the WoS chat bubble';
  warn.style.display = 'none';
  head.appendChild(warn);

  if (state.editor) {
    const actions = document.createElement('div');
    actions.className = 'card-actions';
    const edit = document.createElement('button');
    edit.className = 'icon-btn';
    edit.title = 'Edit';
    edit.innerHTML = '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#ffffff" d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zm17.71-9.96a1 1 0 0 0 0-1.41l-2.59-2.59a1 1 0 0 0-1.41 0L14.13 5.87l3.75 3.75 2.83-2.83z"/></svg>';
    edit.addEventListener('click', (e) => { e.stopPropagation(); openEdit(p); });
    const del = document.createElement('button');
    del.className = 'icon-btn danger';
    del.title = 'Delete';
    del.innerHTML = '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill="#ffffff" d="M6 19a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V7H6v12zm2.46-7.12 1.41-1.41L12 12.59l2.12-2.12 1.41 1.41L13.41 14l2.12 2.12-1.41 1.41L12 15.41l-2.12 2.12-1.41-1.41L10.59 14l-2.13-2.12zM15.5 4l-1-1h-5l-1 1H5v2h14V4z"/></svg>';
    del.addEventListener('click', (e) => { e.stopPropagation(); deletePiece(p); });
    actions.appendChild(edit);
    actions.appendChild(del);
    head.appendChild(actions);
  }
  card.appendChild(head);

  // preview
  const prev = document.createElement('div');
  prev.className = 'preview';
  const pre = document.createElement('pre');
  pre.className = 'art-render';
  pre.textContent = p.art || '';
  prev.appendChild(pre);
  card.appendChild(prev);

  // scale to fit after layout, then flag the card if the real render wrapped
  requestAnimationFrame(() => {
    fitArt(prev, pre, 14, { height: true });
    const srcRows = (p.art || '').split('\n').length;
    const lh = parseFloat(getComputedStyle(pre).lineHeight) || 1;
    const rows = Math.round(pre.scrollHeight / lh);
    warn.style.display = rows > srcRows ? '' : 'none';
  });

  // chips
  if (p.tags && p.tags.length) {
    const chips = document.createElement('div');
    chips.className = 'chips';
    for (const t of p.tags) {
      const c = document.createElement('span');
      c.className = 'chip';
      c.textContent = t;
      chips.appendChild(c);
    }
    card.appendChild(chips);
  }

  // flag note (textarea) — only when flagged
  const note = document.createElement('textarea');
  note.className = 'flag-note';
  note.placeholder = 'Why is this flagged?';
  note.value = state.flags[p.id] || '';
  const saveNote = debounce(() => {
    if (p.id in state.flags) {
      state.flags[p.id] = note.value;
      API.saveFlag(p.id, 'note', note.value);
    }
  }, 900);
  note.addEventListener('input', saveNote);
  note.addEventListener('blur', () => {
    if (p.id in state.flags) {
      state.flags[p.id] = note.value;
      API.saveFlag(p.id, 'note', note.value);
    }
  });
  note.addEventListener('click', (e) => e.stopPropagation());
  card.appendChild(note);

  // copy
  const copy = document.createElement('button');
  copy.className = 'copy-btn';
  copy.textContent = '📋 Copy';
  copy.addEventListener('click', (e) => {
    e.stopPropagation();
    copyArt(p.art, copy);
  });
  card.appendChild(copy);

  // wos badge
  const wos = document.createElement('span');
  wos.className = 'wos-badge ' + (p.wosVerified ? 'verified' : 'unverified');
  wos.textContent = p.wosVerified ? '✅ WoS' : '? WoS';
  wos.addEventListener('click', (e) => {
    if (!state.editor) return;
    e.stopPropagation();
    toggleVerified(p);
  });
  card.appendChild(wos);

  // flag corner
  const flag = document.createElement('span');
  flag.className = 'flag-corner';
  const box = document.createElement('span');
  box.className = 'box';
  box.textContent = (p.id in state.flags) ? '🚩' : '';
  flag.appendChild(box);
  flag.appendChild(document.createTextNode(' ' + ((p.id in state.flags) ? 'flagged' : 'flag')));
  flag.addEventListener('click', (e) => {
    e.stopPropagation();
    toggleFlag(p, card, box, flag, note);
  });
  card.appendChild(flag);

  // open lightbox on card body click
  card.addEventListener('click', () => openLightbox(p));

  return card;
}

// One renderer for ALL art surfaces (card, lightbox, editor preview). Uniform
// font-size scaling — never transform: scale(), which crunches subpixels and
// visibly drifts alignment. Combined with the shared .art-render class, the
// same art aligns identically in every surface.
function fitArt(container, pre, base, { height = false } = {}) {
  pre.style.transform = '';
  pre.style.fontSize = base + 'px';
  const cs = getComputedStyle(container);
  const cw = container.clientWidth - (parseFloat(cs.paddingLeft) + parseFloat(cs.paddingRight));
  const pw = pre.scrollWidth;
  if (pw <= 0 || cw <= 0) return;
  let scale = cw / pw;
  if (height) {
    const ch = container.clientHeight - (parseFloat(cs.paddingTop) + parseFloat(cs.paddingBottom));
    const ph = pre.scrollHeight;
    if (ch > 0 && ph > 0) scale = Math.min(scale, ch / ph);
  }
  scale = Math.min(1, scale);
  if (scale < 1) pre.style.fontSize = (base * scale).toFixed(2) + 'px';
}

/* ============ 06  Filtering + search ============ */
els.search.addEventListener('input', () => {
  state.query = els.search.value;
  render();
  saveSession();
});
els.stripLeft.addEventListener('click', () => els.tagStrip.scrollBy({ left: -160, behavior: 'smooth' }));
els.stripRight.addEventListener('click', () => els.tagStrip.scrollBy({ left: 160, behavior: 'smooth' }));

/* Drawer (hamburger menu) — open/close + outside-click + escape */
function openDrawer() {
  if (!els.drawer) return;
  els.drawer.hidden = false;
  els.drawerScrim.hidden = false;
  // next frame so the transition actually animates
  requestAnimationFrame(() => {
    els.drawer.classList.add('open');
    els.drawerScrim.classList.add('open');
  });
  els.drawer.setAttribute('aria-hidden', 'false');
  els.hamburger.setAttribute('aria-expanded', 'true');
}
function closeDrawer() {
  if (!els.drawer) return;
  els.drawer.classList.remove('open');
  els.drawerScrim.classList.remove('open');
  els.drawer.setAttribute('aria-hidden', 'true');
  els.hamburger.setAttribute('aria-expanded', 'false');
  // Hide after transition so it's removed from the a11y tree
  setTimeout(() => {
    if (!els.drawer.classList.contains('open')) {
      els.drawer.hidden = true;
      els.drawerScrim.hidden = true;
    }
  }, 280);
}
if (els.hamburger) {
  els.hamburger.addEventListener('click', () => {
    const open = els.hamburger.getAttribute('aria-expanded') === 'true';
    if (open) closeDrawer(); else openDrawer();
  });
}
if (els.drawerClose) els.drawerClose.addEventListener('click', closeDrawer);
if (els.drawerScrim) els.drawerScrim.addEventListener('click', closeDrawer);
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && els.drawer && els.drawer.classList.contains('open')) closeDrawer();
});
// Active-theme chip — tap to clear the filter back to "all"
if (els.activeThemeChip) {
  els.activeThemeChip.addEventListener('click', () => setActiveTag('all'));
}

function updateStripArrows() {
  const el = els.tagStrip;
  const maxScroll = el.scrollWidth - el.clientWidth;
  const atLeft = el.scrollLeft <= 1;
  const atRight = el.scrollLeft >= maxScroll - 1 || maxScroll <= 0;
  els.stripLeft.style.visibility = atLeft ? 'hidden' : 'visible';
  els.stripRight.style.visibility = atRight ? 'hidden' : 'visible';
}
els.tagStrip.addEventListener('scroll', updateStripArrows, { passive: true });
window.addEventListener('resize', updateStripArrows);
// run after initial render (tags populate on boot)
setTimeout(updateStripArrows, 50);
setTimeout(updateStripArrows, 500);

/* ============ 07  Lightbox ============ */
function openLightbox(p) {
  els.lightbox.dataset.openId = p.id;
  els.lbTitle.textContent = p.title || 'Untitled';
  // WoS is proportional; show the art exactly as the bubble renders it (it will
  // visibly wrap if a line is too wide) rather than guessing from char counts.
  els.lbPre.textContent = p.art || '';
  const m = measure(p.art);
  els.lbDim.textContent = `${m.width} × ${m.height} graphemes`;
  els.lbPills.innerHTML = '';
  for (const t of (p.tags || [])) {
    const c = document.createElement('span');
    c.className = 'chip';
    c.textContent = t;
    els.lbPills.appendChild(c);
  }
  els.lbCopy.classList.remove('copied');
  els.lbCopy.textContent = '📋 Copy to Clipboard';
  els.lbCopy.onclick = () => copyArt(p.art, els.lbCopy, true);
  // fit preview to modal width
  requestAnimationFrame(() => fitArt(els.lbPre.parentElement, els.lbPre, 20));
  els.lightbox.classList.add('open');
  saveSession();
}
function closeLightbox() {
  els.lightbox.classList.remove('open');
  delete els.lightbox.dataset.openId;
  saveSession();
}
els.lbClose.addEventListener('click', closeLightbox);
els.lightbox.addEventListener('click', (e) => { if (e.target === els.lightbox) closeLightbox(); });

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    if (els.lightbox.classList.contains('open')) closeLightbox();
    else if (els.edit.classList.contains('open')) closeEdit();
    // auth modal is intentionally NOT closeable via Esc — only via X or correct password
  }
});

/* ============ 08  Copy with NBSP ============ */
async function copyArt(text, btn, isLightbox) {
  const normalized = spacesToNbsp(text);
  try {
    await navigator.clipboard.writeText(normalized);
  } catch {
    // fallback
    const ta = document.createElement('textarea');
    ta.value = normalized;
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch {}
    ta.remove();
  }
  const original = isLightbox ? '📋 Copy to Clipboard' : '📋 Copy';
  btn.classList.add('copied');
  btn.textContent = '✓ Copied!';
  setTimeout(() => {
    btn.classList.remove('copied');
    btn.textContent = original;
  }, 1400);
}

/* ============ 09  Share bar ============ */
els.shareBar.addEventListener('click', async () => {
  const url = 'https://frostline-art.netlify.app';
  try { await navigator.clipboard.writeText(url); } catch {}
  els.shareBar.classList.add('copied');
  const cta = els.shareBar.querySelector('.cta');
  const prev = cta.textContent;
  cta.textContent = '✓ Copied!';
  setTimeout(() => { cta.textContent = prev; els.shareBar.classList.remove('copied'); }, 1400);
});

/* ============ 10  Auth (7-tap unlock) ============ */
// The emblem gives NO visual feedback on tap (no spin, no cursor change) so it
// doesn't read as a button — a casual user can't tell the admin editor exists.
// Seven taps within 3s silently opens the password prompt.
let tapTimes = [];
els.snowflake.addEventListener('click', () => {
  const now = Date.now();
  tapTimes = tapTimes.filter((t) => now - t < 3000);
  tapTimes.push(now);
  if (tapTimes.length >= 7) {
    tapTimes = [];
    openAuth();
  }
});

function openAuth() {
  els.authError.textContent = '';
  els.authPassword.value = '';
  // Default the checkbox to ON — most users will want to stay unlocked, and
  // the lock button makes signing out a single tap.
  if (els.authRemember) {
    const remembered = (() => {
      try { return !!localStorage.getItem(REMEMBER_KEY); } catch { return false; }
    })();
    els.authRemember.checked = remembered || true;
  }
  els.auth.classList.add('open');
  setTimeout(() => els.authPassword.focus(), 50);
}
function closeAuth() { els.auth.classList.remove('open'); }
els.authClose.addEventListener('click', closeAuth);
// auth modal is intentionally NOT closeable by clicking the backdrop
els.authSubmit.addEventListener('click', submitAuth);
els.authPassword.addEventListener('keydown', (e) => { if (e.key === 'Enter') submitAuth(); });

async function submitAuth() {
  els.authError.textContent = '';
  const pw = els.authPassword.value;
  if (!pw) { els.authError.textContent = 'Enter the password'; return; }
  els.authSubmit.disabled = true;
  els.authSubmit.textContent = 'Unlocking…';
  const r = await API.authenticate(pw);
  els.authSubmit.disabled = false;
  els.authSubmit.textContent = 'Unlock';
  if (r.ok) {
    state.editor = true;
    state.password = pw;
    document.body.classList.add('editor');
    els.btnExport.disabled = false;
    // Persist the password if the user opted in.
    const remember = !!(els.authRemember && els.authRemember.checked);
    try {
      if (remember) localStorage.setItem(REMEMBER_KEY, pw);
      else localStorage.removeItem(REMEMBER_KEY);
    } catch { /* ignore quota errors */ }
    closeAuth();
    render();
  } else {
    els.authError.textContent = r.error || 'Wrong password';
  }
}

// Lock editor — drops the remembered password and returns to read-only mode
// without a page reload, so session state (scroll, search, etc.) is kept.
function lockEditor() {
  state.editor = false;
  state.password = null;
  document.body.classList.remove('editor');
  els.btnExport.disabled = true;
  try { localStorage.removeItem(REMEMBER_KEY); } catch {}
  // Re-render so per-card edit/delete buttons + flagged tab disappear.
  if (state.activeTag === '__flagged') state.activeTag = 'all';
  render();
  showToast('Editor locked');
}
if (els.btnLock) {
  els.btnLock.addEventListener('click', () => {
    if (!state.editor) return;
    lockEditor();
  });
}

/* ============ 11  Add/Edit modal ============ */
let editing = null; // null = adding new

function openAdd() {
  editing = null;
  els.editTitle.textContent = 'Add new art';
  els.editTitleInput.value = '';
  els.editTagsInput.value = '';
  // Auto-prepare a blank canvas so the cursor / sketch view both work immediately.
  const cols = 27, rows = 12;
  const line = '\u00A0'.repeat(cols);
  els.editArtInput.value = Array(rows).fill(line).join('\n');
  resetEditHistory(els.editArtInput.value);
  closeSaveSheet();
  toggleDraw(true); // new art opens straight into the draw canvas (primary feature)
  runAudit();
  renderSketch();
  els.edit.classList.add('open');
  // After the modal is open, see if a draft is waiting for this target.
  tryRestoreDraft();
}
function openEdit(p) {
  editing = p;
  els.editTitle.textContent = 'Edit art';
  els.editTitleInput.value = p.title || '';
  els.editTagsInput.value = (p.tags || []).join(', ');
  els.editArtInput.value = p.art || '';
  resetEditHistory(p.art || '');
  closeSaveSheet();
  toggleDraw(false);
  runAudit();
  renderSketch();
  els.edit.classList.add('open');
  tryRestoreDraft();
}
function closeEdit() {
  els.edit.classList.remove('open');
  els.edit.classList.remove('drawing');
  closeSaveSheet();
}
els.editClose.addEventListener('click', () => closeEdit());
els.editCancel.addEventListener('click', () => closeEdit());

/* ===== Autosave drafts =====================================================
 * The editor writes the in-progress piece to localStorage on every edit so a
 * pull-to-refresh, accidental close, or device kill never loses Codi's work.
 * Drafts are keyed by piece id (or "new" for a brand-new piece). On open, if a
 * draft exists for the target, we silently restore it and show a small
 * "Restored draft" indicator with a Discard action. Saving successfully or
 * confirming a discard clears the draft.
 */
const DRAFT_KEY = 'frostline:drafts:v1';
function loadDrafts() {
  try { return JSON.parse(localStorage.getItem(DRAFT_KEY) || '{}'); }
  catch { return {}; }
}
function saveDrafts(d) {
  try { localStorage.setItem(DRAFT_KEY, JSON.stringify(d)); } catch {}
}
function draftKey() {
  // editing.id when editing existing, "new" when adding
  return editing && editing.id ? `edit:${editing.id}` : 'new';
}
function readDraft() {
  return loadDrafts()[draftKey()] || null;
}
function writeDraft() {
  if (!els.edit.classList.contains('open')) return;
  const d = loadDrafts();
  d[draftKey()] = {
    title: els.editTitleInput.value,
    tags: els.editTagsInput.value,
    art: els.editArtInput.value,
    ts: Date.now(),
  };
  saveDrafts(d);
  showSavedIndicator();
}
function clearDraft() {
  const d = loadDrafts();
  delete d[draftKey()];
  saveDrafts(d);
}
const debouncedAutosave = debounce(writeDraft, 400);

let _indicatorTimer = null;
function showSavedIndicator() {
  const ind = document.getElementById('autosave-indicator');
  if (!ind) return;
  ind.textContent = 'Draft saved';
  ind.classList.add('show');
  clearTimeout(_indicatorTimer);
  _indicatorTimer = setTimeout(() => ind.classList.remove('show'), 1400);
}
function showRestoredIndicator() {
  const ind = document.getElementById('autosave-indicator');
  if (!ind) return;
  ind.innerHTML = 'Restored draft · <button type="button" class="draft-discard-btn">Discard</button>';
  ind.classList.add('show');
  const btn = ind.querySelector('.draft-discard-btn');
  if (btn) btn.addEventListener('click', () => {
    if (!confirm('Discard the restored draft and start fresh?')) return;
    clearDraft();
    // re-open with the original target
    if (editing) openEdit(editing); else openAdd();
    ind.classList.remove('show');
  });
  clearTimeout(_indicatorTimer);
  _indicatorTimer = setTimeout(() => ind.classList.remove('show'), 6000);
}

// Apply draft (if any) to the open editor; returns true if applied.
function tryRestoreDraft() {
  const d = readDraft();
  if (!d) return false;
  // Don't restore if the draft is identical to what's already loaded.
  if (d.title === els.editTitleInput.value &&
      d.tags === els.editTagsInput.value &&
      d.art === els.editArtInput.value) return false;
  els.editTitleInput.value = d.title || '';
  els.editTagsInput.value = d.tags || '';
  els.editArtInput.value = d.art || '';
  resetEditHistory(d.art || '');
  runAudit();
  renderSketch();
  showRestoredIndicator();
  return true;
}

// Wire autosave to every input the editor exposes.
['editTitleInput', 'editTagsInput', 'editArtInput'].forEach((k) => {
  const el = els[k];
  if (el) el.addEventListener('input', debouncedAutosave);
});
// Save once more on the way out (covers pagehide / visibilitychange too).
window.addEventListener('pagehide', () => { if (els.edit.classList.contains('open')) writeDraft(); });
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden' && els.edit.classList.contains('open')) writeDraft();
});
els.edit.addEventListener('click', (e) => {
  // Intentionally NOT closing on backdrop click — prevents accidental exit.
});
els.btnAdd.addEventListener('click', openAdd);

// Draw toggle — flips the canvas between type and paint without leaving the view
const drawToggleBtn = document.getElementById('draw-toggle');
if (drawToggleBtn) drawToggleBtn.addEventListener('click', () => toggleDraw(!isSketchMode()));
function ensureBlankCanvas() {
  // Make sure the textarea has a paintable 27×12 NBSP grid for sketch mode.
  // Called when entering Sketch mode with an empty textarea.
  if (els.editArtInput.value && els.editArtInput.value.trim()) return;
  const cols = 27, rows = 12;
  const line = '\u00A0'.repeat(cols);
  els.editArtInput.value = Array(rows).fill(line).join('\n');
  lastEditSnapshot = els.editArtInput.value;
  resetEditHistory(els.editArtInput.value);
  runAudit();
}

function toggleDraw(on) {
  const drawing = !!on;
  els.edit.classList.toggle('drawing', drawing);
  const btn = document.getElementById('draw-toggle');
  if (btn) {
    btn.classList.toggle('active', drawing);
    btn.setAttribute('aria-checked', drawing ? 'true' : 'false');
  }
  const txt = document.getElementById('draw-toggle-text');
  if (txt) txt.textContent = drawing ? '✏ Draw' : '⌨ Type';
  if (drawing) {
    ensureBlankCanvas();
    renderSketch(true);
  }
}

const runAudit = () => {
  const text = els.editArtInput.value;
  if (els.editPreview) {
    els.editPreview.textContent = text;
    requestAnimationFrame(() => fitArt(els.editPreview.parentElement, els.editPreview, 16));
  }
  const issues = auditArt(text);
  if (!issues.length) {
    els.editAudit.innerHTML = '';
    return;
  }
  els.editAudit.innerHTML = issues.map((i) =>
    `<div class="audit-line ${i.level}">
       <span class="glyph">${i.level === 'warn' ? '!' : '×'}</span>
       <span>${i.msg}</span>
     </div>`,
  ).join('');
};
els.editArtInput.addEventListener('input', runAudit);

/* ============ 12  Character palette + favorites ============ */
const FAVORITES_KEY = 'frostline:favorites';

function loadFavorites() {
  try {
    const arr = JSON.parse(localStorage.getItem(FAVORITES_KEY) || '[]');
    return Array.isArray(arr) ? arr.slice(0, 10) : [];
  } catch { return []; }
}
function saveFavorites(arr) {
  localStorage.setItem(FAVORITES_KEY, JSON.stringify(arr.slice(0, 10)));
}

function insertAtCursor(ch) {
  const ta = els.editArtInput;
  ta.focus();
  const start = ta.selectionStart;
  const end = ta.selectionEnd;
  const before = ta.value.slice(0, start);
  const after = ta.value.slice(end);
  ta.value = before + ch + after;
  const pos = start + ch.length;
  ta.setSelectionRange(pos, pos);
  runAudit();
  renderSketch();
}

/* ============ 12.5  Sketch view ============ */
let activeBrush = '❤';
let eraserOn = false;
const editHistory = [];      // stack of prior art strings
const EDIT_HISTORY_MAX = 40;
let editHistorySuspend = false;
let lastEditSnapshot = '';
let strokeStartSnapshot = null; // captured at pointerdown / touchstart
let lastTouchAt = 0;            // ms timestamp of most recent touch event

function pushEditHistory() {
  if (editHistorySuspend) return;
  const v = els.editArtInput.value;
  if (editHistory.length && editHistory[editHistory.length - 1] === v) return;
  editHistory.push(v);
  if (editHistory.length > EDIT_HISTORY_MAX) editHistory.shift();
}
function resetEditHistory(v) {
  editHistory.length = 0;
  editHistory.push(v || '');
  lastEditSnapshot = v || '';
}
function undoEdit() {
  if (editHistory.length < 2) return;
  editHistory.pop();
  const prev = editHistory[editHistory.length - 1];
  editHistorySuspend = true;
  els.editArtInput.value = prev;
  lastEditSnapshot = prev;
  editHistorySuspend = false;
  renderSketch(true);
  runAudit();
}

function setActiveBrush(ch) {
  activeBrush = ch;
  if (els.sketchActiveChar) els.sketchActiveChar.textContent = ch;
  // Highlight the matching palette button so the user can see what's selected.
  if (els.charPalette) {
    for (const b of els.charPalette.querySelectorAll('.palette-btn')) {
      b.classList.toggle('brush-active', b.dataset.char === ch);
    }
  }
  if (els.favoritesBar) {
    for (const b of els.favoritesBar.querySelectorAll('.fav-slot')) {
      b.classList.toggle('brush-active', b.textContent === ch);
    }
  }
}

function setEraser(on) {
  eraserOn = !!on;
  if (els.sketchEraser) els.sketchEraser.classList.toggle('active', eraserOn);
  if (els.sketchActiveChar) {
    els.sketchActiveChar.classList.toggle('eraser', eraserOn);
    els.sketchActiveChar.textContent = eraserOn ? '⌫' : activeBrush;
  }
}

function renderSketch(force) {
  if (!els.sketchView) return;
  if (!force && !isSketchMode()) return;
  const text = els.editArtInput.value;
  els.sketchView.innerHTML = '';
  if (!text) {
    const hint = document.createElement('div');
    hint.className = 'sketch-hint';
    hint.textContent = 'Switch to Sketch mode to start drawing on a 27×12 blank canvas.';
    els.sketchView.appendChild(hint);
    return;
  }
  // Cap canvas at WoS limits so there's no dead space outside chat-safe bounds.
  //   width  → max(27, actual) capped at 58 (hard limit)
  //   height → max(12, actual) capped at 24 (twice WoS height; anything beyond is degenerate)
  const lines = text.split('\n');
  let actualWidest = 0;
  for (const l of lines) actualWidest = Math.max(actualWidest, graphemeCount(l));
  const widest = Math.min(WOS_HARD_LIMIT, Math.max(WOS_MAX_WIDTH, actualWidest));
  const tallest = Math.min(24, Math.max(12, lines.length));
  for (let y = 0; y < tallest; y++) {
    const lineEl = document.createElement('div');
    lineEl.className = 'sketch-line';
    const gs = y < lines.length ? graphemes(lines[y]) : [];
    while (gs.length < widest) gs.push('\u00A0');
    for (let x = 0; x < widest; x++) {
      const span = document.createElement('span');
      span.className = 'sketch-char';
      const g = gs[x];
      span.textContent = (g === undefined || g === '\u00A0' || g === ' ') ? '\u00A0' : g;
      if (g === undefined || g === '\u00A0' || g === ' ') span.classList.add('sketch-empty-cell');
      span.dataset.y = y;
      span.dataset.x = x;
      lineEl.appendChild(span);
    }
    els.sketchView.appendChild(lineEl);
  }
}

function replaceCharAt(y, x) {
  // Note: this does NOT push history per-call. History is pushed once at
  // stroke start (pointerdown / touchstart) so a drag = one undo, not many.
  const text = els.editArtInput.value;
  const lines = text.split('\n');
  while (y >= lines.length) lines.push('');
  if (x < 0) return;
  const gs = graphemes(lines[y]);
  while (gs.length < x) gs.push('\u00A0');
  // Paint exactly ONE grapheme into the cell. A multi-character brush (a whole
  // kaomoji face, a bracket pair, an eye like "\u25DC\u25DD") would otherwise drop several
  // characters into one slot and shove the rest of the row to the right \u2014 the
  // user wants a stroke to replace the cell it lands on, not insert into it.
  // Stamp the FULL brush across consecutive cells. The brush may be a single
  // char or a multi-char face/kaomoji; EVERY grapheme must land so faces print
  // whole instead of just their first character. The eraser is one blank cell.
  const brush = eraserOn ? ['\u00A0'] : graphemes(activeBrush);
  if (!brush.length) return;
  // Cheap no-op guard when repainting the same single char (keeps drags light).
  if (brush.length === 1 && x < gs.length && gs[x] === brush[0]) return;
  for (let i = 0; i < brush.length; i++) {
    const col = x + i;
    while (gs.length <= col) gs.push('\u00A0');
    gs[col] = brush[i];
  }
  lines[y] = gs.join('');
  editHistorySuspend = true; // avoid the input listener pushing history
  els.editArtInput.value = lines.join('\n');
  editHistorySuspend = false;
  lastEditSnapshot = els.editArtInput.value;

  // Single-char brush -> mutate just the touched span (fast path for drags).
  // Multi-char brush -> re-render so every stamped cell refreshes.
  if (brush.length === 1) {
    const lineEl = els.sketchView.children[y];
    if (lineEl) {
      let span = lineEl.children[x];
      if (!span) {
        while (lineEl.children.length <= x) {
          const s = document.createElement('span');
          s.className = 'sketch-char sketch-empty-cell';
          s.textContent = '\u00A0';
          s.dataset.y = y;
          s.dataset.x = lineEl.children.length;
          lineEl.appendChild(s);
        }
        span = lineEl.children[x];
      }
      const nc = brush[0];
      if (nc === '\u00A0' || nc === ' ') {
        span.textContent = '\u00A0';
        span.classList.add('sketch-empty-cell');
      } else {
        span.textContent = nc;
        span.classList.remove('sketch-empty-cell');
      }
    }
  } else {
    renderSketch(true);
  }
  runAudit();
}

function startStroke() {
  // Snapshot value once at the start of a paint drag so a whole drag = one undo.
  strokeStartSnapshot = els.editArtInput.value;
  pushEditHistory();
}
function endStroke() {
  paintActive = false;
  strokeStartSnapshot = null;
}

/* ---- Canvas gestures: tap/drag to paint, long-press to grab & move ----
 * One unified model so the gestures never fight:
 *   quick tap           -> paint one cell with the active brush
 *   drag                -> paint a stroke
 *   long-press (~450ms) -> GRAB the character under the finger, drag it, and
 *                          release to DROP it in a new cell (origin left blank,
 *                          so it MOVES rather than copies).
 * Painting is deferred until we know it is not a long-press, so grabbing a
 * character never paints over it first. */
let paintActive = false;
let gesturePending = null;   // {y,x,clientX,clientY} captured at down
let grabState = null;        // {ch, fromY, fromX} while a character is held
let grabGhostEl = null;      // floating chip that follows the finger
let grabHoldTimer = null;
const GRAB_HOLD_MS = 450;

function cellFromPoint(cx, cy) {
  const target = document.elementFromPoint(cx, cy);
  return target && target.closest ? target.closest('.sketch-char') : null;
}
function cellAt(y, x) {
  const lineEl = els.sketchView.children[y];
  return lineEl ? lineEl.children[x] : null;
}
function cellContent(y, x) {
  const lines = els.editArtInput.value.split('\n');
  if (y < 0 || y >= lines.length) return '\u00A0';
  const gs = graphemes(lines[y]);
  return (x >= 0 && x < gs.length) ? gs[x] : '\u00A0';
}
function isBlankCell(ch) {
  return ch === undefined || ch === '' || ch === '\u00A0' || ch === ' ';
}

// Write a single grapheme into one cell (model + DOM in place). Used by grab/move.
function writeCell(y, x, ch) {
  if (x < 0 || y < 0) return;
  const lines = els.editArtInput.value.split('\n');
  while (y >= lines.length) lines.push('');
  const gs = graphemes(lines[y]);
  while (gs.length <= x) gs.push('\u00A0');
  gs[x] = ch;
  lines[y] = gs.join('');
  editHistorySuspend = true;
  els.editArtInput.value = lines.join('\n');
  editHistorySuspend = false;
  lastEditSnapshot = els.editArtInput.value;
  const span = cellAt(y, x);
  if (span) {
    if (isBlankCell(ch)) { span.textContent = '\u00A0'; span.classList.add('sketch-empty-cell'); }
    else { span.textContent = ch; span.classList.remove('sketch-empty-cell'); }
  }
  runAudit();
}

/* Find the contiguous run of non-blank cells in row y that includes column x.
 * This is what "the whole face / combo" means at grab time: any adjacent
 * non-blank characters travel together. Returns null if the pressed cell is
 * itself blank. */
function findRun(y, x) {
  const lines = els.editArtInput.value.split('\n');
  if (y < 0 || y >= lines.length) return null;
  const gs = graphemes(lines[y]);
  if (x < 0 || x >= gs.length || isBlankCell(gs[x])) return null;
  let start = x, end = x;
  while (start > 0 && !isBlankCell(gs[start - 1])) start--;
  while (end < gs.length - 1 && !isBlankCell(gs[end + 1])) end++;
  return {
    runChars: gs.slice(start, end + 1),
    runStart: start,
    runY: y,
    pressIdx: x - start, // where in the run the finger landed
  };
}

let dropHighlighted = [];
function clearDropTarget() {
  for (const c of dropHighlighted) c.classList.remove('drop-target');
  dropHighlighted = [];
}
function highlightDropRange(y, startX, len) {
  clearDropTarget();
  for (let i = 0; i < len; i++) {
    const c = cellAt(y, startX + i);
    if (c) { c.classList.add('drop-target'); dropHighlighted.push(c); }
  }
}
function moveGhost(cx, cy) {
  if (grabGhostEl) { grabGhostEl.style.left = cx + 'px'; grabGhostEl.style.top = cy + 'px'; }
}
function endGrab() {
  if (grabGhostEl) { grabGhostEl.remove(); grabGhostEl = null; }
  clearDropTarget();
  els.sketchView.classList.remove('grabbing');
  grabState = null;
}

function gestureDown(cx, cy, cell) {
  if (!cell) return;
  gesturePending = { y: +cell.dataset.y, x: +cell.dataset.x, clientX: cx, clientY: cy };
  clearTimeout(grabHoldTimer);
  grabHoldTimer = setTimeout(() => {
    if (!gesturePending) return;
    const run = findRun(gesturePending.y, gesturePending.x);
    if (!run) return; // pressed cell is blank; fall back to paint on release
    pushEditHistory(); // capture pre-grab state so the whole move = one undo
    grabState = run;
    els.sketchView.classList.add('grabbing');
    // Lift the ENTIRE run (one cell or many) off the canvas.
    for (let i = 0; i < run.runChars.length; i++) {
      writeCell(run.runY, run.runStart + i, '\u00A0');
    }
    grabGhostEl = document.createElement('div');
    grabGhostEl.className = 'grab-ghost';
    grabGhostEl.textContent = run.runChars.join('');
    document.body.appendChild(grabGhostEl);
    moveGhost(gesturePending.clientX, gesturePending.clientY);
    highlightDropRange(run.runY, run.runStart, run.runChars.length);
    gesturePending = null;
    paintActive = false;
  }, GRAB_HOLD_MS);
}

function gestureMove(cx, cy) {
  if (grabState) {
    moveGhost(cx, cy);
    const cell = cellFromPoint(cx, cy);
    if (!cell) { clearDropTarget(); return; }
    const newStart = (+cell.dataset.x) - grabState.pressIdx;
    highlightDropRange(+cell.dataset.y, newStart, grabState.runChars.length);
    return;
  }
  const cell = cellFromPoint(cx, cy);
  if (gesturePending) {
    // Moved off the origin cell before the hold fired => paint drag.
    if (cell && (+cell.dataset.y !== gesturePending.y || +cell.dataset.x !== gesturePending.x)) {
      clearTimeout(grabHoldTimer);
      startStroke();
      replaceCharAt(gesturePending.y, gesturePending.x);
      paintActive = true;
      gesturePending = null;
      replaceCharAt(+cell.dataset.y, +cell.dataset.x);
    }
    return;
  }
  if (paintActive && cell) replaceCharAt(+cell.dataset.y, +cell.dataset.x);
}

function gestureUp(cx, cy) {
  clearTimeout(grabHoldTimer);
  if (grabState) {
    const cell = cellFromPoint(cx, cy);
    const run = grabState;
    let placed = false;
    if (cell) {
      const ty = +cell.dataset.y;
      const newStart = (+cell.dataset.x) - run.pressIdx;
      const lineEl = els.sketchView.children[ty];
      const rowWidth = lineEl ? lineEl.children.length : 0;
      // Fit-check the whole run against the row; if it would overflow either
      // edge, snap it back to origin instead of clipping the face in half.
      if (newStart >= 0 && newStart + run.runChars.length <= rowWidth) {
        for (let i = 0; i < run.runChars.length; i++) {
          writeCell(ty, newStart + i, run.runChars[i]);
        }
        placed = true;
      }
    }
    if (!placed) {
      // Off-canvas or doesn't fit -> put it back where it was.
      for (let i = 0; i < run.runChars.length; i++) {
        writeCell(run.runY, run.runStart + i, run.runChars[i]);
      }
    }
    pushEditHistory(); // post-move state -> whole grab undoes in one step
    endGrab();
    return;
  }
  if (gesturePending) {
    startStroke();
    replaceCharAt(gesturePending.y, gesturePending.x);
    endStroke();
    gesturePending = null;
    return;
  }
  if (paintActive) endStroke();
}

els.sketchView.addEventListener('pointerdown', (e) => {
  if (Date.now() - lastTouchAt < 400) return; // ignore synthetic post-touch pointer
  const cell = cellFromPoint(e.clientX, e.clientY);
  if (!cell) return;
  gestureDown(e.clientX, e.clientY, cell);
  e.preventDefault();
});
els.sketchView.addEventListener('pointermove', (e) => {
  if (Date.now() - lastTouchAt < 400) return;
  if (!gesturePending && !paintActive && !grabState) return;
  gestureMove(e.clientX, e.clientY);
  e.preventDefault();
});
window.addEventListener('pointerup', (e) => {
  if (gesturePending || paintActive || grabState) gestureUp(e.clientX, e.clientY);
});
window.addEventListener('pointercancel', () => {
  clearTimeout(grabHoldTimer);
  if (grabState) {
    for (let i = 0; i < grabState.runChars.length; i++) {
      writeCell(grabState.runY, grabState.runStart + i, grabState.runChars[i]);
    }
    endGrab();
  }
  gesturePending = null; paintActive = false;
});

// Touch fallbacks (fire before pointer events; mark time so pointer skips dupes).
els.sketchView.addEventListener('touchstart', (e) => {
  lastTouchAt = Date.now();
  const t = e.touches[0]; if (!t) return;
  const cell = cellFromPoint(t.clientX, t.clientY);
  if (!cell) return;
  gestureDown(t.clientX, t.clientY, cell);
  e.preventDefault();
}, { passive: false });
els.sketchView.addEventListener('touchmove', (e) => {
  lastTouchAt = Date.now();
  const t = e.touches[0]; if (!t) return;
  if (!gesturePending && !paintActive && !grabState) return;
  gestureMove(t.clientX, t.clientY);
  e.preventDefault();
}, { passive: false });
els.sketchView.addEventListener('touchend', (e) => {
  lastTouchAt = Date.now();
  const t = e.changedTouches && e.changedTouches[0];
  if (t) gestureUp(t.clientX, t.clientY); else gestureUp(-1, -1);
});
els.sketchView.addEventListener('touchcancel', () => {
  clearTimeout(grabHoldTimer);
  if (grabState) {
    for (let i = 0; i < grabState.runChars.length; i++) {
      writeCell(grabState.runY, grabState.runStart + i, grabState.runChars[i]);
    }
    endGrab();
  }
  gesturePending = null; paintActive = false;
});

// Consolidated "Clear": reset to a FRESH blank 27×12 grid so there's always a
// paintable surface (replaces the old separate Blank + Clear buttons).
function fillBlankGrid() {
  pushEditHistory();
  const cols = 27, rows = 12;
  const line = '\u00A0'.repeat(cols);
  els.editArtInput.value = Array(rows).fill(line).join('\n');
  lastEditSnapshot = els.editArtInput.value;
  renderSketch(true);
  runAudit();
}
if (els.sketchFill) els.sketchFill.addEventListener('click', fillBlankGrid);
if (els.sketchClear) els.sketchClear.addEventListener('click', () => {
  if (!confirm('Clear the canvas and start over with a fresh blank grid?')) return;
  fillBlankGrid();
});
els.sketchUndo.addEventListener('click', undoEdit);
const textUndoBtn = document.getElementById('text-undo');
if (textUndoBtn) textUndoBtn.addEventListener('click', undoEdit);
if (els.sketchEraser) els.sketchEraser.addEventListener('click', () => setEraser(!eraserOn));

els.editArtInput.addEventListener('input', () => {
  // user typed/pasted directly — push a history snapshot of the value BEFORE
  // this change.
  if (!editHistorySuspend) {
    if (lastEditSnapshot !== els.editArtInput.value) {
      editHistory.push(lastEditSnapshot);
      if (editHistory.length > EDIT_HISTORY_MAX) editHistory.shift();
      lastEditSnapshot = els.editArtInput.value;
    }
  }
  // Only re-render sketch view when it's actually visible.
  if (isSketchMode()) renderSketch();
});

const textBlankBtn = document.getElementById('text-blank-canvas');
if (textBlankBtn) {
  textBlankBtn.addEventListener('click', () => {
    if (els.editArtInput.value && !confirm('Replace current art with a blank 27×12 canvas?')) return;
    pushEditHistory();
    const cols = 27, rows = 12;
    const line = '\u00A0'.repeat(cols);
    els.editArtInput.value = Array(rows).fill(line).join('\n');
    lastEditSnapshot = els.editArtInput.value;
    els.editArtInput.focus();
    els.editArtInput.setSelectionRange(0, 0);
    renderSketch();
    runAudit();
  });
}

// Ctrl/Cmd+Z anywhere in the edit modal undoes
document.addEventListener('keydown', (e) => {
  if (!els.edit.classList.contains('open')) return;
  const ctrl = e.ctrlKey || e.metaKey;
  if (ctrl && !e.shiftKey && (e.key === 'z' || e.key === 'Z')) {
    e.preventDefault();
    undoEdit();
  }
});

function toggleFavorite(ch) {
  const favs = loadFavorites();
  const idx = favs.indexOf(ch);
  if (idx >= 0) {
    favs.splice(idx, 1);
  } else if (favs.length < 10) {
    favs.push(ch);
  } else {
    // 10 slots full — drop the oldest, append the new one
    favs.shift();
    favs.push(ch);
  }
  saveFavorites(favs);
  buildFavoritesBar();
  refreshPaletteFavoriteState();
}
function removeFavorite(ch) {
  const favs = loadFavorites().filter((c) => c !== ch);
  saveFavorites(favs);
  buildFavoritesBar();
  refreshPaletteFavoriteState();
}
function refreshPaletteFavoriteState() {
  if (!els.charPalette) return;
  const favSet = new Set(loadFavorites());
  for (const b of els.charPalette.querySelectorAll('.palette-btn')) {
    b.classList.toggle('favorited', favSet.has(b.dataset.char));
  }
}

function attachLongPress(el, { onTap, onLong }) {
  let timer = null;
  let triggered = false;
  let pressed = false;
  let startX = 0, startY = 0;
  el.addEventListener('pointerdown', (e) => {
    pressed = true;
    triggered = false;
    startX = e.clientX;
    startY = e.clientY;
    timer = setTimeout(() => {
      if (pressed) {
        triggered = true;
        onLong();
        if (navigator.vibrate) navigator.vibrate(20);
      }
    }, 450);
  });
  // Only cancel if the finger actually moves a lot — small micro-movements
  // on touch screens should not abort a long-press.
  el.addEventListener('pointermove', (e) => {
    if (!pressed) return;
    if (Math.hypot(e.clientX - startX, e.clientY - startY) > 10) {
      pressed = false;
      if (timer) { clearTimeout(timer); timer = null; }
    }
  });
  el.addEventListener('pointerup', () => {
    const wasTriggered = triggered;
    const wasPressed = pressed;
    pressed = false;
    if (timer) { clearTimeout(timer); timer = null; }
    if (wasPressed && !wasTriggered) onTap();
  });
  el.addEventListener('pointercancel', () => {
    pressed = false;
    if (timer) { clearTimeout(timer); timer = null; }
  });
  // suppress the default context menu so right-click / 2-finger long-press
  // doesn't pop one up over our long-press handler
  el.addEventListener('contextmenu', (e) => e.preventDefault());
}

function isSketchMode() {
  return els.edit.classList.contains('drawing');
}

function handlePaletteSelection(ch) {
  setActiveBrush(ch);
  // In Sketch mode, just set the brush — user places the char by tapping the canvas.
  // In Text mode, also insert at cursor so it acts like a keyboard shortcut.
  if (!isSketchMode()) insertAtCursor(ch);
}

// A leading combining mark (e.g. a bare mouth/nose piece) has nothing to attach
// to inside a button, so show it on a dotted circle (◌). The inserted value is
// still the raw mark — only the on-screen label gets the placeholder base.
function paletteLabel(ch) {
  return /^\p{M}/u.test(ch) ? '◌' + ch : ch;
}

function buildPalette() {
  els.charPalette.innerHTML = '';
  const favs = new Set(loadFavorites());
  for (const group of PALETTE_GROUPS) {
    const section = document.createElement('div');
    section.className = 'palette-group';

    const heading = document.createElement('div');
    heading.className = 'palette-group-label';
    heading.textContent = group.label;
    section.appendChild(heading);

    const grid = document.createElement('div');
    grid.className = 'palette-grid' + (group.wide ? ' wide' : '');
    for (const ch of group.chars) {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'palette-btn' + (favs.has(ch) ? ' favorited' : '');
      b.textContent = paletteLabel(ch);
      b.dataset.char = ch;
      b.title = ch;
      attachLongPress(b, {
        onTap: () => handlePaletteSelection(ch),
        onLong: () => toggleFavorite(ch),
      });
      grid.appendChild(b);
    }
    section.appendChild(grid);
    els.charPalette.appendChild(section);
  }
}

function buildFavoritesBar() {
  els.favoritesBar.innerHTML = '';
  const favs = loadFavorites();
  for (let i = 0; i < 10; i++) {
    const ch = favs[i];
    const slot = document.createElement('button');
    slot.type = 'button';
    slot.className = 'fav-slot' + (ch ? ' filled' : ' empty');
    if (ch) {
      slot.textContent = paletteLabel(ch);
      attachLongPress(slot, {
        onTap: () => handlePaletteSelection(ch),
        onLong: () => removeFavorite(ch),
      });
    } else {
      slot.textContent = '';
      slot.disabled = true;
      slot.title = 'Empty — long-press a palette character to add';
    }
    els.favoritesBar.appendChild(slot);
  }
}

/* ============ 13  Save / delete / flag / verified ============ */
function newId() {
  return 'user-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 6);
}

/* Two-step save: tap Save -> name the piece in the sheet -> confirm. Keeps the
   Title/Tags fields out of the drawing view so the canvas + palette own it. */
function openSaveSheet() {
  if (!state.editor) return;
  if (!els.editArtInput.value.trim()) { alert('Add some art before saving.'); return; }
  const sheet = document.getElementById('save-sheet');
  if (sheet) sheet.classList.add('open');
  setTimeout(() => { if (els.editTitleInput) els.editTitleInput.focus(); }, 60);
}
function closeSaveSheet() {
  const sheet = document.getElementById('save-sheet');
  if (sheet) sheet.classList.remove('open');
}
async function commitSave() {
  if (!state.editor) return;
  const title = els.editTitleInput.value.trim();
  const tags = els.editTagsInput.value
    .split(',').map((t) => t.trim().toLowerCase()).filter(Boolean);
  let art = els.editArtInput.value;
  if (!title) { alert('Title is required'); els.editTitleInput.focus(); return; }
  if (!art.trim()) { alert('Art is required'); closeSaveSheet(); return; }

  art = spacesToNbsp(art);
  const { width, height } = measure(art);

  let piece;
  if (editing) {
    piece = { ...editing, title, tags, art, width, height };
  } else {
    piece = {
      id: newId(),
      title, tags, art, width, height,
      wosVerified: false,
    };
  }

  // Flat library is authoritative: replace the piece by id, or append if new.
  const prevLib = state.library;
  const prevDel = new Set(state.deletedIds);
  const next = state.library.slice();
  const existingIdx = next.findIndex((p) => p.id === piece.id);
  if (existingIdx >= 0) next[existingIdx] = piece;
  else next.push(piece);
  state.library = next;
  state.deletedIds.delete(piece.id); // editing un-deletes

  const confirmBtn = document.getElementById('save-confirm');
  if (confirmBtn) { confirmBtn.disabled = true; confirmBtn.textContent = 'Saving…'; }
  const r = await API.savePiece(piece, state.password);
  if (confirmBtn) { confirmBtn.disabled = false; confirmBtn.textContent = 'Save art'; }

  if (!r.ok) {
    state.library = prevLib;
    state.deletedIds = prevDel;
    alert('Save failed: ' + (r.error || 'unknown'));
    return;
  }
  cacheNow();
  recomputeMerged();
  clearDraft(); // successful save → autosaved draft is now obsolete
  closeSaveSheet();
  closeEdit();
  render();
  if (r.local) {
    alert('Saved on this device, but the server was unreachable — it won’t sync to other devices until you’re back online and save again.');
  } else {
    refresh(); // pull in anything another device changed
  }
}

els.editSave.addEventListener('click', openSaveSheet);
document.getElementById('save-confirm')?.addEventListener('click', commitSave);
document.getElementById('save-back')?.addEventListener('click', closeSaveSheet);

async function deletePiece(p) {
  if (!confirm(`Delete "${p.title}"?`)) return;
  const prevLib = state.library;
  const prevDel = new Set(state.deletedIds);

  state.library = state.library.filter((u) => u.id !== p.id);
  state.deletedIds.add(p.id); // tombstone so a redeploy can't bring it back

  const r = await API.deletePiece(p.id, state.password);
  if (!r.ok) {
    state.library = prevLib;
    state.deletedIds = prevDel;
    alert('Delete failed: ' + (r.error || 'unknown'));
    return;
  }
  cacheNow();
  recomputeMerged();
  render();
  if (!r.local) refresh();
}

async function toggleFlag(p, card, box, flag, note) {
  const wasFlagged = p.id in state.flags;
  // optimistic UI
  if (wasFlagged) {
    delete state.flags[p.id];
    card.classList.remove('flagged');
    box.textContent = '';
    flag.lastChild.textContent = ' flag';
  } else {
    state.flags[p.id] = '';
    card.classList.add('flagged');
    box.textContent = '🚩';
    flag.lastChild.textContent = ' flagged';
    note.value = '';
  }
  syncFlaggedTab();
  const r = await API.saveFlag(p.id, 'toggle');
  if (r && r.flagged !== undefined) {
    if (r.flagged) state.flags[p.id] = r.note || '';
    else delete state.flags[p.id];
    syncFlaggedTab();
  }
}

async function toggleVerified(p) {
  const prevLib = state.library;
  const next = state.library.slice();
  const idx = next.findIndex((u) => u.id === p.id);
  const base = idx >= 0 ? next[idx] : p;
  const updated = { ...base, wosVerified: !base.wosVerified };
  if (idx >= 0) next[idx] = updated;
  else next.push(updated);
  state.library = next;

  const r = await API.savePiece(updated, state.password);
  if (!r.ok) {
    state.library = prevLib;
    alert('Save failed: ' + (r.error || 'unknown'));
    return;
  }
  cacheNow();
  recomputeMerged();
  render();
}

/* ============ 14  Export art.js ============ */
els.btnExport.addEventListener('click', () => {
  if (!state.merged.length) return;
  const out = ['/**',
    ' * Frostline — bundled art library. AUTO-GENERATED.',
    ' * Regenerated ' + new Date().toISOString(),
    ' * NBSP (U+00A0) and ideographic-space (U+3000) preserved.',
    ' */',
    'const ART = [',
  ];
  for (const p of state.merged) {
    out.push('  {');
    out.push(`    id: ${JSON.stringify(p.id)},`);
    out.push(`    title: ${JSON.stringify(p.title)},`);
    out.push(`    tags: ${JSON.stringify(p.tags || [])},`);
    const m = measure(p.art);
    out.push(`    width: ${m.width}, height: ${m.height},`);
    // Use a normal JSON string (no template literals) to preserve special chars cleanly.
    out.push(`    art: ${JSON.stringify(p.art)},`);
    if (p.wosVerified) out.push('    wosVerified: true,');
    if (p.wosRisk) out.push('    wosRisk: true,');
    out.push('  },');
  }
  out.push('];');
  out.push('');
  out.push("if (typeof window !== 'undefined') window.ART = ART;");
  out.push('');

  const blob = new Blob([out.join('\n')], { type: 'text/javascript' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'art.js';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

/* ============ 15  Init ============ */
buildPalette();
buildFavoritesBar();
boot().catch((err) => {
  console.error('boot failed', err);
  renderEmpty('Failed to load. Refresh to try again.');
});
