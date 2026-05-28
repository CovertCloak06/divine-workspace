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
const WOS_MAX_WIDTH = 27;
const DEV_FALLBACK_PASSWORD = 'dev';

const DRAW_PALETTE = [
  // hearts
  '❤','💛','💚','💙','💜','💖','💓','♥',
  // stars & sparkles
  '⭐','★','✦','✧','✨','☆',
  // snow & flowers
  '❄','🌸','🌼','🌿','🌹','🌺','✿','❀','✾',
  // shapes solid
  '◆','●','■','▪','◼','▲','▼','▶','◀',
  // shapes outline
  '◇','○','□','▫','◻',
  // emoji squares
  '◾','◽','🟥','🟧','🟨','🟩','🟦','🟪',
  // box-drawing thick
  '━','┃','┏','┓','┗','┛','┣','┫','┳','┻','╋',
  // box-drawing thin
  '─','│','┌','┐','└','┘','┬','┴','┼',
  // rounded corners
  '╭','╮','╰','╯',
  // double-line
  '═','║','╔','╗','╚','╝',
  // diagonals
  '╱','╲',
  // blocks / shading
  '█','▇','▒','░','▔','▏','▂','▃',
  // food / flair
  '🍪','🍭','🍺','🎂','🎀',
  // fire / motion
  '🔥','💥','💨','⚡',
  // misc emoji
  '👀','🚨','⭕','🐾',
  // cat-face / katakana parts
  '∧','ω','ノ','つ','づ','⊂','⊃','・','。',
  // ideographic space (fills cells without showing a visible glyph)
  '　',
];

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

  edit: $('edit'),
  editTitle: $('edit-title'),
  editClose: $('edit-close'),
  editTitleInput: $('edit-title-input'),
  editTagsInput: $('edit-tags-input'),
  editArtInput: $('edit-art-input'),
  editAudit: $('edit-audit'),
  editCancel: $('edit-cancel'),
  editSave: $('edit-save'),

  favoritesBar: $('favorites-bar'),
  charPalette: $('char-palette'),

  sketchView: $('sketch-view'),
  sketchActiveChar: $('sketch-active-char'),
  sketchUndo: $('sketch-undo'),
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
// Single source of truth: the full library lives in Netlify Blobs (the
// `library` key, written by save-art). localStorage is only a last-known-good
// CACHE — never a competing store — so an unreachable backend shows your real
// library instead of silently falling back to the bundled seed.
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
  const payload = (lib) => JSON.stringify({ library: lib, deletedIds, ts: Date.now() });
  try {
    localStorage.setItem(CACHE_KEY, payload(library));
  } catch {
    // Quota hit (snapshots are large). Strip the PNGs — they regenerate from
    // `art` on load — and keep the text, which is what must never be lost.
    try {
      const lean = library.map((p) => { const { snapshot, ...rest } = p; return rest; });
      localStorage.setItem(CACHE_KEY, payload(lean));
    } catch { /* give up silently — server is still source of truth */ }
  }
}

const API = {
  async getArt() {
    try {
      const res = await fetch('/.netlify/functions/get-art', { cache: 'no-store' });
      if (res.ok) return await res.json();   // { library?, art?, deletedIds? }
      if (res.status === 404) return { empty: true };
    } catch { /* offline / unreachable */ }
    return { offline: true };
  },
  async _post(payload, password) {
    const res = await fetch('/.netlify/functions/save-art', {
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
      const res = await fetch('/.netlify/functions/get-flags');
      if (res.ok) return (await res.json()).flags || {};
    } catch { /* fall through */ }
    const stored = localStorage.getItem('frostline:flags');
    return stored ? JSON.parse(stored) : {};
  },
  async saveFlag(id, action, note) {
    try {
      const res = await fetch('/.netlify/functions/save-flags', {
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
      const res = await fetch('/.netlify/functions/auth', {
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

/* ============ 04  State + boot ============ */
const state = {
  bundled: [],           // copy of ART (seed/backup only — never overrides runtime)
  library: [],           // authoritative full list (from Blobs `library`)
  deletedIds: new Set(), // tombstones — stop future bundle adds from resurrecting deletes
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
  buildTagStrip();
  renderEmpty('Loading…');

  const [artData, flags] = await Promise.all([API.getArt(), API.getFlags()]);
  state.flags = flags || {};
  resolveLibrary(artData);
  state.booted = true;
  recomputeMerged();
  render();
}

function bundleSeed() {
  return state.bundled.map((p) => ({ ...p }));
}

// One-time merge used when migrating OLD server/cache data (user pieces +
// deletedIds layered over the bundle) into the new flat library.
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

// Decide the authoritative library from (in priority order) the server's
// `library`, an OLD server payload to migrate, the local cache, or the bundle.
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

  state.deletedIds = new Set(deletedIds);

  // Fold in genuinely-new bundled pieces (curated art added in a later deploy)
  // without resurrecting anything the editor deleted.
  const known = new Set(library.map((p) => p.id));
  for (const p of state.bundled) {
    if (!known.has(p.id) && !state.deletedIds.has(p.id)) {
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

// Cache the current library locally (last-known-good for offline loads).
function cacheNow() {
  writeCache(state.library, [...state.deletedIds]);
}

// Pull the authoritative library from the shared store so this device's view
// converges with edits made on other devices/users. Safe to call any time.
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

// Refresh when this device regains focus — picks up the other person's edits.
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') refresh();
});
window.addEventListener('focus', refresh);

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
  syncFlaggedTab();
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
}

function setActiveTag(tag) {
  state.activeTag = tag;
  for (const b of els.tagStrip.querySelectorAll('.tag')) {
    b.classList.toggle('active', b.dataset.tag === tag);
  }
  render();
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

  const width = p.width ?? measure(p.art).width;
  const height = p.height ?? measure(p.art).height;
  const overWide = width > WOS_MAX_WIDTH;

  if (overWide) {
    const warn = document.createElement('span');
    warn.className = 'card-warn';
    warn.title = 'Width exceeds WoS 27-char limit — may clip in chat';
    warn.textContent = '⚠';
    head.appendChild(warn);
  }

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

  // preview — a PNG snapshot of the art (display only; never the copy source)
  const prev = document.createElement('div');
  prev.className = 'preview';
  const showImg = (url) => {
    prev.innerHTML = '';
    const img = document.createElement('img');
    img.className = 'preview-img';
    img.src = url;
    img.alt = p.title || 'art';
    img.draggable = false;
    prev.appendChild(img);
  };
  if (p.snapshot) {
    prev.classList.add('has-img');
    showImg(p.snapshot);
  } else {
    // Legacy piece without a stored snapshot: render the text now, then
    // generate a snapshot in the background and swap it in (cached on the piece).
    const pre = document.createElement('pre');
    pre.textContent = p.art || '';
    prev.appendChild(pre);
    requestAnimationFrame(() => fitPreview(prev, pre));
    artToSnapshot(p.art).then((url) => {
      if (!url) return;
      p.snapshot = url;        // cache in-memory; persists when the piece is next saved
      prev.classList.add('has-img');
      showImg(url);
    }).catch(() => { /* keep the text fallback */ });
  }
  card.appendChild(prev);

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

function fitPreview(container, pre) {
  // Reset to base size and clear any prior transform.
  pre.style.transform = '';
  pre.style.fontSize = '';
  const base = 14; // base font size in px (matches .preview pre default)
  pre.style.fontSize = base + 'px';
  const cw = container.clientWidth - 24;
  const ch = container.clientHeight - 24;
  const pw = pre.scrollWidth;
  const ph = pre.scrollHeight;
  if (pw <= 0 || ph <= 0) return;
  const scale = Math.min(1, cw / pw, ch / ph);
  if (scale < 1) {
    // Adjust the actual font-size rather than CSS-transforming the rendered
    // glyphs — proportional fonts re-render cleanly at smaller sizes, whereas
    // transform: scale() crunches subpixels and visibly drifts alignment.
    pre.style.fontSize = (base * scale).toFixed(2) + 'px';
  }
}

/* ============ 05b  Snapshot — PNG of the art for card faces ============ */
// The card shows a *picture* of the art so it can never drift from the popup.
// The text itself (p.art) is always stored separately and is what Copy uses —
// the snapshot is display-only. Rendered to match the WoS lightbox preview.
const SNAP = {
  font: '"Noto Sans JP", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif',
  fontPx: 24, lineH: 1.25, pad: 18,
  bg: '#0f2033',   // matches --bg-wos (the lightbox preview tray)
  fg: '#d8e8f8',   // matches --ink-wos
};
let _snapCanvas = null;
let _fontsReady = false;
async function ensureFonts() {
  if (_fontsReady) return;
  try { if (document.fonts && document.fonts.ready) await document.fonts.ready; } catch { /* ignore */ }
  _fontsReady = true;
}
async function artToSnapshot(art) {
  if (!art) return '';
  await ensureFonts();
  const lines = String(art).split('\n');
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const canvas = _snapCanvas || (_snapCanvas = document.createElement('canvas'));
  const ctx = canvas.getContext('2d');
  const font = `${SNAP.fontPx}px ${SNAP.font}`;
  const lineHeightPx = SNAP.fontPx * SNAP.lineH;
  ctx.font = font;
  let maxW = 0;
  for (const ln of lines) maxW = Math.max(maxW, ctx.measureText(ln).width);
  const wCss = Math.ceil(maxW) + SNAP.pad * 2;
  const hCss = Math.ceil(lines.length * lineHeightPx) + SNAP.pad * 2;
  canvas.width = Math.max(1, Math.round(wCss * dpr));
  canvas.height = Math.max(1, Math.round(hCss * dpr));
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.fillStyle = SNAP.bg;
  ctx.fillRect(0, 0, wCss, hCss);
  ctx.font = font;            // re-set: resizing the canvas clears context state
  ctx.textBaseline = 'top';
  ctx.fillStyle = SNAP.fg;
  for (let i = 0; i < lines.length; i++) {
    ctx.fillText(lines[i], SNAP.pad, SNAP.pad + i * lineHeightPx);
  }
  return canvas.toDataURL('image/png');
}

/* ============ 06  Filtering + search ============ */
els.search.addEventListener('input', () => {
  state.query = els.search.value;
  render();
});
els.stripLeft.addEventListener('click', () => els.tagStrip.scrollBy({ left: -160, behavior: 'smooth' }));
els.stripRight.addEventListener('click', () => els.tagStrip.scrollBy({ left: 160, behavior: 'smooth' }));

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
  els.lbTitle.textContent = p.title || 'Untitled';
  const lines = (p.art || '').split('\n');
  const html = lines.map((l) => {
    const w = graphemeCount(l);
    const cls = w > WOS_MAX_WIDTH ? 'ov' : '';
    return cls
      ? `<span class="${cls}">${escapeHtml(l)}</span>`
      : escapeHtml(l);
  }).join('\n');
  els.lbPre.innerHTML = html;
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
  requestAnimationFrame(() => fitWosPreview(els.lbPre));
  els.lightbox.classList.add('open');
}
function fitWosPreview(pre) {
  pre.style.transform = '';
  pre.style.fontSize = '';
  const base = 20; // base font size in px (matches .wos-preview pre default)
  pre.style.fontSize = base + 'px';
  const parent = pre.parentElement;
  const cw = parent.clientWidth - 8;
  const pw = pre.scrollWidth;
  if (pw <= 0) return;
  const scale = Math.min(1, cw / pw);
  if (scale < 1) pre.style.fontSize = (base * scale).toFixed(2) + 'px';
}
function closeLightbox() { els.lightbox.classList.remove('open'); }
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
let tapTimes = [];
els.snowflake.addEventListener('click', () => {
  els.snowflake.classList.remove('spin');
  // force reflow to restart animation
  void els.snowflake.offsetWidth;
  els.snowflake.classList.add('spin');

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
    closeAuth();
    render();
    // Re-pull as an editor: this also migrates any legacy aggregate data into
    // per-piece records (and won't drop the old user pieces).
    refresh();
  } else {
    els.authError.textContent = r.error || 'Wrong password';
  }
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
  setMode('text');
  runAudit();
  renderSketch();
  els.edit.classList.add('open');
  setTimeout(() => els.editTitleInput.focus(), 50);
}
function openEdit(p) {
  editing = p;
  els.editTitle.textContent = 'Edit art';
  els.editTitleInput.value = p.title || '';
  els.editTagsInput.value = (p.tags || []).join(', ');
  els.editArtInput.value = p.art || '';
  resetEditHistory(p.art || '');
  setMode('text');
  runAudit();
  renderSketch();
  els.edit.classList.add('open');
}
function closeEdit() { els.edit.classList.remove('open'); }
els.editClose.addEventListener('click', closeEdit);
els.editCancel.addEventListener('click', closeEdit);
els.edit.addEventListener('click', (e) => {
  // Intentionally NOT closing on backdrop click — prevents accidental exit.
});
els.btnAdd.addEventListener('click', openAdd);

// Mode toggle (Type ⟷ Draw) — one editing surface, switched in place.
let editMode = 'text';
function setMode(name) {
  editMode = name === 'draw' ? 'draw' : 'text';
  const tgl = $('mode-toggle');
  if (tgl) {
    tgl.classList.toggle('is-draw', editMode === 'draw');
    for (const b of tgl.querySelectorAll('.mode-opt')) {
      const on = b.dataset.mode === editMode;
      b.classList.toggle('active', on);
      b.setAttribute('aria-pressed', on ? 'true' : 'false');
    }
  }
  for (const s of document.querySelectorAll('.edit-surface')) {
    s.hidden = s.dataset.surface !== editMode;
  }
  if (editMode === 'draw') { ensureBlankCanvas(); renderSketch(); }
}
{
  const tgl = $('mode-toggle');
  if (tgl) {
    for (const b of tgl.querySelectorAll('.mode-opt')) {
      b.addEventListener('click', () => setMode(b.dataset.mode));
    }
  }
}
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

const runAudit = () => {
  const text = els.editArtInput.value;
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
const editHistory = [];      // stack of prior art strings
const EDIT_HISTORY_MAX = 40;
let editHistorySuspend = false;
let lastEditSnapshot = '';

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
  // editHistory[last] is the current value; pop it and apply the one before.
  if (editHistory.length < 2) return;
  editHistory.pop();
  const prev = editHistory[editHistory.length - 1];
  editHistorySuspend = true;
  els.editArtInput.value = prev;
  lastEditSnapshot = prev;
  editHistorySuspend = false;
  renderSketch();
  runAudit();
}

function setActiveBrush(ch) {
  activeBrush = ch;
  if (els.sketchActiveChar) els.sketchActiveChar.textContent = ch;
}

function renderSketch() {
  if (!els.sketchView) return;
  const text = els.editArtInput.value;
  els.sketchView.innerHTML = '';
  if (!text) {
    const hint = document.createElement('div');
    hint.className = 'sketch-hint';
    hint.textContent = 'Switch to Sketch mode to start drawing on a 27×12 blank canvas.';
    els.sketchView.appendChild(hint);
    return;
  }
  const lines = text.split('\n');
  // For consistent painting, pad every line out to at least the widest line's
  // width with NBSP cells. Empty rows become full rows of paintable cells.
  const widest = Math.max(27, ...lines.map((l) => graphemeCount(l)));
  for (let y = 0; y < lines.length; y++) {
    const lineEl = document.createElement('div');
    lineEl.className = 'sketch-line';
    const gs = graphemes(lines[y]);
    // pad with NBSPs to the widest line so the row is fully paintable
    while (gs.length < widest) gs.push('\u00A0');
    for (let x = 0; x < gs.length; x++) {
      const span = document.createElement('span');
      span.className = 'sketch-char';
      span.textContent = gs[x] === '\u00A0' ? '\u00A0' : gs[x];
      // mark visually-empty cells so they still show a faint hover target
      if (gs[x] === '\u00A0' || gs[x] === ' ') span.classList.add('sketch-empty-cell');
      span.dataset.y = y;
      span.dataset.x = x;
      lineEl.appendChild(span);
    }
    els.sketchView.appendChild(lineEl);
  }
}

function replaceCharAt(y, x) {
  pushEditHistory();
  const text = els.editArtInput.value;
  const lines = text.split('\n');
  // Pad missing rows with NBSP so the user can paint into "off-canvas" rows.
  while (y >= lines.length) lines.push('');
  if (x < 0) return;
  const gs = graphemes(lines[y]);
  // Pad the row with NBSP up to x so the new char doesn't fall through.
  while (gs.length < x) gs.push('\u00A0');
  if (x < gs.length) {
    if (gs[x] === activeBrush) return;
    gs[x] = activeBrush;
  } else {
    gs.push(activeBrush);
  }
  lines[y] = gs.join('');
  els.editArtInput.value = lines.join('\n');
  lastEditSnapshot = els.editArtInput.value;
  renderSketch();
  runAudit();
}

let sketchPainting = false;
els.sketchView.addEventListener('pointerdown', (e) => {
  const target = document.elementFromPoint(e.clientX, e.clientY);
  const t = target && target.closest && target.closest('.sketch-char');
  if (!t) return;
  sketchPainting = true;
  replaceCharAt(+t.dataset.y, +t.dataset.x);
  e.preventDefault();
});
els.sketchView.addEventListener('pointermove', (e) => {
  if (!sketchPainting) return;
  const target = document.elementFromPoint(e.clientX, e.clientY);
  const t = target && target.closest && target.closest('.sketch-char');
  if (!t) return;
  replaceCharAt(+t.dataset.y, +t.dataset.x);
  e.preventDefault();
});
window.addEventListener('pointerup', () => { sketchPainting = false; });
window.addEventListener('pointercancel', () => { sketchPainting = false; });
// touch-event fallback for iOS Safari — pointer events sometimes don't reach
// fast-tap targets when scroll containers swallow the gesture.
els.sketchView.addEventListener('touchstart', (e) => {
  const t = e.touches[0];
  if (!t) return;
  const target = document.elementFromPoint(t.clientX, t.clientY);
  const cell = target && target.closest && target.closest('.sketch-char');
  if (!cell) return;
  sketchPainting = true;
  replaceCharAt(+cell.dataset.y, +cell.dataset.x);
  e.preventDefault();
}, { passive: false });
els.sketchView.addEventListener('touchmove', (e) => {
  if (!sketchPainting) return;
  const t = e.touches[0];
  if (!t) return;
  const target = document.elementFromPoint(t.clientX, t.clientY);
  const cell = target && target.closest && target.closest('.sketch-char');
  if (!cell) return;
  replaceCharAt(+cell.dataset.y, +cell.dataset.x);
  e.preventDefault();
}, { passive: false });
els.sketchView.addEventListener('touchend', () => { sketchPainting = false; });

els.sketchFill.addEventListener('click', () => {
  pushEditHistory();
  const cols = 27, rows = 12;
  const line = '\u00A0'.repeat(cols);
  els.editArtInput.value = Array(rows).fill(line).join('\n');
  lastEditSnapshot = els.editArtInput.value;
  renderSketch();
  runAudit();
});
els.sketchClear.addEventListener('click', () => {
  if (!els.editArtInput.value) return;
  if (!confirm('Clear all art?')) return;
  pushEditHistory();
  els.editArtInput.value = '';
  lastEditSnapshot = '';
  renderSketch();
  runAudit();
});
els.sketchUndo.addEventListener('click', undoEdit);

els.editArtInput.addEventListener('input', () => {
  // user typed/pasted directly — push a history snapshot of the value BEFORE
  // this change. We mimic this by snapshotting on every focus and after a
  // 600ms idle window.
  if (!editHistorySuspend) {
    if (lastEditSnapshot !== els.editArtInput.value) {
      editHistory.push(lastEditSnapshot);
      if (editHistory.length > EDIT_HISTORY_MAX) editHistory.shift();
      lastEditSnapshot = els.editArtInput.value;
    }
  }
  renderSketch();
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
  return editMode === 'draw';
}

function handlePaletteSelection(ch) {
  setActiveBrush(ch);
  // In Sketch mode, just set the brush — user places the char by tapping the canvas.
  // In Text mode, also insert at cursor so it acts like a keyboard shortcut.
  if (!isSketchMode()) insertAtCursor(ch);
}

function buildPalette() {
  els.charPalette.innerHTML = '';
  const favs = new Set(loadFavorites());
  for (const ch of DRAW_PALETTE) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'palette-btn' + (favs.has(ch) ? ' favorited' : '');
    b.textContent = ch;
    b.dataset.char = ch;
    b.title = ch;
    attachLongPress(b, {
      onTap: () => handlePaletteSelection(ch),
      onLong: () => toggleFavorite(ch),
    });
    els.charPalette.appendChild(b);
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
      slot.textContent = ch;
      attachLongPress(slot, {
        onTap: () => handlePaletteSelection(ch),
        onLong: () => removeFavorite(ch),
      });
    } else {
      slot.textContent = '+';
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

els.editSave.addEventListener('click', async () => {
  if (!state.editor) return;
  const title = els.editTitleInput.value.trim();
  const tags = els.editTagsInput.value
    .split(',').map((t) => t.trim().toLowerCase()).filter(Boolean);
  let art = els.editArtInput.value;
  if (!title) { alert('Title is required'); return; }
  if (!art.trim()) { alert('Art is required'); return; }

  art = spacesToNbsp(art);
  const { width, height } = measure(art);

  els.editSave.disabled = true;
  els.editSave.textContent = 'Saving…';

  // Freeze a picture of exactly what this art renders to (display only).
  let snapshot = '';
  try { snapshot = await artToSnapshot(art); } catch { /* card falls back to text */ }

  let piece;
  if (editing) {
    piece = { ...editing, title, tags, art, width, height, snapshot };
  } else {
    piece = { id: newId(), title, tags, art, width, height, wosVerified: false, snapshot };
  }

  const prevLib = state.library;
  const prevDel = new Set(state.deletedIds);
  const next = state.library.slice();
  const idx = next.findIndex((p) => p.id === piece.id);
  if (idx >= 0) next[idx] = piece;
  else next.push(piece);
  state.library = next;
  state.deletedIds.delete(piece.id); // editing un-deletes

  const r = await API.savePiece(piece, state.password);
  els.editSave.disabled = false;
  els.editSave.textContent = 'Save';

  if (!r.ok) {
    state.library = prevLib;
    state.deletedIds = prevDel;
    alert('Save failed: ' + (r.error || 'unknown'));
    return;
  }
  cacheNow();
  recomputeMerged();
  closeEdit();
  render();
  if (r.local) {
    alert('Saved on this device, but the server was unreachable — it won’t sync to other devices until you’re back online and save again.');
  } else {
    refresh(); // pull in anything the other device changed
  }
});

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
  const idx = state.library.findIndex((u) => u.id === p.id);
  if (idx < 0) return;
  const prevLib = state.library;
  const next = state.library.slice();
  const updated = { ...next[idx], wosVerified: !next[idx].wosVerified };
  next[idx] = updated;
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
