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
/* WoS chat rendering spec (v1.0):
 *  - WoS uses a PROPORTIONAL font, so raw char count is meaningless.
 *  - Effective hard wrap ≈ 34 VISUAL columns.
 *  - Safe target = 30 VISUAL columns.
 *  - Visual width is a weighted sum:  narrow=0.5, medium=1.0, wide=1.5
 * These constants drive the audit zones AND the editor canvas size. */
const WOS_SAFE_WIDTH   = 30;   // <= 30 visual cols  -> safe
const WOS_HARD_LIMIT   = 34;   // 31..34 -> warn, > 34 -> fail
const WOS_DEFAULT_COLS = 30;   // default canvas char-grid width (cols)
const WOS_DEFAULT_ROWS = 12;   // default canvas rows
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
  themeTabs: $('theme-tabs'),
  activeThemeRow: $('active-theme-row'),
  activeThemeChip: $('active-theme-chip'),
  activeThemeLabel: $('active-theme-label'),

  edit: $('edit'),
  editTitle: $('edit-title'),
  editClose: $('edit-close'),
  editTitleInput: $('edit-title-input'),
  editTagsInput: $('edit-tags-input'),
  editDraftInput: $('edit-draft-input'),
  editArtInput: $('edit-art-input'),
  editPreview: $('edit-preview'),
  editAudit: $('edit-audit'),
  widthMeter: $('wos-width-meter'),
  widthVal: $('wos-width-val'),
  widthHint: $('wos-width-hint'),
  editCancel: $('edit-cancel'),
  editSave: $('edit-save'),

  favoritesBar: $('favorites-bar'),
  charPalette: $('char-palette'),

  sketchView: $('sketch-view'),
  sketchActiveChar: $('sketch-active-char'),
  sketchUndo: $('sketch-undo'),
  sketchRedo: $('sketch-redo'),
  sketchEraser: $('sketch-eraser'),
  sketchClear: $('sketch-clear'),
  sketchSelect: $('sketch-select'),
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
/* WoS visual-width model (per rendering spec v1.0).
 *  narrow chars contribute 0.5, wide chars 1.5, everything else 1.0.
 *  Single source of truth for both the audit zones and the warn-line UI. */
const WOS_NARROW_CHARS = new Set(['.', ',', ':', ';', "'", '`', '|', '!', 'i', 'l']);
const WOS_WIDE_CHARS   = new Set(['M', 'W', '@', '#', '%', '&']);
function wosCharWidth(ch) {
  if (WOS_NARROW_CHARS.has(ch)) return 0.5;
  if (WOS_WIDE_CHARS.has(ch))   return 1.5;
  return 1.0;
}
function wosVisualWidth(line) {
  let w = 0;
  for (const ch of line) w += wosCharWidth(ch);
  return w;
}
function wosWidestVisualLine(art) {
  if (!art) return 0;
  let max = 0;
  for (const line of art.split('\n')) {
    const w = wosVisualWidth(line);
    if (w > max) max = w;
  }
  return max;
}
/* Returns one of: { level: 'safe' | 'warn' | 'fail', width: <number> } */
function wosClassifyWidth(art) {
  const w = wosWidestVisualLine(art);
  if (w > WOS_HARD_LIMIT) return { level: 'fail', width: w };
  if (w > WOS_SAFE_WIDTH) return { level: 'warn', width: w };
  return { level: 'safe', width: w };
}

function spacesToNbsp(s) {
  return s.replace(/ /g, '\u00A0');
}

/* Strip trailing rows that are entirely whitespace (space, tab, NBSP).
 * Used by commitSave() before persisting \u2014 Draw mode primes the canvas
 * as a tall NBSP grid, and rows the user never painted into would
 * otherwise ship as a dead vertical void below the art. Returns the
 * input unchanged if no trailing blanks are found. Does not strip
 * leading or inner blank rows (they can carry intentional positioning)
 * and does not trim per-row trailing whitespace (it can carry alignment
 * padding for centered renders). */
function trimTrailingBlankRows(s) {
  const lines = s.split('\n');
  const blank = (row) => {
    for (let i = 0; i < row.length; i++) {
      const c = row[i];
      if (c !== ' ' && c !== '\t' && c !== '\u00A0') return false;
    }
    return true;
  };
  while (lines.length > 0 && blank(lines[lines.length - 1])) lines.pop();
  return lines.join('\n');
}

/* Render-time normalizer: returns art with trailing all-blank rows
 * stripped, so old pieces saved before the save-time trim (wos24) also
 * display without their dead NBSP void. Both the card grid and the
 * lightbox route through this. Editor textarea loads the raw value
 * directly \u2014 Draw mode needs the canvas headroom, and trim happens
 * again at save. */
function displayArt(raw) {
  return trimTrailingBlankRows(raw || '');
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
  // Width audit per WoS rendering spec v1.0.
  // WoS uses a proportional font with effective wrap ~34 visual columns.
  // We measure visual width via the weighted model (narrow 0.5 / med 1.0 / wide 1.5)
  // and report against the safe (30) and hard (34) thresholds.
  const widthCheck = wosClassifyWidth(text);
  if (widthCheck.level === 'fail') {
    issues.push({
      level: 'error',
      msg: `Artwork exceeds supported chat width (${widthCheck.width.toFixed(1)} of max ${WOS_HARD_LIMIT} visual columns). It will wrap or misalign in chat — trim wide rows.`,
    });
  } else if (widthCheck.level === 'warn') {
    issues.push({
      level: 'warn',
      msg: `Artwork is approaching the chat wrap limit (${widthCheck.width.toFixed(1)} of safe ${WOS_SAFE_WIDTH} visual columns; hard cap ${WOS_HARD_LIMIT}).`,
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

/* ---- Anonymous usage counters (feeds the admin-only analytics panel) ----
 * Fire-and-forget: never blocks the UI, silently no-ops when the backend is
 * unreachable, and sends only an aggregate event + (for copies) the piece id —
 * no identifiers or personal data. */
function trackEvent(kind, id) {
  try {
    fnUrl('track').then((url) => {
      fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(id ? { event: kind, id } : { event: kind }),
        keepalive: true,
      }).catch(() => {});
    }).catch(() => {});
  } catch { /* ignore */ }
}
// Count one visit per device per UTC day so a single user refreshing doesn't
// inflate the numbers (roughly "unique daily visitors").
function trackVisitOncePerDay() {
  let day;
  try { day = new Date().toISOString().slice(0, 10); } catch { day = 'x'; }
  try {
    const key = 'frostline:tracked:' + day;
    if (localStorage.getItem(key)) return;
    localStorage.setItem(key, '1');
  } catch { /* no storage — just count it */ }
  trackEvent('visit');
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
  /* wos46: POST /change-password. Verifies currentPassword server-side
   * and rotates the editor password into Netlify Blob storage. */
  async changePassword(currentPassword, newPassword) {
    try {
      const res = await fetch(await fnUrl('change-password'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ currentPassword, newPassword }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.ok) return { ok: true };
      return { ok: false, status: res.status, error: data.error || 'Server error' };
    } catch (err) {
      return { ok: false, error: 'Network error' };
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

  // Count this visit (anonymous, deduped per day) for the admin analytics panel.
  trackVisitOncePerDay();

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
  // Also fold in tombstones recorded in the LOCAL CACHE. A delete that didn't
  // reach the server (offline, a transient failure, or Blobs list() lag) writes
  // its tombstone to the cache but not the server. On the NEXT page reload the
  // server returns a fresh `library` that lacks the tombstone, and (before this)
  // the cache tombstones were only read in the offline branch — so the deleted
  // piece came back ("I deleted it but it reappeared"). Unioning them here keeps
  // the delete sticky across reloads; needsPersist re-sends it so the tombstone
  // eventually reaches the server and the piece is deleted everywhere.
  const cached = readCache();
  if (cached && Array.isArray(cached.deletedIds)) {
    for (const id of cached.deletedIds) {
      if (!tomb.has(id)) { tomb.add(id); needsPersist = true; }
    }
  }
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
  buildThemeTabs();
  syncFlaggedTab();
  syncActiveThemeChip();
}

/* wos40: themes render as a horizontal tab strip above the search bar.
   Replaces the previous drawer Themes section entirely. */
function buildThemeTabs() {
  if (!els.themeTabs) return;
  els.themeTabs.innerHTML = '';
  for (const tag of TAGS) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'theme-tab';
    b.textContent = tag;
    b.dataset.tag = tag;
    b.setAttribute('role', 'tab');
    if (tag === state.activeTag) {
      b.classList.add('active');
      b.setAttribute('aria-selected', 'true');
    }
    b.addEventListener('click', () => {
      const next = tag === state.activeTag ? 'all' : tag;
      setActiveTag(next);
    });
    els.themeTabs.appendChild(b);
  }
  attachThemeTabsScroll();
}

/* wos51: scroll the theme-tabs strip via click-drag, arrow buttons, mouse
   wheel, or touch swipe — no visible scrollbar (per user). Injects a
   .theme-tabs-wrap wrapper around the strip and prepends/appends arrow
   buttons that only show when there is overflow on that side. */
function attachThemeTabsScroll() {
  const strip = els.themeTabs;
  if (!strip) return;

  // Ensure wrapper exists. Wrap the strip lazily on first run.
  let wrap = strip.parentElement && strip.parentElement.classList.contains('theme-tabs-wrap')
    ? strip.parentElement
    : null;
  if (!wrap) {
    wrap = document.createElement('div');
    wrap.className = 'theme-tabs-wrap';
    strip.parentNode.insertBefore(wrap, strip);
    wrap.appendChild(strip);
  }

  // Ensure arrow buttons exist (idempotent).
  let leftBtn = wrap.querySelector('.theme-tab-arrow.left');
  let rightBtn = wrap.querySelector('.theme-tab-arrow.right');
  if (!leftBtn) {
    leftBtn = document.createElement('button');
    leftBtn.type = 'button';
    leftBtn.className = 'theme-tab-arrow left';
    leftBtn.setAttribute('aria-label', 'Scroll themes left');
    leftBtn.innerHTML = '&#x2039;';
    wrap.insertBefore(leftBtn, strip);
  }
  if (!rightBtn) {
    rightBtn = document.createElement('button');
    rightBtn.type = 'button';
    rightBtn.className = 'theme-tab-arrow right';
    rightBtn.setAttribute('aria-label', 'Scroll themes right');
    rightBtn.innerHTML = '&#x203A;';
    wrap.appendChild(rightBtn);
  }

  // Wire scroll behaviors once per element.
  if (strip._scrollWired) return;
  strip._scrollWired = true;

  // -- Click-drag scroll --
  let drag = null;
  let dragStartedMoving = false;
  const onPointerDown = (e) => {
    if (e.button !== 0 && e.pointerType === 'mouse') return; // only left mouse
    if (e.target.closest('.theme-tab-arrow')) return;
    drag = { x: e.clientX, scrollLeft: strip.scrollLeft, pointerId: e.pointerId };
    dragStartedMoving = false;
  };
  const onPointerMove = (e) => {
    if (!drag || e.pointerId !== drag.pointerId) return;
    const dx = e.clientX - drag.x;
    if (!dragStartedMoving && Math.abs(dx) > 4) {
      dragStartedMoving = true;
      strip.classList.add('dragging');
      try { strip.setPointerCapture(drag.pointerId); } catch (_) {}
    }
    if (dragStartedMoving) {
      strip.scrollLeft = drag.scrollLeft - dx;
      e.preventDefault();
    }
  };
  const onPointerUp = (e) => {
    if (!drag) return;
    const moved = dragStartedMoving;
    strip.classList.remove('dragging');
    try { strip.releasePointerCapture(drag.pointerId); } catch (_) {}
    drag = null;
    // If we dragged the strip, swallow the click so the tab under the
    // pointer doesn't get activated as a click.
    if (moved) {
      const swallow = (ev) => { ev.stopPropagation(); ev.preventDefault(); };
      strip.addEventListener('click', swallow, { capture: true, once: true });
    }
  };

  // -- Mouse wheel → horizontal --
  const onWheel = (e) => {
    if (strip.scrollWidth <= strip.clientWidth) return;
    if (e.shiftKey) return;
    if (Math.abs(e.deltaX) > Math.abs(e.deltaY)) return;
    e.preventDefault();
    strip.scrollLeft += e.deltaY;
  };

  // -- Arrow buttons (one-screen step per click) --
  const stepBy = (dir) => {
    const step = Math.max(120, strip.clientWidth * 0.7);
    strip.scrollTo({ left: strip.scrollLeft + dir * step, behavior: 'smooth' });
  };
  leftBtn.addEventListener('click', () => stepBy(-1));
  rightBtn.addEventListener('click', () => stepBy(1));

  // -- Position state + arrow visibility --
  const onScroll = () => {
    const max = strip.scrollWidth - strip.clientWidth;
    if (max <= 1) {
      strip.dataset.scroll = 'none';
      leftBtn.hidden = rightBtn.hidden = true;
      return;
    }
    if (strip.scrollLeft <= 1) strip.dataset.scroll = 'start';
    else if (strip.scrollLeft >= max - 1) strip.dataset.scroll = 'end';
    else strip.dataset.scroll = 'mid';
    leftBtn.hidden  = strip.scrollLeft <= 1;
    rightBtn.hidden = strip.scrollLeft >= max - 1;
  };

  strip.addEventListener('pointerdown', onPointerDown);
  strip.addEventListener('pointermove', onPointerMove);
  strip.addEventListener('pointerup', onPointerUp);
  strip.addEventListener('pointercancel', onPointerUp);
  strip.addEventListener('wheel', onWheel, { passive: false });
  strip.addEventListener('scroll', onScroll, { passive: true });
  window.addEventListener('resize', onScroll);

  // Initial state — wait for layout.
  requestAnimationFrame(onScroll);
}

function syncActiveThemeChip() {
  if (!els.activeThemeRow) return;
  const t = state.activeTag;
  /* wos38: hide the active-tag chip while viewing the Drafts destination —
   * the dedicated banner above the gallery already labels the section, and
   * showing the raw "__drafts" string in a topical-tag-style chip implied
   * drafts was a tag in the strip (it isn't). */
  const isDefault = !t || t === 'all' || t === '__drafts';
  if (isDefault) {
    els.activeThemeRow.hidden = true;
    return;
  }
  els.activeThemeRow.hidden = false;
  const flagged = t === '__flagged';
  els.activeThemeChip.classList.toggle('flagged', flagged);
  const flagCount = liveFlagCount();
  els.activeThemeLabel.textContent = flagged ? `flagged (${flagCount})` : t;
}

/* Returns the number of flags whose piece still exists in the live library.
 * Counting Object.keys(state.flags).length is wrong because flags persist
 * across art deletions — a piece can be removed from state.merged but its
 * flag stays in state.flags until explicitly cleared. Using that raw count
 * for UI labels produces a "flagged (39)" badge that doesn't match the 6
 * cards the user actually sees in the flagged view. This helper intersects
 * flags with the actual rendered library so the label matches reality. */
function liveFlagCount() {
  const flags = state.flags || {};
  const library = state.merged || [];
  if (library.length === 0) return 0;
  let n = 0;
  for (const p of library) if (p && p.id in flags) n++;
  return n;
}

function syncFlaggedTab() {
  let existing = els.tagStrip.querySelector('.tag.flagged-tab');
  const flagCount = liveFlagCount();
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

  // wos40: mirror the flagged tag into the theme-tabs strip.
  if (els.themeTabs) {
    let tabFlagged = els.themeTabs.querySelector('.theme-tab.flagged-tab');
    if (shouldShow) {
      if (!tabFlagged) {
        tabFlagged = document.createElement('button');
        tabFlagged.type = 'button';
        tabFlagged.className = 'theme-tab flagged-tab';
        tabFlagged.dataset.tag = '__flagged';
        tabFlagged.setAttribute('role', 'tab');
        tabFlagged.addEventListener('click', () => {
          setActiveTag(state.activeTag === '__flagged' ? 'all' : '__flagged');
        });
        els.themeTabs.appendChild(tabFlagged);
      }
      tabFlagged.textContent = `flagged (${flagCount})`;
      tabFlagged.classList.toggle('active', state.activeTag === '__flagged');
    } else if (tabFlagged) {
      tabFlagged.remove();
    }
  }
  syncActiveThemeChip();
}

/* wos35: admin-only "Drafts" tab. Mirror of syncFlaggedTab but for in-progress
 * art. Counts non-deleted pieces with .draft truthy. */
function liveDraftCount() {
  const library = state.merged || [];
  let n = 0;
  for (const p of library) if (p && p.draft) n++;
  return n;
}
/* wos38: Drafts is its own ADMIN DESTINATION, not a tag in the tag strip.
 * The strip is for topical filters of the published library (hearts,
 * animals, etc); drafts are work-in-progress and live in a separate place
 * accessed only from the admin drawer. This syncs:
 *   - the drawer's dedicated Drafts button (creates/removes/updates count)
 *   - a banner shown ABOVE the gallery while __drafts is active so the user
 *     knows they're in a separate WIP section (with a Back-to-library link).
 * Anything that used to push Drafts into the tag strip is removed. */
function syncDraftsTab() {
  const count = liveDraftCount();
  const shouldShow = state.editor && count > 0;

  // Remove any stale tag-strip entry (this used to live here in wos35).
  if (els.tagStrip) {
    const stale = els.tagStrip.querySelector('.tag.drafts-tab');
    if (stale) stale.remove();
  }

  // Dedicated drawer entry (separate "destination").
  const drawerBtn = document.getElementById('drawer-drafts-btn');
  if (drawerBtn) {
    drawerBtn.hidden = !shouldShow;
    drawerBtn.textContent = `📝 Drafts (${count})`;
    drawerBtn.classList.toggle('active', state.activeTag === '__drafts');
  }

  // If the active view IS drafts but admin lost access or count dropped to 0,
  // bounce back to the published library so the user is never stranded.
  if (state.activeTag === '__drafts' && !shouldShow) state.activeTag = 'all';

  // Banner above the gallery while we're in the drafts destination.
  const banner = document.getElementById('drafts-banner');
  if (banner) {
    const isDrafts = state.editor && state.activeTag === '__drafts';
    banner.hidden = !isDrafts;
  }
}

function setActiveTag(tag) {
  state.activeTag = tag;
  for (const b of els.tagStrip.querySelectorAll('.tag')) {
    b.classList.toggle('active', b.dataset.tag === tag);
  }
  if (els.themeTabs) {
    for (const b of els.themeTabs.querySelectorAll('.theme-tab')) {
      const on = b.dataset.tag === tag;
      b.classList.toggle('active', on);
      if (on) b.setAttribute('aria-selected', 'true');
      else b.removeAttribute('aria-selected');
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
  // wos35: drafts are private WIPs — never shown to non-admins, hidden by
  // default in admin view too. Visible only in the admin-only "__drafts" tab.
  if (state.activeTag === '__drafts') {
    if (!state.editor) {
      list = [];               // public has no access to the drafts view
    } else {
      list = list.filter((p) => p && p.draft);
    }
  } else {
    list = list.filter((p) => p && !p.draft);
    if (state.activeTag === '__flagged') {
      list = list.filter((p) => p.id in state.flags);
    } else if (state.activeTag !== 'all') {
      list = list.filter((p) => Array.isArray(p.tags) && p.tags.includes(state.activeTag));
    }
  }
  const q = state.query.trim().toLowerCase();
  if (q) {
    list = list.filter((p) => {
      const hay = (p.title + ' ' + (p.tags || []).join(' ')).toLowerCase();
      return hay.includes(q);
    });
  }
  // Safe Mode — public content protection (the content-warning gate defaults it
  // ON). Hides pieces flagged as mature so minors don't see reported / NSFW art.
  // Only editors are exempt (they see everything, including the admin flagged
  // view). We deliberately do NOT exempt the "__flagged" tag here: a stale
  // '__flagged' activeTag restored from a prior editor session (loadSession runs
  // before auth) would otherwise drop a public visitor straight onto flagged
  // content with the filter bypassed. For a non-editor the flagged view simply
  // ends up empty, which is the safe outcome.
  if (document.documentElement.classList.contains('safe-mode') && !state.editor) {
    const flags = state.flags || {};
    list = list.filter((p) => !(p.id in flags));
  }
  return list;
}

function render() {
  syncFlaggedTab();
  syncDraftsTab();
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
  if (p.draft) {
    const draftPill = document.createElement('span');
    draftPill.className = 'draft-pill';
    draftPill.textContent = 'DRAFT';
    title.appendChild(draftPill);
  }
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
  pre.textContent = displayArt(p.art);
  prev.appendChild(pre);
  card.appendChild(prev);

  // wos86: the art renders RIGID (white-space: pre — it never wraps), then
  // fitArt scales the whole block to fit. So the ⚠ badge can no longer mean
  // "wrapped in preview" (impossible now); it means "wider than the WoS bubble"
  // — i.e. this piece WILL wrap in the game. Decide that from the true unwrapped
  // width at base size, then scale the picture down to fit the card.
  requestAnimationFrame(() => {
    pre.style.fontSize = '14px';
    const emPx = parseFloat(getComputedStyle(pre).fontSize) || 14;
    const wosCols = parseFloat(
      getComputedStyle(document.documentElement).getPropertyValue('--wos-cols'),
    ) || 17;
    warn.style.display = (pre.scrollWidth > wosCols * emPx + 1) ? '' : 'none';
    fitArt(prev, pre, 14, { height: true });
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

  // wos35: footer is one flex row anchored at the bottom of the card. Before,
  // Copy was in normal flow while WoS + flag were position:absolute, so the
  // gap between Copy and the bottom row varied with chip count / flag state
  // (the "random spacing" the user noticed).
  const footer = document.createElement('div');
  footer.className = 'card-footer';

  // wos badge (left). Use text checkmark not the ✅ emoji so the badge
  // doesn't balloon to ~35px tall on mobile (the colorful emoji ignores
  // font-size and renders at its natural icon size).
  const wos = document.createElement('span');
  wos.className = 'wos-badge ' + (p.wosVerified ? 'verified' : 'unverified');
  // wos88: force TEXT presentation of the checkmark (U+FE0E). Since wos87 loads
  // Noto Color Emoji, a bare ✓ was falling back to a COLOR-emoji glyph — taller
  // than text, which made verified cards' footers ~11px taller and broke the
  // uniform card height. The variation selector keeps it a flat text ✓.
  wos.textContent = p.wosVerified ? '✓︎ WoS' : '? WoS';
  wos.addEventListener('click', (e) => {
    if (!state.editor) return;
    e.stopPropagation();
    toggleVerified(p);
  });
  footer.appendChild(wos);

  // copy (center). Text-only — same reason as badge above.
  const copy = document.createElement('button');
  copy.className = 'copy-btn';
  copy.textContent = 'Copy';
  copy.addEventListener('click', (e) => {
    e.stopPropagation();
    copyArt(p.art, copy, false, p.id);
  });
  footer.appendChild(copy);

  // flag corner (right)
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
  footer.appendChild(flag);

  card.appendChild(footer);

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

// wos86: re-fit every rigid art block when its container can change size — the
// grid reflows columns on viewport resize / orientation change, and a rigid
// (non-wrapping) block must be re-scaled to keep fitting. Debounced so a drag-
// resize doesn't thrash. Also re-fits the open lightbox.
function refitAllArt() {
  document.querySelectorAll('.grid .card .preview').forEach((prev) => {
    const pre = prev.querySelector('.art-render');
    if (pre) fitArt(prev, pre, 14, { height: true });
  });
  if (els.lightbox && els.lightbox.classList.contains('open') && els.lbPre) {
    fitArt(els.lbPre.parentElement, els.lbPre, 20);
  }
}
let _refitTimer = null;
window.addEventListener('resize', () => {
  clearTimeout(_refitTimer);
  _refitTimer = setTimeout(refitAllArt, 120);
});
// wos86: the art fits at render time using whatever fonts are loaded then. When
// the web fonts (Roboto / Noto Sans / Noto Color Emoji) finish loading, glyph
// widths change — re-fit so the rigid block re-scales to the real metrics
// instead of staying sized for the fallback font (avoids a slightly-off scale
// on first paint / cold cache).
if (document.fonts && document.fonts.ready) {
  document.fonts.ready.then(() => { try { refitAllArt(); } catch {} });
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

// wos38: drawer "📝 Drafts" CTA — switches the gallery to the Drafts
// destination (admin only) and closes the drawer.
const draftsCta = document.getElementById('drawer-drafts-btn');
if (draftsCta) draftsCta.addEventListener('click', () => {
  if (!state.editor) return;
  setActiveTag(state.activeTag === '__drafts' ? 'all' : '__drafts');
  closeDrawer();
});
// "← Back to library" inside the drafts banner returns to the published view.
const draftsBack = document.getElementById('drafts-banner-back');
if (draftsBack) draftsBack.addEventListener('click', () => setActiveTag('all'));
/* Settings accordion — tap a section head to expand/collapse its body. Only
   one section is open by default (Themes); future sections (Character
   Management, Chat) will hang off the same pattern. */
const drawerSectionsRoot = document.getElementById('drawer-sections');
if (drawerSectionsRoot) {
  drawerSectionsRoot.addEventListener('click', (e) => {
    const head = e.target.closest('.drawer-section-head');
    if (!head) return;
    const section = head.closest('.drawer-section');
    if (!section) return;
    const willOpen = !section.classList.contains('is-open');
    section.classList.toggle('is-open', willOpen);
    head.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
    if (willOpen && section.dataset.section === 'analytics') loadAnalytics();
  });
}

/* === Admin analytics panel ===================================================
 * Fetches /get-stats (Bearer = editor password) and renders visits-per-day +
 * most-copied art. Editor-only (the drawer section is hidden unless unlocked,
 * and the server rejects the request without a valid password). */
async function loadAnalytics() {
  const statusEl = document.getElementById('analytics-status');
  const contentEl = document.getElementById('analytics-content');
  if (!statusEl || !contentEl) return;
  if (!state.editor || !state.password) {
    statusEl.hidden = false;
    statusEl.textContent = 'Unlock the editor to view analytics.';
    contentEl.hidden = true;
    return;
  }
  statusEl.hidden = false;
  statusEl.textContent = 'Loading…';
  contentEl.hidden = true;
  try {
    const res = await fetch(await fnUrl('get-stats'), {
      headers: { 'Authorization': 'Bearer ' + state.password },
      cache: 'no-store',
    });
    if (res.status === 404) { statusEl.textContent = 'Analytics not deployed yet.'; return; }
    if (res.status === 401) { statusEl.textContent = 'Not authorized.'; return; }
    if (!res.ok) { statusEl.textContent = 'Could not load stats.'; return; }
    renderAnalytics(await res.json());
    statusEl.hidden = true;
    contentEl.hidden = false;
  } catch {
    statusEl.textContent = 'Offline — analytics need the network.';
  }
}

function renderAnalytics(stats) {
  const contentEl = document.getElementById('analytics-content');
  if (!contentEl) return;
  const byDay = stats.visitsByDay || {};
  // Last 14 days, oldest→newest, filling gaps with 0.
  const days = [];
  const today = new Date();
  for (let i = 13; i >= 0; i--) {
    const d = new Date(today.getTime() - i * 86400000).toISOString().slice(0, 10);
    days.push({ d, n: byDay[d] || 0 });
  }
  const maxN = Math.max(1, ...days.map((x) => x.n));
  const bars = days.map((x) => {
    const h = Math.round((x.n / maxN) * 46);
    const label = x.d.slice(5); // MM-DD
    return `<div class="an-bar" title="${x.d}: ${x.n}"><span class="an-bar-fill" style="height:${h}px"></span><span class="an-bar-n">${x.n || ''}</span><span class="an-bar-d">${label}</span></div>`;
  }).join('');

  // Resolve titles for the most-copied pieces from the loaded library.
  const lib = (state.merged && state.merged.length ? state.merged : state.library) || [];
  const titleFor = (id) => {
    const p = lib.find((q) => q && q.id === id);
    return p ? (p.title || id) : id;
  };
  const top = (stats.topCopied || []).slice(0, 10);
  const rows = top.length
    ? top.map((c, i) => `<li><span class="an-rank">${i + 1}</span><span class="an-title">${escapeHtml(titleFor(c.id))}</span><span class="an-count">${c.n}</span></li>`).join('')
    : '<li class="an-empty">No copies recorded yet.</li>';

  contentEl.innerHTML = `
    <div class="an-totals">
      <div class="an-total"><span class="an-total-n">${stats.visitsTotal || 0}</span><span class="an-total-l">total visits</span></div>
      <div class="an-total"><span class="an-total-n">${stats.copyTotal || 0}</span><span class="an-total-l">total copies</span></div>
    </div>
    <div class="an-section-label">Visits · last 14 days</div>
    <div class="an-chart">${bars}</div>
    <div class="an-section-label">Most-copied art</div>
    <ol class="an-top">${rows}</ol>`;
}

const analyticsRefreshBtn = document.getElementById('analytics-refresh');
if (analyticsRefreshBtn) analyticsRefreshBtn.addEventListener('click', loadAnalytics);

/* === Feedback form ===========================================================
 * Public bug-feedback form in the Settings drawer. POSTs to /api/submit-bug,
 * which fans out to Anthropic (triage) -> Netlify Blobs (storage) -> GitHub
 * Issue (tracking) -> Discord webhook (push to phone). Each downstream
 * integration is optional on the server side; on the client we just render
 * whatever the function returns.
 */
const APP_VERSION = 'wos88';

function captureFeedbackContext() {
  let editorState = 'locked';
  if (typeof state !== 'undefined') {
    if (state.editor) editorState = 'unlocked';
  }
  const ctx = {
    appVersion: APP_VERSION,
    url: location.pathname + location.search,
    userAgent: navigator.userAgent.slice(0, 200),
    viewport: { w: window.innerWidth, h: window.innerHeight, dpr: window.devicePixelRatio || 1 },
    activeTag: (typeof state !== 'undefined' && state.activeTag) || null,
    editorState,
    drawing: !!document.getElementById('edit')?.classList.contains('drawing'),
    timestamp: new Date().toISOString(),
  };
  try {
    const theme = document.body.className.match(/\bfx-shape-(\w+)/);
    if (theme) ctx.cardShape = theme[1];
  } catch {}
  return ctx;
}

function renderTriageStatus(triage, issue) {
  if (!triage || triage.skipped || triage.error) {
    const note = triage?.skipped
      ? ' (AI triage not configured on this deploy)'
      : triage?.error
      ? ` (triage error: ${triage.error})`
      : '';
    return `Report sent.${note}${issue ? ` Tracked as <a href="${issue.url}" target="_blank" rel="noopener">issue #${issue.number}</a>.` : ''}`;
  }
  const sev = triage.severity || 'untriaged';
  const sevClass = `sev-${sev}`;
  const safeSummary = (triage.summary || '').replace(/[<>&]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;' }[c]));
  const safeArea = (triage.area || '').replace(/[<>&]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;' }[c]));
  let html = `<strong>Report sent.</strong> Claude pre-read it:`;
  html += `<div class="triage-row"><span class="sev-badge ${sevClass}">${sev}</span>${safeArea ? `<span>${safeArea}</span>` : ''}</div>`;
  if (safeSummary) html += `<div style="margin-top:6px;">${safeSummary}</div>`;
  if (issue) html += `<div style="margin-top:8px;font-size:12px;color:rgba(255,255,255,0.7);">Tracked as <a href="${issue.url}" target="_blank" rel="noopener" style="color:#9bd1ff;">issue #${issue.number}</a></div>`;
  return html;
}

/* wos46: in-app password rotation. Verifies the current password
 * server-side, hashes the new one (PBKDF2-SHA256) into Netlify Blob.
 * On success, updates state.password + remembered password so the user
 * stays logged in seamlessly. */
(function wireChangePasswordForm() {
  const form = document.getElementById('change-pw-form');
  if (!form) return;
  const curEl = document.getElementById('change-pw-current');
  const newEl = document.getElementById('change-pw-new');
  const confEl = document.getElementById('change-pw-confirm');
  const status = document.getElementById('change-pw-status');
  const submit = document.getElementById('change-pw-submit');

  const setStatus = (msg, kind) => {
    status.textContent = msg || '';
    status.className = 'change-pw-status' + (kind ? ' ' + kind : '');
  };

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    setStatus('', '');
    const current = curEl.value;
    const next = newEl.value;
    const confirm = confEl.value;
    if (!current || !next || !confirm) {
      setStatus('All fields required.', 'err'); return;
    }
    if (next.length < 4 || next.length > 128) {
      setStatus('New password must be 4–128 characters.', 'err'); return;
    }
    if (next !== confirm) {
      setStatus('New password and confirmation do not match.', 'err'); return;
    }
    if (next === current) {
      setStatus('New password must differ from current.', 'err'); return;
    }

    submit.disabled = true;
    setStatus('Updating…', '');
    const result = await API.changePassword(current, next);
    submit.disabled = false;

    if (!result.ok) {
      setStatus(result.error || 'Failed to change password.', 'err');
      return;
    }

    // Success: rotate the password the client uses for subsequent writes.
    state.password = next;
    // If the user previously chose "stay unlocked", update the remembered
    // value so they don't get bounced to the lock screen on next visit.
    try {
      if (localStorage.getItem(REMEMBER_KEY)) {
        localStorage.setItem(REMEMBER_KEY, next);
      }
    } catch {}

    curEl.value = newEl.value = confEl.value = '';
    setStatus('Password changed. The old password no longer works.', 'ok');
  });
})();

(function wireFeedbackForm() {
  const form = document.getElementById('feedback-form');
  if (!form) return;
  const descEl = document.getElementById('feedback-description');
  const reporterEl = document.getElementById('feedback-reporter');
  const submitBtn = document.getElementById('feedback-submit');
  const statusEl = document.getElementById('feedback-status');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const description = (descEl.value || '').trim();
    if (!description) {
      statusEl.className = 'feedback-status is-error';
      statusEl.textContent = 'A short description is required.';
      descEl.focus();
      return;
    }

    submitBtn.disabled = true;
    statusEl.className = 'feedback-status';
    statusEl.textContent = 'Sending…';

    try {
      const url = await fnUrl('submit-bug');
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          description,
          reporter: (reporterEl.value || '').trim() || null,
          context: captureFeedbackContext(),
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        statusEl.className = 'feedback-status is-error';
        statusEl.textContent = data.error || `Server returned ${res.status}.`;
        submitBtn.disabled = false;
        return;
      }
      statusEl.className = 'feedback-status is-success';
      statusEl.innerHTML = renderTriageStatus(data.triage, data.issue);
      descEl.value = '';
      submitBtn.disabled = false;
    } catch (err) {
      statusEl.className = 'feedback-status is-error';
      statusEl.textContent = 'Could not reach the server. Check your connection and try again.';
      submitBtn.disabled = false;
    }
  });
})();
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
  els.lbPre.textContent = displayArt(p.art);
  const m = measure(displayArt(p.art));
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
  els.lbCopy.onclick = () => copyArt(p.art, els.lbCopy, true, p.id);
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
async function copyArt(text, btn, isLightbox, id) {
  if (id) trackEvent('copy', id);   // anonymous most-copied counter (admin stats)
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
  btn.textContent = '✓︎ Copied!';
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
  cta.textContent = '✓︎ Copied!';
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
  // wos35: new art defaults to Draft so the library only shows finished work
  // by default. Admin can untick to publish straight away.
  if (els.editDraftInput) els.editDraftInput.checked = true;
  syncStatusToggle();
  // Auto-prepare a blank canvas so the cursor / sketch view both work immediately.
  const cols = WOS_DEFAULT_COLS, rows = WOS_DEFAULT_ROWS;
  const line = '\u00A0'.repeat(cols);
  els.editArtInput.value = Array(rows).fill(line).join('\n');
  resetEditHistory(els.editArtInput.value);
  closeSaveSheet();
  resetBrushState();          // fresh canvas: nothing armed (safe). Toggling keeps it after.
  toggleDraw(true); // new art opens straight into the draw canvas (primary feature)
  runAudit();
  renderSketch();
  els.edit.classList.add('open');
  // After the modal is open, see if a draft is waiting for this target.
  tryRestoreDraft();
  // Modal just became visible; refresh the dynamic group label with real rects.
  requestAnimationFrame(refreshGroupLabel);
}
/* wos42: status toggle (Draft / Published) in the save sheet.
   The buttons drive the hidden #edit-draft-input checkbox, which the
   save handler already reads — so this is purely UI. */
function syncStatusToggle() {
  const isDraft = els.editDraftInput ? !!els.editDraftInput.checked : false;
  const opts = document.querySelectorAll('.status-opt');
  for (const o of opts) {
    const on = (o.dataset.status === 'draft') === isDraft;
    o.classList.toggle('active', on);
    o.setAttribute('aria-pressed', String(on));
  }
}
for (const opt of document.querySelectorAll('.status-opt')) {
  opt.addEventListener('click', () => {
    if (!els.editDraftInput) return;
    els.editDraftInput.checked = (opt.dataset.status === 'draft');
    syncStatusToggle();
  });
}

function openEdit(p) {
  editing = p;
  els.editTitle.textContent = 'Edit art';
  els.editTitleInput.value = p.title || '';
  els.editTagsInput.value = (p.tags || []).join(', ');
  if (els.editDraftInput) els.editDraftInput.checked = !!p.draft;
  syncStatusToggle();
  els.editArtInput.value = p.art || '';
  resetEditHistory(p.art || '');
  closeSaveSheet();
  resetBrushState();
  toggleDraw(true); // wos45: existing art also opens straight into Draw mode
  runAudit();
  renderSketch();
  els.edit.classList.add('open');
  tryRestoreDraft();
  requestAnimationFrame(refreshGroupLabel);
}
function closeEdit() {
  els.edit.classList.remove('open');
  els.edit.classList.remove('drawing');
  els.edit.classList.remove('typing');
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
  const cols = WOS_DEFAULT_COLS, rows = WOS_DEFAULT_ROWS;
  const line = '\u00A0'.repeat(cols);
  els.editArtInput.value = Array(rows).fill(line).join('\n');
  lastEditSnapshot = els.editArtInput.value;
  resetEditHistory(els.editArtInput.value);
  runAudit();
}

/* wos30: the editor is ALWAYS in the unified `.drawing` workspace layout;
 * this only switches the INPUT sub-mode. on=true -> draw-input (paint the
 * canvas). on=false -> type-input (`.typing`: keyboard into the text box).
 * Brush state is NOT reset here (resetBrushState handles that once per open),
 * so flipping Type<->Draw keeps whatever you had selected. */
function toggleDraw(on) {
  const drawing = !!on;
  els.edit.classList.add('drawing');
  els.edit.classList.toggle('typing', !drawing);
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
    updateBrushChip();
    // wos82 typeable canvas: seat the text cursor at the top-left and hand focus
    // to the hidden keyboard proxy so you can type on the canvas immediately —
    // no separate "Type" mode to switch into.
    placeCursorAt(0, 0);
    focusTypeProxy();
  } else if (els.editArtInput) {
    // entering type-input: hand focus to the text box for keyboard entry, with
    // the caret at the very start (row 0, col 0) and scrolled to the top. The
    // blank canvas is a full 12-row × 30-NBSP block, so the textarea's default
    // end-caret would otherwise land in the bottom-right cell and scroll the
    // view to the bottom — the "cursor starts at the bottom" bug.
    setTimeout(() => {
      try {
        els.editArtInput.focus();
        els.editArtInput.setSelectionRange(0, 0);
        els.editArtInput.scrollTop = 0;
        els.editArtInput.scrollLeft = 0;
      } catch {}
    }, 0);
  }
}

/* Reset the paint brush to a clean, safe state. Called once per editor open
 * (NOT on every toggle) so a fresh canvas starts with nothing armed, while
 * flipping Type<->Draw preserves whatever brush you had selected. */
function resetBrushState() {
  activeBrush = null;
  eraserOn = false;
  canvasMode = true;
  selectMode = false;     // wos36: leave Select mode on a fresh open
  clearSelection();
  if (els.sketchSelect) updateSelectChip();
  if (els.sketchEraser) els.sketchEraser.classList.remove('active');
  if (els.charPalette) els.charPalette.querySelectorAll('.palette-btn.brush-active').forEach((b) => b.classList.remove('brush-active'));
  if (els.favoritesBar) els.favoritesBar.querySelectorAll('.fav-slot.brush-active').forEach((b) => b.classList.remove('brush-active'));
  updateBrushChip();
}

function updateWidthMeter(text) {
  if (!els.widthMeter) return;
  const m = els.widthMeter;
  m.hidden = false;
  const r = wosClassifyWidth(text);
  m.classList.remove('safe', 'warn', 'fail');
  m.classList.add(r.level);
  if (els.widthVal) els.widthVal.textContent = r.width.toFixed(1);
  if (els.widthHint) {
    els.widthHint.textContent =
      r.level === 'fail' ? `⛔ exceeds ${WOS_HARD_LIMIT}-col cap` :
      r.level === 'warn' ? `⚠ warn zone (cap ${WOS_HARD_LIMIT})` :
      '';
  }
}

const runAudit = () => {
  const text = els.editArtInput.value;
  if (els.editPreview) {
    els.editPreview.textContent = text;
    requestAnimationFrame(() => fitArt(els.editPreview.parentElement, els.editPreview, 16));
  }
  updateWidthMeter(text);
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
let activeBrush = null;   // wos27: no default brush — user must pick one to paint
let eraserOn = false;
let canvasMode = true;    // wos27: true = Canvas mode (taps don't paint); false = Drawing/Input
const editHistory = [];      // wos49: stack of POST-edit art-string snapshots (top = current state)
const redoHistory = [];      // stack of states popped by undo (redo)
const EDIT_HISTORY_MAX = 200;
let editHistorySuspend = false;
let lastEditSnapshot = '';
let strokeStartSnapshot = null; // captured at pointerdown / touchstart
let grabStartSnapshot = null;   // captured at grab start
let lastTouchAt = 0;            // ms timestamp of most recent touch event

// wos49: free-form canvas caps — generous so users almost never hit them, but
// finite so a runaway gesture can't create a 100,000-row canvas.
const FREEFORM_MAX_ROWS = 50;
const FREEFORM_MAX_COLS = 80;

function syncHistoryButtons() {
  if (els.sketchUndo) els.sketchUndo.disabled = editHistory.length < 2;
  if (els.sketchRedo) els.sketchRedo.disabled = redoHistory.length < 1;
}
// wos49: push the CURRENT (post-edit) value onto history. Undo pops the top
// to revert to the previous edit's snapshot. This makes undo granular per
// keystroke (input event) and per paint stroke (pointerdown..pointerup).
function pushEditHistory() {
  if (editHistorySuspend) return;
  const v = els.editArtInput.value;
  if (editHistory.length && editHistory[editHistory.length - 1] === v) return;
  editHistory.push(v);
  if (editHistory.length > EDIT_HISTORY_MAX) editHistory.shift();
  redoHistory.length = 0;
  lastEditSnapshot = v;
  syncHistoryButtons();
}
function resetEditHistory(v) {
  editHistory.length = 0;
  redoHistory.length = 0;
  editHistory.push(v || '');
  lastEditSnapshot = v || '';
  syncHistoryButtons();
}
function undoEdit() {
  if (editHistory.length < 2) return;
  // wos49: pop the CURRENT state, expose the previous one. Symmetric model.
  const current = editHistory.pop();
  redoHistory.push(current);
  const prev = editHistory[editHistory.length - 1];
  editHistorySuspend = true;
  els.editArtInput.value = prev;
  lastEditSnapshot = prev;
  editHistorySuspend = false;
  renderSketch(true);
  runAudit();
  syncHistoryButtons();
}
function redoEdit() {
  if (!redoHistory.length) return;
  const next = redoHistory.pop();
  editHistory.push(next);
  editHistorySuspend = true;
  els.editArtInput.value = next;
  lastEditSnapshot = next;
  editHistorySuspend = false;
  renderSketch(true);
  runAudit();
  syncHistoryButtons();
}

/* wos27: Canvas/Drawing mode + no-default-brush.
 *   canvasMode true  → "Canvas mode": taps don't paint (long-press grab-move
 *                      and scrolling still work, so you can rearrange/look
 *                      without dropping unwanted characters).
 *   canvasMode false → "Drawing/Input mode": taps paint activeBrush (or erase).
 * The chip (#sketch-active-char) is the toggle button between the two. Picking
 * a palette char selects it AND drops you into Drawing mode so you can paint
 * right away. */
function canPaint() {
  return !canvasMode && (eraserOn || !!activeBrush);
}

function updateBrushChip() {
  const chip = els.sketchActiveChar;
  if (!chip) return;
  chip.classList.toggle('canvas-mode', canvasMode);
  chip.classList.toggle('eraser', !canvasMode && eraserOn);
  chip.classList.toggle('empty', !canvasMode && !eraserOn && !activeBrush);
  if (canvasMode) {
    chip.textContent = '✋';
    chip.title = 'Canvas mode — tap to switch to Drawing';
    chip.setAttribute('aria-pressed', 'false');
  } else if (eraserOn) {
    chip.textContent = '⌫';
    chip.title = 'Drawing mode (eraser) — tap to switch to Canvas';
    chip.setAttribute('aria-pressed', 'true');
  } else if (activeBrush) {
    chip.textContent = activeBrush;
    chip.title = 'Drawing mode — tap to switch to Canvas';
    chip.setAttribute('aria-pressed', 'true');
  } else {
    chip.textContent = '·';
    chip.title = 'Pick a character from the palette to draw';
    chip.setAttribute('aria-pressed', 'true');
  }
}

function toggleCanvasMode() {
  canvasMode = !canvasMode;
  updateBrushChip();
}

function setActiveBrush(ch) {
  activeBrush = ch;
  eraserOn = false;     // choosing a paint char clears the eraser
  canvasMode = false;   // ...and enters Drawing mode so you can paint immediately
  if (els.sketchEraser) els.sketchEraser.classList.remove('active');
  updateBrushChip();
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
  if (eraserOn) canvasMode = false;   // eraser is a Drawing-mode tool
  if (els.sketchEraser) els.sketchEraser.classList.toggle('active', eraserOn);
  updateBrushChip();
}

/* wos28: the canvas renders each line as ONE continuous text node — so the
 * browser shapes it and picks fonts exactly like the card's
 * <pre class="art-render"> does. The old per-<span>-per-character structure
 * forced isolated shaping/fallback on every glyph, which is why the editor
 * never matched the card. Hit-testing is now geometry-based (measureLineCells
 * + cellFromPoint) so painting still targets the right cell on a proportional
 * font. */
let gridW = 0, gridH = 0;   // current canvas dimensions (cols, rows)
let overlayEl = null;       // drop-target highlight layer (grab-move)

function lineModelText(rawLine) {
  // Pad the model line to gridW NBSPs for DISPLAY only (never written back to
  // the model) so the whole grid stays paintable to the right of the art.
  const gs = (rawLine != null) ? graphemes(rawLine) : [];
  while (gs.length < gridW) gs.push(' ');
  return gs.join('');
}
function buildLineEl(y, rawLine) {
  const lineEl = document.createElement('div');
  lineEl.className = 'sketch-line';
  lineEl.dataset.y = y;
  lineEl.textContent = lineModelText(rawLine);
  lineEl._cells = null; // lazy boundary cache (x offsets relative to the line)
  return lineEl;
}
function renderLine(y) {
  const lineEl = els.sketchView.children[y];
  if (!lineEl || !lineEl.classList.contains('sketch-line')) return;
  const lines = els.editArtInput.value.split('\n');
  lineEl.textContent = lineModelText(lines[y]);
  lineEl._cells = null; // glyph widths shift on a proportional font — re-measure lazily
}
function ensureOverlay() {
  overlayEl = document.createElement('div');
  overlayEl.className = 'sketch-overlay';
  els.sketchView.appendChild(overlayEl);
  renderWrapGuides();
}
// wos49: thin vertical guides at WoS safe / hard wrap boundaries so users
// see where their art will wrap in the WoS chat bubble — visual cue only,
// never blocks input. Reference width is measured from a hidden 34×'o' line
// so the guide position is content-independent (matches the "average char"
// row, regardless of what the user actually typed).
let _wrapGuideRefCache = null;
function measureWrapGuideRef() {
  const probe = document.createElement('div');
  probe.className = 'sketch-line';
  probe.style.visibility = 'hidden';
  probe.style.position = 'absolute';
  probe.style.top = '-9999px';
  probe.style.whiteSpace = 'pre';
  probe.textContent = 'o'.repeat(WOS_HARD_LIMIT);
  els.sketchView.appendChild(probe);
  const w = probe.getBoundingClientRect().width;
  probe.remove();
  return w / WOS_HARD_LIMIT;
}
function renderWrapGuides() {
  if (!overlayEl || !els.sketchView) return;
  overlayEl.querySelectorAll('.sketch-wrap-guide').forEach(g => g.remove());
  const firstLine = els.sketchView.querySelector('.sketch-line');
  if (!firstLine) return;
  if (!_wrapGuideRefCache) _wrapGuideRefCache = measureWrapGuideRef();
  const refWidth = _wrapGuideRefCache;
  if (!refWidth) return;
  const viewRect = els.sketchView.getBoundingClientRect();
  const offsetX = firstLine.getBoundingClientRect().left - viewRect.left;
  const safePx = offsetX + (WOS_SAFE_WIDTH * refWidth);
  const hardPx = offsetX + (WOS_HARD_LIMIT * refWidth);
  const make = (cls, px) => {
    const g = document.createElement('div');
    g.className = 'sketch-wrap-guide ' + cls;
    g.style.left = px + 'px';
    g.setAttribute('aria-hidden', 'true');
    overlayEl.appendChild(g);
  };
  make('safe', safePx);
  make('hard', hardPx);
}

function renderSketch(force) {
  if (!els.sketchView) return;
  if (!force && !isSketchMode()) return;
  const text = els.editArtInput.value;
  els.sketchView.innerHTML = '';
  // wos49: free-form input — render at least an empty row so first tap lands
  // somewhere. Expand to fit existing content; cap at FREEFORM_MAX_ROWS.
  const lines = text ? text.split('\n') : [''];
  let actualWidest = 0;
  for (const l of lines) actualWidest = Math.max(actualWidest, graphemeCount(l));
  gridW = Math.max(WOS_DEFAULT_COLS, actualWidest);
  gridH = Math.min(FREEFORM_MAX_ROWS, Math.max(WOS_DEFAULT_ROWS, lines.length));
  for (let y = 0; y < gridH; y++) {
    els.sketchView.appendChild(buildLineEl(y, lines[y] != null ? lines[y] : ''));
  }
  ensureOverlay();
  // wos36: the overlay was just rebuilt empty — restore selection highlight.
  if (selectMode && selection.size) renderSelectionHighlight();
  // wos82: the view was wiped, taking the cursor box with it — re-place it.
  // Guard on `.drawing` (set the moment the canvas is active) rather than
  // `.open`, since openAdd renders once more before it adds the `.open` class.
  if (els.edit && els.edit.classList.contains('drawing')) positionCursor();
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

  // wos28: a paint can shift glyph widths across the rest of the row on a
  // proportional font, so re-render the whole affected line (cheap) instead
  // of mutating one cell in place.
  // wos29: a multi-grapheme brush pushing past the current gridW would leave
  // other rows with stale padding — full re-render so gridW + every line's
  // padding recompute together.
  // wos49: free-form input — when paint lands in a new row (y >= gridH) or
  // pushes a row beyond gridW, the per-line update has no element to write
  // to. Force a full re-render so the new cell becomes part of the grid and
  // future taps in that region work too.
  const newRowLen = graphemes(lines[y]).length;
  const grewBeyondGrid = (y >= gridH) || (lines.length > gridH) || (newRowLen > gridW);
  if (grewBeyondGrid || (brush.length > 1 && newRowLen > gridW)) renderSketch(true);
  else renderLine(y);
  runAudit();
}

function startStroke() {
  // wos49: snapshot pre-stroke value but DON'T push history yet — the push
  // happens at endStroke once the stroke is complete, so the snapshot at
  // history's top is the POST-stroke state (granular per-stroke undo).
  strokeStartSnapshot = els.editArtInput.value;
}
function endStroke() {
  paintActive = false;
  if (strokeStartSnapshot !== null && strokeStartSnapshot !== els.editArtInput.value) {
    pushEditHistory();
    // wos84: paints/tap-placements set editArtInput.value programmatically (the
    // native 'input' event is suppressed), so the input-driven autosave never
    // fires. Schedule a draft write here so click-placed / dragged art survives
    // an in-modal Close/Cancel (which don't trigger pagehide/visibilitychange).
    debouncedAutosave();
  }
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

function measureLineCells(lineEl) {
  // Cache each grapheme cell as {left,right} pixel offsets RELATIVE to the
  // line element, so the cache survives canvas scrolling. Recomputed lazily
  // after any edit (renderLine nulls _cells).
  if (lineEl._cells) return lineEl._cells;
  const node = lineEl.firstChild;
  const cells = [];
  if (node && node.nodeType === 3) {
    const lineLeft = lineEl.getBoundingClientRect().left;
    const gs = graphemes(node.nodeValue);
    const range = document.createRange();
    let cu = 0;
    for (let i = 0; i < gs.length; i++) {
      const len = gs[i].length;
      range.setStart(node, cu);
      range.setEnd(node, cu + len);
      const r = range.getBoundingClientRect();
      cells.push({ left: r.left - lineLeft, right: r.right - lineLeft });
      cu += len;
    }
  }
  lineEl._cells = cells;
  return cells;
}
// wos28/49: pixel -> {y,x} grid cell by geometry. Free-form: extrapolates
// beyond rendered grid bounds (right of last cell, below last row) so taps
// in empty space create new cells. Bounded by FREEFORM_MAX_ROWS/COLS.
function cellFromPoint(cx, cy) {
  const view = els.sketchView;
  if (!view || gridH === 0) return null;
  // Walk children: collect first/last row and detect exact-Y hit.
  let lineEl = null;
  let firstRowEl = null;
  let lastRowEl = null;
  let rowHeight = 0;
  for (let y = 0; y < gridH; y++) {
    const el = view.children[y];
    if (!el || !el.classList || !el.classList.contains('sketch-line')) continue;
    if (!firstRowEl) firstRowEl = el;
    lastRowEl = el;
    const r = el.getBoundingClientRect();
    if (!rowHeight && r.height) rowHeight = r.height;
    if (cy >= r.top && cy <= r.bottom) { lineEl = el; break; }
  }
  // FREE-FORM Y: tap below the last row extrapolates to a new row index.
  if (!lineEl && lastRowEl) {
    const lastRect = lastRowEl.getBoundingClientRect();
    if (cy > lastRect.bottom && rowHeight > 0) {
      const extra = Math.floor((cy - lastRect.bottom) / rowHeight) + 1;
      const newY = (+lastRowEl.dataset.y) + extra;
      if (newY >= FREEFORM_MAX_ROWS) return null;
      return { y: newY, x: cellXFromPoint(lastRowEl, cx) };
    }
    if (firstRowEl) {
      const firstRect = firstRowEl.getBoundingClientRect();
      if (cy < firstRect.top) lineEl = firstRowEl;
    }
  }
  if (!lineEl) return null;
  const y = +lineEl.dataset.y;
  return { y, x: cellXFromPoint(lineEl, cx) };
}
// Compute the column index for a given pixel x on a specific line element.
// Free-form: returns indices beyond cells.length-1 when cx is right of the
// last rendered cell, using the cell width as the extrapolation step.
function cellXFromPoint(lineEl, cx) {
  const cells = measureLineCells(lineEl);
  if (!cells.length) return 0;
  const lineRect = lineEl.getBoundingClientRect();
  const cxRel = cx - lineRect.left;
  if (cxRel < cells[0].left) return 0;
  const lastCell = cells[cells.length - 1];
  if (cxRel >= lastCell.right) {
    const cellWidth = (lastCell.right - lastCell.left) || 12;
    const extra = Math.floor((cxRel - lastCell.right) / cellWidth) + 1;
    const newX = cells.length - 1 + extra;
    return Math.min(FREEFORM_MAX_COLS - 1, newX);
  }
  let lo = 0, hi = cells.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (cxRel < cells[mid].left) hi = mid - 1;
    else if (cxRel >= cells[mid].right) lo = mid + 1;
    else return mid;
  }
  return Math.min(cells.length - 1, Math.max(0, lo));
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
  renderLine(y);
  runAudit();
}

/* wos36: precise SELECTION mode. selectMode ON => taps/box-drags build a set
 * of exactly the cells the user wants; long-press a selected cell drags ONLY
 * those. Gives full control so you never drag "half a gun" attached to a cat. */
let selectMode = false;
let selection = new Set();   // "y,x" keys of currently-selected cells
let marqueeActive = false;   // true while dragging a selection box

/* Find the connected 2D shape of non-blank cells that includes the pressed
 * cell — 4-way (orthogonal only) so corner-touching neighbors are left behind.
 * Used by the quick long-press grab when NOT in Select mode. Returns null if
 * the pressed cell is itself blank. */
function findShape(startY, startX) {
  const lines = els.editArtInput.value.split('\n');
  if (startY < 0 || startY >= lines.length) return null;
  const lineGS = lines.map(graphemes);
  if (startX < 0 || startX >= lineGS[startY].length || isBlankCell(lineGS[startY][startX])) return null;
  const visited = new Set();
  const cells = [];
  const stack = [[startY, startX]];
  let minY = startY, maxY = startY, minX = startX, maxX = startX;
  // 4-way neighbors only — diagonals were dragging unrelated chars along.
  const NEIGHBORS = [[-1, 0], [1, 0], [0, -1], [0, 1]];
  while (stack.length) {
    const [y, x] = stack.pop();
    const key = y + ',' + x;
    if (visited.has(key)) continue;
    if (y < 0 || y >= lineGS.length) continue;
    const row = lineGS[y];
    if (x < 0 || x >= row.length || isBlankCell(row[x])) continue;
    visited.add(key);
    cells.push({ y: y, x: x, ch: row[x] });
    if (y < minY) minY = y;
    if (y > maxY) maxY = y;
    if (x < minX) minX = x;
    if (x > maxX) maxX = x;
    for (const [dy, dx] of NEIGHBORS) stack.push([y + dy, x + dx]);
  }
  return {
    cells: cells, minY: minY, maxY: maxY, minX: minX, maxX: maxX,
    pressDY: startY - minY,
    pressDX: startX - minX,
  };
}

// wos28: grab-move highlight uses an absolutely-positioned overlay layer
// (there are no per-cell elements to add a class to anymore). Each target
// cell is drawn as a box positioned from the measured grapheme rect.
function clearDropTarget() {
  if (overlayEl) overlayEl.innerHTML = '';
}
// Draw one overlay box over grid cell (ny,nx) with the given class. Shared by
// the drop-target preview, the selection highlight, and the marquee preview.
function overlayCellBox(ny, nx, cls) {
  if (!overlayEl) return;
  const view = els.sketchView;
  if (ny < 0 || ny >= gridH || nx < 0 || nx >= gridW) return;
  const lineEl = view.children[ny];
  if (!lineEl || !lineEl.classList || !lineEl.classList.contains('sketch-line')) return;
  const cells = measureLineCells(lineEl);
  if (nx >= cells.length) return;
  const cell = cells[nx];
  const viewRect = view.getBoundingClientRect();
  const lineRect = lineEl.getBoundingClientRect();
  const sl = view.scrollLeft, st = view.scrollTop;
  const box = document.createElement('div');
  box.className = cls;
  box.style.left = ((lineRect.left - viewRect.left) + sl + cell.left) + 'px';
  box.style.top = ((lineRect.top - viewRect.top) + st) + 'px';
  box.style.width = Math.max(2, cell.right - cell.left) + 'px';
  box.style.height = lineRect.height + 'px';
  overlayEl.appendChild(box);
}
function highlightDropShape(shape, releaseY, releaseX) {
  clearDropTarget();
  if (!overlayEl) return;
  const newMinY = releaseY - shape.pressDY;
  const newMinX = releaseX - shape.pressDX;
  for (const c of shape.cells) {
    overlayCellBox(newMinY + (c.y - shape.minY), newMinX + (c.x - shape.minX), 'sketch-drop');
  }
}

/* ---- wos36 selection helpers ---- */
function clearSelection() {
  selection.clear();
  marqueeActive = false;
  if (overlayEl) overlayEl.innerHTML = '';
}
// Re-draw the persistent highlight for every selected cell.
function renderSelectionHighlight() {
  if (!overlayEl) return;
  overlayEl.innerHTML = '';
  if (!selectMode) return;
  for (const key of selection) {
    const [y, x] = key.split(',').map(Number);
    overlayCellBox(y, x, 'sketch-selected');
  }
}
// While dragging a box: show the current selection plus a preview of the
// non-blank cells the box currently covers.
function renderMarquee(aY, aX, bY, bX) {
  if (!overlayEl) return;
  overlayEl.innerHTML = '';
  for (const key of selection) {
    const [y, x] = key.split(',').map(Number);
    overlayCellBox(y, x, 'sketch-selected');
  }
  const y0 = Math.min(aY, bY), y1 = Math.max(aY, bY);
  const x0 = Math.min(aX, bX), x1 = Math.max(aX, bX);
  const lineGS = els.editArtInput.value.split('\n').map(graphemes);
  for (let y = y0; y <= y1; y++) {
    for (let x = x0; x <= x1; x++) {
      if (lineGS[y] && x < lineGS[y].length && !isBlankCell(lineGS[y][x])) {
        overlayCellBox(y, x, 'sketch-marquee');
      }
    }
  }
}
// Add every non-blank cell inside the box to the selection (additive).
function commitMarquee(aY, aX, bY, bX) {
  const y0 = Math.min(aY, bY), y1 = Math.max(aY, bY);
  const x0 = Math.min(aX, bX), x1 = Math.max(aX, bX);
  const lineGS = els.editArtInput.value.split('\n').map(graphemes);
  for (let y = y0; y <= y1; y++) {
    for (let x = x0; x <= x1; x++) {
      if (lineGS[y] && x < lineGS[y].length && !isBlankCell(lineGS[y][x])) selection.add(y + ',' + x);
    }
  }
}
// Build a movable shape object from the current selection, pressed at (py,px).
function shapeFromSelection(py, px) {
  const lineGS = els.editArtInput.value.split('\n').map(graphemes);
  const cells = [];
  let minY = Infinity, maxY = -Infinity, minX = Infinity, maxX = -Infinity;
  for (const key of selection) {
    const [y, x] = key.split(',').map(Number);
    const ch = (lineGS[y] && x < lineGS[y].length) ? lineGS[y][x] : ' ';
    cells.push({ y, x, ch });
    if (y < minY) minY = y; if (y > maxY) maxY = y;
    if (x < minX) minX = x; if (x > maxX) maxX = x;
  }
  if (!cells.length) return null;
  return { cells, minY, maxY, minX, maxX, pressDY: py - minY, pressDX: px - minX };
}
// Lift a shape off the canvas and start the ghost drag (shared by quick-grab
// and selection-move).
function beginShapeDrag(shape, pressY, pressX, clientX, clientY) {
  // wos49: capture pre-grab snapshot for stroke logic, but DON'T push to
  // history until the grab is committed (drop or restore). The push happens
  // at gestureUp (line ~2423) so one grab = one undo entry.
  grabStartSnapshot = els.editArtInput.value;
  grabState = shape;
  els.sketchView.classList.add('grabbing');
  for (const c of shape.cells) writeCell(c.y, c.x, ' ');
  grabGhostEl = document.createElement('div');
  const multi = (shape.maxY > shape.minY) || (shape.maxX > shape.minX);
  grabGhostEl.className = 'grab-ghost' + (multi ? ' multi' : '');
  grabGhostEl.textContent = buildGhostText(shape);
  document.body.appendChild(grabGhostEl);
  moveGhost(clientX, clientY);
  highlightDropShape(shape, pressY, pressX);
  gesturePending = null;
  paintActive = false;
}
function updateSelectChip() {
  if (!els.sketchSelect) return;
  els.sketchSelect.classList.toggle('active', selectMode);
  els.sketchSelect.setAttribute('aria-pressed', selectMode ? 'true' : 'false');
  els.sketchSelect.textContent = (selectMode && selection.size)
    ? `⬚ Select (${selection.size})`
    : '⬚ Select';
}
/* Render the shape into a single (multi-line if needed) string for the ghost. */
function buildGhostText(shape) {
  const h = shape.maxY - shape.minY + 1;
  const w = shape.maxX - shape.minX + 1;
  if (h === 1 && w === 1) return shape.cells[0].ch;
  const buf = Array.from({ length: h }, () => Array(w).fill('\u00A0'));
  for (const c of shape.cells) buf[c.y - shape.minY][c.x - shape.minX] = c.ch;
  return buf.map(function (r) { return r.join(''); }).join('\n');
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
  gesturePending = { y: cell.y, x: cell.x, clientX: cx, clientY: cy };
  clearTimeout(grabHoldTimer);
  if (selectMode) {
    // In Select mode, only a press on an ALREADY-selected cell arms a move
    // (long-press). Pressing elsewhere becomes a tap-toggle or a box drag,
    // handled in gestureMove / gestureUp. No painting happens in this mode.
    if (selection.has(cell.y + ',' + cell.x)) {
      grabHoldTimer = setTimeout(() => {
        if (!gesturePending) return;
        const shape = shapeFromSelection(gesturePending.y, gesturePending.x);
        if (!shape) return;
        beginShapeDrag(shape, gesturePending.y, gesturePending.x, gesturePending.clientX, gesturePending.clientY);
      }, GRAB_HOLD_MS);
    }
    return;
  }
  grabHoldTimer = setTimeout(() => {
    if (!gesturePending) return;
    const shape = findShape(gesturePending.y, gesturePending.x);
    if (!shape) return; // pressed cell is blank; fall back to paint on release
    beginShapeDrag(shape, gesturePending.y, gesturePending.x, gesturePending.clientX, gesturePending.clientY);
  }, GRAB_HOLD_MS);
}

function gestureMove(cx, cy) {
  if (grabState) {
    moveGhost(cx, cy);
    const cell = cellFromPoint(cx, cy);
    if (!cell) { clearDropTarget(); return; }
    highlightDropShape(grabState, cell.y, cell.x);
    return;
  }
  if (selectMode && gesturePending) {
    const cell = cellFromPoint(cx, cy);
    if (cell && (cell.y !== gesturePending.y || cell.x !== gesturePending.x)) {
      clearTimeout(grabHoldTimer);   // a drag = box-select, not a move
      marqueeActive = true;
      renderMarquee(gesturePending.y, gesturePending.x, cell.y, cell.x);
    }
    return;
  }
  const cell = cellFromPoint(cx, cy);
  if (gesturePending) {
    // Moved off the origin cell before the hold fired => paint drag.
    if (cell && (cell.y !== gesturePending.y || cell.x !== gesturePending.x)) {
      clearTimeout(grabHoldTimer);
      // wos27: in Canvas mode (or with no brush) a drag places nothing — cancel
      // the gesture. Long-press grab-move is armed separately and still works.
      if (!canPaint()) { gesturePending = null; return; }
      startStroke();
      replaceCharAt(gesturePending.y, gesturePending.x);
      paintActive = true;
      gesturePending = null;
      replaceCharAt(cell.y, cell.x);
    }
    return;
  }
  if (paintActive && cell) replaceCharAt(cell.y, cell.x);
}

function gestureUp(cx, cy) {
  clearTimeout(grabHoldTimer);
  if (grabState) {
    const cell = cellFromPoint(cx, cy);
    const shape = grabState;
    let placed = false;
    if (cell) {
      const newMinY = (cell.y) - shape.pressDY;
      const newMinX = (cell.x) - shape.pressDX;
      const lineCount = gridH;
      // Fit-check every cell of the shape against the canvas; if ANY would
      // land off, snap the whole shape back to origin rather than clipping.
      let valid = true;
      for (const c of shape.cells) {
        const ny = newMinY + (c.y - shape.minY);
        const nx = newMinX + (c.x - shape.minX);
        if (ny < 0 || ny >= lineCount) { valid = false; break; }
        const rowWidth = gridW;
        if (nx < 0 || nx >= rowWidth) { valid = false; break; }
      }
      if (valid) {
        for (const c of shape.cells) {
          const ny = newMinY + (c.y - shape.minY);
          const nx = newMinX + (c.x - shape.minX);
          writeCell(ny, nx, c.ch);
        }
        placed = true;
        // wos36: if this was a selection move, re-key the selection to the
        // cells' new positions so they stay highlighted at the drop site.
        if (selectMode) {
          const ns = new Set();
          for (const c of shape.cells) ns.add((newMinY + (c.y - shape.minY)) + ',' + (newMinX + (c.x - shape.minX)));
          selection = ns;
        }
      }
    }
    if (!placed) {
      for (const c of shape.cells) writeCell(c.y, c.x, c.ch);
    }
    pushEditHistory();
    debouncedAutosave();   // wos84: persist grab-moved art to the draft too
    endGrab();
    if (selectMode) { renderSelectionHighlight(); updateSelectChip(); }
    return;
  }
  if (selectMode && gesturePending) {
    const cell = cellFromPoint(cx, cy);
    if (marqueeActive) {
      commitMarquee(gesturePending.y, gesturePending.x, (cell || gesturePending).y, (cell || gesturePending).x);
      marqueeActive = false;
    } else {
      // a tap: toggle the single pressed cell (only non-blank cells select)
      const key = gesturePending.y + ',' + gesturePending.x;
      if (selection.has(key)) selection.delete(key);
      else if (!isBlankCell(cellContent(gesturePending.y, gesturePending.x))) selection.add(key);
    }
    gesturePending = null;
    renderSelectionHighlight();
    updateSelectChip();
    return;
  }
  if (gesturePending) {
    const { y, x } = gesturePending;
    // wos84: an explicit tap PLACES the armed character at that exact cell — the
    // classic "pick a char, then click the spot" flow. Selecting a palette char
    // only arms it now; the character isn't dropped until this click. With
    // nothing armed (Canvas mode / no brush) the tap just repositions the text
    // cursor so keyboard typing continues from there. Either way the cursor
    // lands here and the keyboard proxy stays focused.
    if (canPaint()) {
      startStroke();
      replaceCharAt(y, x);
      endStroke();
      const adv = eraserOn ? 1 : Math.max(1, graphemes(activeBrush).length);
      placeCursorAt(y, x + adv);
    } else {
      placeCursorAt(y, x);
    }
    focusTypeProxy();
    gesturePending = null;
    return;
  }
  if (paintActive) endStroke();
}

// wos53: when the user taps the canvas scrollbar gutter, the touch lands on
// .sketch-view and would otherwise trigger paint. Use a 18px hit zone
// along the right/bottom edges when a scrollbar is present — wider than
// the native scrollbar (which can be 4px on mobile) so imprecise finger
// taps near the scrollbar register as scroll intent, not paint.
const SCROLLBAR_HIT = 18;
function isOnScrollbar(el, x, y) {
  const rect = el.getBoundingClientRect();
  const relX = x - rect.left;
  const relY = y - rect.top;
  const sbW = el.offsetWidth - el.clientWidth;
  const sbH = el.offsetHeight - el.clientHeight;
  if (sbW > 0 && relX >= el.offsetWidth - SCROLLBAR_HIT) return true;
  if (sbH > 0 && relY >= el.offsetHeight - SCROLLBAR_HIT) return true;
  return false;
}

els.sketchView.addEventListener('pointerdown', (e) => {
  if (Date.now() - lastTouchAt < 400) return; // ignore synthetic post-touch pointer
  if (isOnScrollbar(els.sketchView, e.clientX, e.clientY)) return;
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
    for (const c of grabState.cells) writeCell(c.y, c.x, c.ch);
    endGrab();
  }
  gesturePending = null; paintActive = false;
});

// Touch fallbacks (fire before pointer events; mark time so pointer skips dupes).
els.sketchView.addEventListener('touchstart', (e) => {
  lastTouchAt = Date.now();
  const t = e.touches[0]; if (!t) return;
  if (isOnScrollbar(els.sketchView, t.clientX, t.clientY)) return; // wos53
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
    for (const c of grabState.cells) writeCell(c.y, c.x, c.ch);
    endGrab();
  }
  gesturePending = null; paintActive = false;
});

/* ============================================================================
 * wos82 — TYPEABLE CANVAS. The draw grid is now directly typeable: a text
 * cursor sits on a cell, the keyboard writes into cells (overwrite + advance),
 * and tapping a cell moves the cursor there. Drag-to-paint, palette, grab-move
 * and Select all still work on the same surface — so Type and Draw are ONE mode
 * with no toggle. The existing #edit-art-input textarea stays in the DOM as the
 * KEYBOARD PROXY (a <div> grid can't summon a mobile soft keyboard); we
 * intercept its input events so its value is only ever changed through our own
 * positional writes — the textarea itself is an invisible, focusable overlay.
 * ========================================================================== */
let cursorCell = { y: 0, x: 0 };
let cursorEl = null;

function focusTypeProxy() {
  // Immediate focus (called from within a tap gesture) so the mobile soft
  // keyboard reliably appears; preventScroll avoids the page jumping.
  try { els.editArtInput.focus({ preventScroll: true }); } catch {}
}

function clampCursor(y, x) {
  return {
    y: Math.max(0, Math.min(y, FREEFORM_MAX_ROWS - 1)),
    x: Math.max(0, Math.min(x, FREEFORM_MAX_COLS - 1)),
  };
}

// Position the blinking cursor box over the current cell (same geometry the
// overlay boxes use). Re-run after any render since renderSketch wipes the view.
function positionCursor() {
  const view = els.sketchView;
  if (!cursorEl) {
    cursorEl = document.createElement('div');
    cursorEl.className = 'sketch-cursor';
    cursorEl.setAttribute('aria-hidden', 'true');
  }
  if (!view) return;
  if (cursorEl.parentNode !== view) view.appendChild(cursorEl);
  const ry = Math.max(0, Math.min(cursorCell.y, gridH - 1));
  const lineEl = view.children[ry];
  if (!lineEl || !lineEl.classList || !lineEl.classList.contains('sketch-line')) {
    cursorEl.style.display = 'none';
    return;
  }
  const cells = measureLineCells(lineEl);
  if (!cells.length) { cursorEl.style.display = 'none'; return; }
  const viewRect = view.getBoundingClientRect();
  const lineRect = lineEl.getBoundingClientRect();
  const baseLeft = (lineRect.left - viewRect.left) + view.scrollLeft;
  const baseTop = (lineRect.top - viewRect.top) + view.scrollTop;
  const x = cursorCell.x;
  let cellLeft, cellW;
  if (x < cells.length) {
    cellLeft = cells[x].left;
    cellW = Math.max(3, cells[x].right - cells[x].left);
  } else {
    const last = cells[cells.length - 1];
    const step = (last.right - last.left) || 10;
    cellLeft = last.right + step * (x - cells.length);
    cellW = Math.max(3, step);
  }
  cursorEl.style.display = 'block';
  cursorEl.style.left = (baseLeft + cellLeft) + 'px';
  cursorEl.style.top = baseTop + 'px';
  cursorEl.style.width = cellW + 'px';
  cursorEl.style.height = lineRect.height + 'px';
}

function scrollCursorIntoView() {
  const view = els.sketchView;
  if (!cursorEl || !view || cursorEl.style.display === 'none') return;
  const cTop = cursorEl.offsetTop, cBot = cTop + cursorEl.offsetHeight;
  if (cTop < view.scrollTop) view.scrollTop = cTop;
  else if (cBot > view.scrollTop + view.clientHeight) view.scrollTop = cBot - view.clientHeight;
  const cLeft = cursorEl.offsetLeft, cRight = cLeft + cursorEl.offsetWidth;
  if (cLeft < view.scrollLeft) view.scrollLeft = cLeft;
  else if (cRight > view.scrollLeft + view.clientWidth) view.scrollLeft = cRight - view.clientWidth;
}

function placeCursorAt(y, x) {
  cursorCell = clampCursor(y, x);
  positionCursor();
}
function moveCursor(dy, dx) {
  cursorCell = clampCursor(cursorCell.y + dy, cursorCell.x + dx);
  positionCursor();
  scrollCursorIntoView();
}

// Type a string into the grid at the cursor: each grapheme OVERWRITES its cell
// and advances; '\n' drops to column 0 of the next row. One history entry per
// call = one undo per keystroke / paste.
function typeAtCursor(str) {
  if (!str) return;
  const before = els.editArtInput.value;
  for (const g of graphemes(str)) {
    if (g === '\n' || g === '\r') { cursorCell = clampCursor(cursorCell.y + 1, 0); continue; }
    writeCell(cursorCell.y, cursorCell.x, g);
    cursorCell = clampCursor(cursorCell.y, cursorCell.x + 1);
  }
  renderSketch(true);        // grow the grid for any new rows/cols, then re-place
  positionCursor();
  scrollCursorIntoView();
  if (before !== els.editArtInput.value) { pushEditHistory(); debouncedAutosave(); }
  runAudit();
}

// Backspace: clear the cell to the LEFT (overtype-erase) and move there; at the
// row start, hop to the end of the previous row (no line-joining on a grid).
function backspaceAtCursor() {
  const before = els.editArtInput.value;
  if (cursorCell.x > 0) {
    cursorCell = clampCursor(cursorCell.y, cursorCell.x - 1);
    writeCell(cursorCell.y, cursorCell.x, ' ');
  } else if (cursorCell.y > 0) {
    const lines = els.editArtInput.value.split('\n');
    const py = cursorCell.y - 1;
    cursorCell = clampCursor(py, graphemes(lines[py] || '').length);
  }
  renderSketch(true);
  positionCursor();
  scrollCursorIntoView();
  if (before !== els.editArtInput.value) { pushEditHistory(); debouncedAutosave(); }
  runAudit();
}
// Delete: clear the current cell in place (no advance).
function deleteAtCursor() {
  const before = els.editArtInput.value;
  writeCell(cursorCell.y, cursorCell.x, ' ');
  renderSketch(true);
  positionCursor();
  if (before !== els.editArtInput.value) { pushEditHistory(); debouncedAutosave(); }
  runAudit();
}

// ---- Keyboard proxy: route the hidden textarea's input onto the grid cursor.
els.editArtInput.addEventListener('keydown', (e) => {
  if (!els.edit.classList.contains('open')) return;
  switch (e.key) {
    case 'ArrowLeft':  moveCursor(0, -1); e.preventDefault(); break;
    case 'ArrowRight': moveCursor(0, 1);  e.preventDefault(); break;
    case 'ArrowUp':    moveCursor(-1, 0); e.preventDefault(); break;
    case 'ArrowDown':  moveCursor(1, 0);  e.preventDefault(); break;
    case 'Home': placeCursorAt(cursorCell.y, 0); e.preventDefault(); break;
    case 'End': {
      const lines = els.editArtInput.value.split('\n');
      placeCursorAt(cursorCell.y, graphemes(lines[cursorCell.y] || '').length);
      e.preventDefault();
      break;
    }
    // printable keys, Enter, Backspace and Delete are handled via beforeinput
    // below so IME / mobile / emoji input all flow through the same path.
  }
});
els.editArtInput.addEventListener('beforeinput', (e) => {
  if (!els.edit.classList.contains('open')) return;
  const t = e.inputType || '';
  if (t === 'insertText' || t === 'insertReplacementText') {
    if (e.data != null) typeAtCursor(e.data);
  } else if (t === 'insertParagraph' || t === 'insertLineBreak') {
    typeAtCursor('\n');
  } else if (t === 'deleteContentBackward') {
    backspaceAtCursor();
  } else if (t === 'deleteContentForward') {
    deleteAtCursor();
  }
  // Always block the native edit — the textarea value is our model and must
  // only change through the positional writes above (keeps the grid coherent).
  e.preventDefault();
});
// Paste gives the full (possibly multi-line) text in one shot.
els.editArtInput.addEventListener('paste', (e) => {
  if (!els.edit.classList.contains('open')) return;
  const cb = e.clipboardData || window.clipboardData;
  const txt = cb && cb.getData ? cb.getData('text') : '';
  if (txt) { typeAtCursor(txt); e.preventDefault(); }
});

// Consolidated "Clear": reset to a FRESH blank 27×12 grid so there's always a
// paintable surface (replaces the old separate Blank + Clear buttons).
function fillBlankGrid() {
  pushEditHistory();
  const cols = WOS_DEFAULT_COLS, rows = WOS_DEFAULT_ROWS;
  const line = '\u00A0'.repeat(cols);
  els.editArtInput.value = Array(rows).fill(line).join('\n');
  lastEditSnapshot = els.editArtInput.value;
  clearSelection();          // wos36: nothing left to keep selected
  if (els.sketchSelect) updateSelectChip();
  renderSketch(true);
  runAudit();
  // wos31: persist the cleared state to the autosaved draft immediately.
  // Setting .value programmatically does NOT fire the input event, so the
  // debounced autosave never ran \u2014 the draft kept the PRE-clear art and
  // restored it on reopen ("whatever I cleared comes right back"). Saving
  // here makes the clear stick across close/reopen.
  writeDraft();
}
if (els.sketchClear) els.sketchClear.addEventListener('click', () => {
  if (!confirm('Clear the canvas and start over with a fresh blank grid?')) return;
  fillBlankGrid();
});
els.sketchUndo.addEventListener('click', undoEdit);
if (els.sketchRedo) els.sketchRedo.addEventListener('click', redoEdit);
const textUndoBtn = document.getElementById('text-undo');
if (textUndoBtn) textUndoBtn.addEventListener('click', undoEdit);
if (els.sketchEraser) els.sketchEraser.addEventListener('click', () => setEraser(!eraserOn));
if (els.sketchSelect) els.sketchSelect.addEventListener('click', () => {
  selectMode = !selectMode;
  if (selectMode) {
    // Select mode owns the canvas; turn off paint/eraser so taps don't paint.
    eraserOn = false;
    if (els.sketchEraser) els.sketchEraser.classList.remove('active');
  } else {
    clearSelection();
  }
  updateSelectChip();
  renderSelectionHighlight();
});
// wos27: the active-char chip is the Canvas/Drawing mode toggle.
if (els.sketchActiveChar) els.sketchActiveChar.addEventListener('click', toggleCanvasMode);

els.editArtInput.addEventListener('input', () => {
  // wos49: push the POST-edit value so undo is granular per keystroke.
  // wos52: tablet/mobile autosuggest, swipe-typing, paste, and predictive
  // keyboards all insert MULTIPLE characters in a single input event. The
  // previous wos49 behavior treated those as one undo step, so a single
  // undo would revert a whole word — user reported "undo reverts 6 inputs".
  // Now: when an input event inserts N>1 contiguous chars, push N
  // intermediate history states so undo walks back one character at a
  // time, no matter how the chars were entered.
  if (!editHistorySuspend) {
    const oldVal = lastEditSnapshot;
    const newVal = els.editArtInput.value;
    if (newVal !== oldVal) {
      let i = 0;
      while (i < oldVal.length && i < newVal.length && oldVal[i] === newVal[i]) i++;
      let oldEnd = oldVal.length, newEnd = newVal.length;
      while (oldEnd > i && newEnd > i && oldVal[oldEnd - 1] === newVal[newEnd - 1]) {
        oldEnd--; newEnd--;
      }
      const insertedLen = newEnd - i;
      const removedLen  = oldEnd - i;
      // Pure insertion of >1 chars (no replacement) → split per-char.
      if (insertedLen > 1 && removedLen === 0 && insertedLen <= 50) {
        const prefix = oldVal.slice(0, i);
        const suffix = oldVal.slice(oldEnd);
        const inserted = newVal.slice(i, newEnd);
        for (let k = 1; k <= inserted.length; k++) {
          const step = prefix + inserted.slice(0, k) + suffix;
          if (editHistory.length && editHistory[editHistory.length - 1] === step) continue;
          editHistory.push(step);
          if (editHistory.length > EDIT_HISTORY_MAX) editHistory.shift();
        }
        redoHistory.length = 0;
        lastEditSnapshot = newVal;
        syncHistoryButtons();
      } else {
        pushEditHistory();
      }
    }
  }
  if (isSketchMode()) renderSketch();
});

// Keyboard shortcuts inside the editor:
//   Ctrl/Cmd + Z          -> undo
//   Ctrl/Cmd + Shift + Z  -> redo
//   Ctrl/Cmd + Y          -> redo
document.addEventListener('keydown', (e) => {
  if (!els.edit.classList.contains('open')) return;
  const ctrl = e.ctrlKey || e.metaKey;
  if (!ctrl) return;
  if (!e.shiftKey && (e.key === 'z' || e.key === 'Z')) {
    e.preventDefault();
    undoEdit();
  } else if ((e.shiftKey && (e.key === 'z' || e.key === 'Z')) || e.key === 'y' || e.key === 'Y') {
    e.preventDefault();
    redoEdit();
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
  // wos30: `.drawing` is the always-on unified workspace; draw-INPUT mode is
  // when we're NOT in the `.typing` sub-mode. Paint/render gating uses this.
  return els.edit.classList.contains('drawing') && !els.edit.classList.contains('typing');
}

function handlePaletteSelection(ch) {
  // wos84: selecting a palette char only ARMS it (readies it for placement) —
  // it is NOT dropped onto the canvas here. The character is placed when the
  // user explicitly clicks a cell (see the tap handler in gestureUp), or by
  // dragging a stroke. This restores the classic "pick a char, click a spot"
  // flow; the earlier auto-type-on-select was the reported regression.
  setActiveBrush(ch);
}

// A leading combining mark (e.g. a bare mouth/nose piece) has nothing to attach
// to inside a button, so show it on a dotted circle (◌). The inserted value is
// still the raw mark — only the on-screen label gets the placeholder base.
function paletteLabel(ch) {
  return /^\p{M}/u.test(ch) ? '◌' + ch : ch;
}

/* Dynamic palette head label: as the user scrolls the palette, name whichever
 * group is currently most prominently in view. The per-group inline labels are
 * hidden in CSS so this is the single source of truth. */
let refreshGroupLabel = function () {};
function setupGroupLabelTracker() {
  const palette = els.charPalette;
  const labelEl = document.getElementById('palette-active-group');
  if (!palette || !labelEl) return;
  let rafPending = false;
  function update() {
    rafPending = false;
    const groups = palette.querySelectorAll('.palette-group');
    if (!groups.length) return;
    const palRect = palette.getBoundingClientRect();
    // Palette is not laid out yet (modal hidden) -> every group reports {top:0}
    // and the loop would pick the LAST one. Bail; a synthetic scroll on modal
    // open will re-run this with real rects.
    if (palRect.height === 0) return;
    let active = '';
    for (const g of groups) {
      const gRect = g.getBoundingClientRect();
      // Most-recent group whose top is at-or-above the palette's viewport top.
      if (gRect.top - palRect.top <= 12) {
        const heading = g.querySelector('.palette-group-label');
        active = heading ? heading.textContent.trim() : '';
      } else {
        break;
      }
    }
    if (!active && groups[0]) {
      const heading = groups[0].querySelector('.palette-group-label');
      active = heading ? heading.textContent.trim() : '';
    }
    if (labelEl.textContent !== active) {
      labelEl.classList.add('is-changing');
      labelEl.textContent = active;
      requestAnimationFrame(() => labelEl.classList.remove('is-changing'));
    }
  }
  palette.addEventListener('scroll', function () {
    if (rafPending) return;
    rafPending = true;
    requestAnimationFrame(update);
  }, { passive: true });
  refreshGroupLabel = update;
  update();
}

/* Live palette source. Starts as a deep-ish clone of the bundled
 * PALETTE_GROUPS from palette-data.js. If the admin has saved a custom
 * palette via the Settings -> Character Palette section, the boot loader
 * fetches it from /get-palette and replaces this array, then rebuilds.
 * buildPalette() reads this; never reads PALETTE_GROUPS directly. */
let LIVE_PALETTE_GROUPS = (typeof PALETTE_GROUPS !== 'undefined' ? PALETTE_GROUPS : []).map((g) => ({
  label: g.label,
  wide: !!g.wide,
  chars: Array.isArray(g.chars) ? [...g.chars] : [],
}));

function buildPalette() {
  els.charPalette.innerHTML = '';
  const favs = new Set(loadFavorites());
  for (const group of LIVE_PALETTE_GROUPS) {
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
  // wos24: strip trailing all-blank rows before persisting. Draw mode primes
  // the canvas as a 27×12 NBSP grid via fillBlankGrid(); if the user only
  // paints in the top few rows, the rest of the textarea is still pure
  // NBSP padding, which renders as a tall empty void below the art on every
  // subsequent view. Only TRAILING rows are dropped — leading and inner
  // blank rows can carry intentional vertical positioning, and per-row
  // trailing whitespace can carry intentional horizontal padding.
  art = trimTrailingBlankRows(art);
  const { width, height } = measure(art);

  // wos35: read Draft checkbox state. Default to true for new art (private
  // WIP), false for existing pieces (preserve their published state).
  const draft = els.editDraftInput ? !!els.editDraftInput.checked : false;

  let piece;
  if (editing) {
    piece = { ...editing, title, tags, art, width, height, draft };
  } else {
    piece = {
      id: newId(),
      title, tags, art, width, height,
      wosVerified: false,
      draft,
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
  // Safe Mode: flagging is public, so a visitor flagging a card must stop seeing
  // it at once. The gallery filter only runs in render(), and toggleFlag mutates
  // state.flags without re-rendering — so re-render now to drop the just-flagged
  // card immediately (the async save continues below).
  const publicSafe = !state.editor && document.documentElement.classList.contains('safe-mode');
  if (publicSafe) render();
  const r = await API.saveFlag(p.id, 'toggle');
  if (r && r.flagged !== undefined) {
    if (r.flagged) state.flags[p.id] = r.note || '';
    else delete state.flags[p.id];
    syncFlaggedTab();
    if (publicSafe) render();   // reconcile with the server's authoritative flag state
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

/* ============ 14  Character Palette manager (admin-only) ============
 * Lives in the Menu drawer's "Character Palette" accordion section.
 * Section is hidden unless body.editor is set (CSS-driven).
 *
 * Operations:
 *   - Tap a character to select it; the action panel under that group shows
 *     a "Move to" group picker + a Delete button.
 *   - Add a character: type/paste into the input at the bottom of a group's
 *     card and hit "+" (or Enter). Accepts multi-character strings (e.g. a
 *     full kaomoji or a bracket pair).
 *   - Add a new group: bottom of the section. Empty groups are allowed so
 *     you can name them first and fill later.
 *   - Delete a group: × on the group's head, after confirm. Refuses if the
 *     group still has characters (delete those first or move them).
 *
 * Every mutation rebuilds the in-app palette and triggers a debounced save
 * to /save-palette so the next page load (anywhere) sees the change.
 */
let paletteMgrSelected = null; // { groupIndex, charIndex } or null
let paletteMgrSaveTimer = null;
const PALETTE_SAVE_DEBOUNCE_MS = 800;

function paletteMgrSetStatus(text, kind) {
  const el = document.getElementById('palette-mgr-status');
  if (!el) return;
  el.className = 'palette-mgr-status' + (kind ? ` is-${kind}` : '');
  el.textContent = text;
}

async function paletteMgrSave() {
  if (!state.editor || !state.password) return;
  paletteMgrSetStatus('Saving…', 'saving');
  try {
    const url = await fnUrl('save-palette');
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${state.password}`,
      },
      body: JSON.stringify({ groups: LIVE_PALETTE_GROUPS }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      paletteMgrSetStatus(`Save failed: ${data.error || res.status}`, 'error');
      return;
    }
    paletteMgrSetStatus('Saved', 'saved');
    setTimeout(() => {
      const el = document.getElementById('palette-mgr-status');
      if (el && el.textContent === 'Saved') paletteMgrSetStatus('');
    }, 1800);
  } catch (err) {
    paletteMgrSetStatus('Save failed: network', 'error');
  }
}

function paletteMgrScheduleSave() {
  if (paletteMgrSaveTimer) clearTimeout(paletteMgrSaveTimer);
  paletteMgrSaveTimer = setTimeout(paletteMgrSave, PALETTE_SAVE_DEBOUNCE_MS);
}

function paletteMgrCommitChange() {
  // Rebuild the in-app palette so the change shows immediately in the editor
  buildPalette();
  // Refresh the dynamic group label since group structure may have changed
  if (typeof refreshGroupLabel === 'function') refreshGroupLabel();
  // Re-render the manager UI itself
  renderPaletteManager();
  // Save (debounced)
  paletteMgrScheduleSave();
}

function renderPaletteManager() {
  const host = document.getElementById('palette-mgr-groups');
  if (!host) return;
  host.innerHTML = '';

  LIVE_PALETTE_GROUPS.forEach((group, groupIndex) => {
    const card = document.createElement('div');
    card.className = 'palette-mgr-group';

    const head = document.createElement('div');
    head.className = 'palette-mgr-group-head';
    const label = document.createElement('span');
    label.className = 'palette-mgr-group-label';
    label.textContent = group.label;
    head.appendChild(label);
    const delGroupBtn = document.createElement('button');
    delGroupBtn.type = 'button';
    delGroupBtn.className = 'palette-mgr-group-delete';
    delGroupBtn.title = 'Delete this whole group';
    delGroupBtn.textContent = '×';
    delGroupBtn.addEventListener('click', () => {
      if (group.chars.length > 0) {
        if (!confirm(`Delete the "${group.label}" group and all ${group.chars.length} characters in it?`)) return;
      } else if (!confirm(`Delete the empty "${group.label}" group?`)) return;
      LIVE_PALETTE_GROUPS.splice(groupIndex, 1);
      paletteMgrSelected = null;
      paletteMgrCommitChange();
    });
    head.appendChild(delGroupBtn);
    card.appendChild(head);

    const chars = document.createElement('div');
    chars.className = 'palette-mgr-chars';
    group.chars.forEach((ch, charIndex) => {
      const tile = document.createElement('button');
      tile.type = 'button';
      tile.className = 'palette-mgr-char' + (group.wide || ch.length > 2 ? ' wide' : '');
      tile.textContent = paletteLabel(ch);
      tile.title = ch;
      if (paletteMgrSelected && paletteMgrSelected.groupIndex === groupIndex && paletteMgrSelected.charIndex === charIndex) {
        tile.classList.add('is-selected');
      }
      tile.addEventListener('click', () => {
        if (paletteMgrSelected && paletteMgrSelected.groupIndex === groupIndex && paletteMgrSelected.charIndex === charIndex) {
          paletteMgrSelected = null;
        } else {
          paletteMgrSelected = { groupIndex, charIndex };
        }
        renderPaletteManager();
      });
      chars.appendChild(tile);
    });
    card.appendChild(chars);

    // Selected-char action panel — only when selection is in this group
    if (paletteMgrSelected && paletteMgrSelected.groupIndex === groupIndex) {
      const selected = group.chars[paletteMgrSelected.charIndex];
      if (selected) {
        const info = document.createElement('div');
        info.className = 'palette-mgr-charinfo';

        const row = document.createElement('div');
        row.className = 'palette-mgr-charinfo-row';
        const preview = document.createElement('span');
        preview.className = 'palette-mgr-charinfo-preview';
        preview.textContent = selected;
        row.appendChild(preview);

        const moveLabel = document.createElement('span');
        moveLabel.textContent = 'Move to';
        row.appendChild(moveLabel);

        const select = document.createElement('select');
        const placeholder = document.createElement('option');
        placeholder.value = '';
        placeholder.textContent = 'choose group…';
        select.appendChild(placeholder);
        LIVE_PALETTE_GROUPS.forEach((g, idx) => {
          if (idx === groupIndex) return;
          const opt = document.createElement('option');
          opt.value = String(idx);
          opt.textContent = g.label;
          select.appendChild(opt);
        });
        select.addEventListener('change', () => {
          const targetIdx = parseInt(select.value, 10);
          if (!Number.isInteger(targetIdx) || targetIdx === groupIndex) return;
          const ch = group.chars.splice(paletteMgrSelected.charIndex, 1)[0];
          LIVE_PALETTE_GROUPS[targetIdx].chars.push(ch);
          paletteMgrSelected = null;
          paletteMgrCommitChange();
        });
        row.appendChild(select);

        const delBtn = document.createElement('button');
        delBtn.type = 'button';
        delBtn.className = 'palette-mgr-btn danger';
        delBtn.textContent = 'Delete';
        delBtn.addEventListener('click', () => {
          group.chars.splice(paletteMgrSelected.charIndex, 1);
          paletteMgrSelected = null;
          paletteMgrCommitChange();
        });
        row.appendChild(delBtn);

        info.appendChild(row);
        card.appendChild(info);
      }
    }

    // Add-character input
    const addRow = document.createElement('form');
    addRow.className = 'palette-mgr-addrow';
    const input = document.createElement('input');
    input.type = 'text';
    input.placeholder = 'Add character…';
    input.maxLength = 80;
    addRow.appendChild(input);
    const addBtn = document.createElement('button');
    addBtn.type = 'submit';
    addBtn.className = 'palette-mgr-btn';
    addBtn.textContent = '+';
    addRow.appendChild(addBtn);
    addRow.addEventListener('submit', (e) => {
      e.preventDefault();
      const val = input.value;
      if (!val || !val.length) return;
      if (val.length > 80) {
        paletteMgrSetStatus('Character too long (max 80 chars)', 'error');
        return;
      }
      if (group.chars.includes(val)) {
        paletteMgrSetStatus('Already in this group', 'error');
        return;
      }
      group.chars.push(val);
      input.value = '';
      paletteMgrCommitChange();
    });
    card.appendChild(addRow);

    host.appendChild(card);
  });
}

(function wirePaletteManager() {
  const form = document.getElementById('palette-mgr-newgroup');
  if (!form) return;
  const input = document.getElementById('palette-mgr-newgroup-input');
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const label = (input.value || '').trim();
    if (!label) return;
    if (label.length > 60) {
      paletteMgrSetStatus('Group name too long (max 60 chars)', 'error');
      return;
    }
    if (LIVE_PALETTE_GROUPS.some((g) => g.label === label)) {
      paletteMgrSetStatus('A group with that name already exists', 'error');
      return;
    }
    LIVE_PALETTE_GROUPS.push({ label, wide: false, chars: [] });
    input.value = '';
    paletteMgrCommitChange();
  });
})();

async function loadCustomPalette() {
  try {
    const url = await fnUrl('get-palette');
    const res = await fetch(url);
    if (res.status === 404) return; // no custom palette yet
    if (!res.ok) return;
    const data = await res.json();
    if (!data || !Array.isArray(data.groups)) return;
    // Sanitize incoming data — only keep well-formed groups/chars
    const clean = [];
    for (const g of data.groups) {
      if (!g || typeof g.label !== 'string' || !Array.isArray(g.chars)) continue;
      clean.push({
        label: g.label,
        wide: !!g.wide,
        chars: g.chars.filter((c) => typeof c === 'string' && c.length > 0 && c.length <= 80),
      });
    }
    if (clean.length === 0) return;
    LIVE_PALETTE_GROUPS = clean;
    buildPalette();
    if (typeof refreshGroupLabel === 'function') refreshGroupLabel();
    renderPaletteManager();
  } catch {
    // network/parse error — silently fall back to default palette
  }
}

/* ============ Site Text manager (wos21) ===================================
 * Lets the admin edit the chrome text — site title, tagline, share-bar URL
 * label, add-button label, search placeholder, footer — from the drawer.
 * Mirrors the palette-manager pattern: debounced autosave on change, status
 * line shows Saving… → Saved, falls back silently if the network is down.
 *
 * Data flow:
 *   - Defaults live in index.html (the literal text in each [data-st] node)
 *   - On boot: capture defaults, then apply localStorage cache (already done
 *     by the pre-paint script in index.html), then fetch from get-site-text
 *     and apply any newer customizations.
 *   - On admin edit: write to DOM live → cache to localStorage → debounced
 *     POST to save-site-text.
 *
 * Keys are validated server-side in save-site-text.js; we additionally
 * trim and reject empty values client-side so the form can't accidentally
 * clear the page chrome to whitespace.
 */
const SITE_TEXT_CACHE_KEY = 'frostline:siteText:v1';
const SITE_TEXT_SAVE_DEBOUNCE_MS = 500;
const SITE_TEXT_KEYS = [
  'siteTitle',
  'tagline',
  'shareUrlLabel',
  'addButtonLabel',
  'searchPlaceholder',
  'footerText',
];

const SITE_TEXT_DEFAULTS = {};
let siteTextSaveTimer = null;

function siteTextCaptureDefaults() {
  // Run before any custom text is applied so we always know the originals.
  // Note: by the time this runs, the pre-paint script in index.html may
  // have already replaced [data-st] textContent with cached values. To
  // avoid recording cache values as "defaults", we use the cached values
  // ONLY if no cache exists; otherwise capture is a no-op.
  if (Object.keys(SITE_TEXT_DEFAULTS).length > 0) return;
  let cached = null;
  try { cached = JSON.parse(localStorage.getItem(SITE_TEXT_CACHE_KEY) || 'null'); } catch {}
  document.querySelectorAll('[data-st]').forEach((el) => {
    const key = el.getAttribute('data-st');
    const attr = el.getAttribute('data-st-attr');
    const current = attr ? el.getAttribute(attr) : el.textContent;
    if (cached && typeof cached[key] === 'string') {
      // Pre-paint script already swapped this in; we don't know the
      // original. Falling back to current is fine — the only thing
      // defaults are used for is the "Reset to defaults" button, and
      // a reset on a cached page still produces a sensible value
      // (whatever the cached one was) until the next deploy.
      SITE_TEXT_DEFAULTS[key] = current || '';
    } else {
      SITE_TEXT_DEFAULTS[key] = (current || '').trim();
    }
  });
}

function siteTextApply(text) {
  if (!text || typeof text !== 'object') return;
  document.querySelectorAll('[data-st]').forEach((el) => {
    const key = el.getAttribute('data-st');
    const val = text[key];
    if (typeof val !== 'string' || val.length === 0) return;
    const attr = el.getAttribute('data-st-attr');
    if (attr) el.setAttribute(attr, val);
    else el.textContent = val;
  });
}

function siteTextSetStatus(msg, kind) {
  const el = document.getElementById('site-text-status');
  if (!el) return;
  el.className = 'site-text-status' + (kind ? ` is-${kind}` : '');
  el.textContent = msg;
}

function siteTextReadForm() {
  const out = {};
  SITE_TEXT_KEYS.forEach((key) => {
    const input = document.querySelector(`[data-st-field="${key}"]`);
    if (!input) return;
    const v = (input.value || '').trim();
    if (v.length > 0) out[key] = v;
  });
  return out;
}

function siteTextFillForm(text) {
  SITE_TEXT_KEYS.forEach((key) => {
    const input = document.querySelector(`[data-st-field="${key}"]`);
    if (!input) return;
    const val = (text && typeof text[key] === 'string') ? text[key] : (SITE_TEXT_DEFAULTS[key] || '');
    input.value = val;
  });
}

async function siteTextSave() {
  if (!state.editor || !state.password) return;
  const text = siteTextReadForm();
  siteTextSetStatus('Saving…', 'saving');
  try {
    const url = await fnUrl('save-site-text');
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${state.password}`,
      },
      body: JSON.stringify({ text }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      siteTextSetStatus(`Save failed: ${data.error || res.status}`, 'error');
      return;
    }
    try { localStorage.setItem(SITE_TEXT_CACHE_KEY, JSON.stringify(text)); } catch {}
    siteTextSetStatus('Saved', 'saved');
    setTimeout(() => {
      const el = document.getElementById('site-text-status');
      if (el && el.textContent === 'Saved') siteTextSetStatus('');
    }, 1800);
  } catch {
    siteTextSetStatus('Save failed: network', 'error');
  }
}

function siteTextScheduleSave() {
  if (siteTextSaveTimer) clearTimeout(siteTextSaveTimer);
  siteTextSaveTimer = setTimeout(siteTextSave, SITE_TEXT_SAVE_DEBOUNCE_MS);
}

function setupSiteTextEditor() {
  const form = document.getElementById('site-text-form');
  if (!form) return;
  // Live-apply each keystroke to the DOM so the admin sees the change
  // immediately (same UX as the palette manager), then schedule a save.
  form.addEventListener('input', (e) => {
    const input = e.target.closest('[data-st-field]');
    if (!input) return;
    const key = input.getAttribute('data-st-field');
    const partial = {};
    const v = (input.value || '').trim();
    partial[key] = v.length > 0 ? v : (SITE_TEXT_DEFAULTS[key] || '');
    siteTextApply(partial);
    siteTextScheduleSave();
  });
  const resetBtn = document.getElementById('site-text-reset');
  if (resetBtn) {
    resetBtn.addEventListener('click', () => {
      if (!confirm('Reset all site text to defaults?')) return;
      siteTextFillForm({});
      siteTextApply(SITE_TEXT_DEFAULTS);
      try { localStorage.removeItem(SITE_TEXT_CACHE_KEY); } catch {}
      siteTextScheduleSave();
    });
  }
}

async function loadCustomSiteText() {
  try {
    const url = await fnUrl('get-site-text');
    const res = await fetch(url);
    if (res.status === 404) {
      // No custom text saved — pre-fill the form with defaults so the
      // admin sees what's currently displayed.
      siteTextFillForm({});
      return;
    }
    if (!res.ok) return;
    const data = await res.json();
    if (!data || !data.text || typeof data.text !== 'object') return;
    siteTextApply(data.text);
    siteTextFillForm(data.text);
    try { localStorage.setItem(SITE_TEXT_CACHE_KEY, JSON.stringify(data.text)); } catch {}
  } catch {
    // network/parse error — leave the in-HTML defaults alone
  }
}

/* ============ 15  Init ============ */
buildPalette();
buildFavoritesBar();
setupGroupLabelTracker();
renderPaletteManager();
loadCustomPalette();
siteTextCaptureDefaults();
setupSiteTextEditor();
loadCustomSiteText();

/* ===== Safe Mode (public content protection) =====
   The first-visit content gate (inline in index.html) sets the `safe-mode`
   class on <html> and persists the choice under 'frostline:safe'. This wires
   the drawer toggle so an adult can flip it afterward, keeps the switch UI in
   sync, and re-renders when it changes (the gate fires 'frostline:safemode'
   in case the app had already booted). Filtering lives in filtered(). */
(function setupSafeMode() {
  const SAFE_KEY = 'frostline:safe';
  const btn = document.getElementById('drawer-safe-btn');
  const stateEl = document.getElementById('drawer-safe-state');
  function isOn() { return document.documentElement.classList.contains('safe-mode'); }
  function syncUi() {
    const on = isOn();
    if (btn) { btn.setAttribute('aria-checked', on ? 'true' : 'false'); btn.classList.toggle('is-on', on); }
    if (stateEl) stateEl.textContent = on ? 'On' : 'Off';
  }
  function setSafe(on, persist) {
    document.documentElement.classList.toggle('safe-mode', !!on);
    if (persist) { try { localStorage.setItem(SAFE_KEY, on ? '1' : '0'); } catch {} }
    syncUi();
    try { render(); } catch {}
  }
  if (btn) btn.addEventListener('click', () => setSafe(!isOn(), true));
  // Gate resolves after boot on a fresh visit — re-sync + re-render then.
  window.addEventListener('frostline:safemode', (e) => setSafe(!!(e.detail && e.detail.on), false));
  syncUi();
})();

boot().catch((err) => {
  console.error('boot failed', err);
  renderEmpty('Failed to load. Refresh to try again.');
});
