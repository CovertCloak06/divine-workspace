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
let artData = []       // loaded from Blob, fallback to bundled ART
let deletedIds = new Set()  // IDs deleted by the editor — persisted in blob
let globalFlags = {}   // {[id]: noteText} — loaded from Blob

// ── Draw mode state ──────────────────────────────────────────────────────────
let drawGrid = []
let drawEraseMode = false
let drawHistory = []
let drawIsPainting = false
let drawCurrentSymbol = '❤'
const DRAW_PALETTE = ['❤','💛','💚','💙','💜','⭐','✦','★','♥','♠','♣','♦','◆','◇','●','○','▪','■','□','━','─','│','▲','▼','⬛','🟥','🟩','🟦','🟨','🟧','🟪','🌸','❄','✿','✾']

// ── Data validation ────────────────────────────────────────────────────────
const isValidPiece = p =>
  p && typeof p.id === 'string' && p.id.length > 0
  && typeof p.title === 'string'
  && typeof p.art === 'string'

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
function wosRenderLines(art) {
  return art.split('\n').map(line => {
    const esc = line.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') || '​'
    return graphemeCount(line) > 27
      ? `<span class="wos-over">${esc}</span>`
      : `<span>${esc}</span>`
  }).join('\n')
}

// ── WoS compatibility ──────────────────────────────────────────────────────
function normalizeSpaces(art) {
  return art ? art.replace(/ /g, ' ') : art  // U+0020 → U+00A0 (NBSP) for WoS paste
}

const WOS_SAFE_CP = cp =>
  cp === 0x0A || cp === 0xA0 || cp === 0x3000 ||           // newline, NBSP, fullwidth space
  (cp >= 0x21  && cp <= 0x7E)  ||                           // printable ASCII
  (cp >= 0x2500 && cp <= 0x27BF) ||                         // box/block/geometric/dingbats
  (cp >= 0x2600 && cp <= 0x26FF) ||                         // misc symbols
  (cp >= 0xFF00 && cp <= 0xFFEF) ||                         // fullwidth/halfwidth forms
  (cp >= 0x1F100 && cp <= 0x1FAFF)                          // emoji (broad range)

function wosAudit(art) {
  const issues = []
  if (art.includes(' ')) issues.push({ type: 'space', msg: 'Contains regular spaces — auto-converted on save. Copy from here, not the text editor, to get WoS-safe version.' })
  const unverified = new Set()
  for (const ch of art) { if (!WOS_SAFE_CP(ch.codePointAt(0))) unverified.add(ch) }
  if (unverified.size > 0) issues.push({ type: 'char', msg: `Unverified in WoS: ${[...unverified].join(' ')} — test in chat before publishing` })
  return issues
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
  if (ok && Array.isArray(data?.art)) {
    deletedIds = new Set(Array.isArray(data.deletedIds) ? data.deletedIds : [])
    const blobIndex = Object.fromEntries(data.art.map(p => [p.id, p]))
    // Bundle is source of truth for art content; blob contributes wosVerified + deletions
    artData = ART
      .filter(p => !deletedIds.has(p.id))
      .map(p => ({ ...p, wosVerified: blobIndex[p.id]?.wosVerified || p.wosVerified }))
    // Append user-created pieces that exist in blob but not in the bundle
    const bundleIds = new Set(ART.map(p => p.id))
    data.art.forEach(p => { if (!bundleIds.has(p.id) && !deletedIds.has(p.id) && isValidPiece(p)) artData.push(p) })
  } else {
    artData = ART.map(p => ({ ...p }))
  }
}

async function loadFlags() {
  const { ok, data } = await apiFetch(API.getFlags)
  if (ok && data?.flags) {
    globalFlags = Array.isArray(data.flags)
      ? Object.fromEntries(data.flags.map(id => [id, '']))
      : data.flags
  } else {
    globalFlags = {}
  }
}

async function saveArt() {
  const clean = artData.filter(isValidPiece)
  return apiFetch(API.saveArt, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${authState.password}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ art: clean, deletedIds: [...deletedIds] }),
  })
}

async function saveFlag(id, note = '') {
  const { ok, status, data } = await apiFetch(API.saveFlags, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id, action: 'toggle', note }),
  })
  if (ok && data) {
    if (data.flagged) globalFlags[id] = data.note ?? ''
    else delete globalFlags[id]
  }
  if (!ok) console.warn(`save-flags failed: HTTP ${status}`, data)
  return ok
}

async function saveNote(id, note) {
  const { ok } = await apiFetch(API.saveFlags, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id, action: 'note', note }),
  })
  if (ok) globalFlags[id] = note
  // Never delete globalFlags on note save — server now always writes without a
  // stale read, so flagged:false is no longer a valid response for this action.
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

// ── Flag helpers ───────────────────────────────────────────────────────────
function isFlagged(id) { return id in globalFlags }
function getNote(id)   { return globalFlags[id] || '' }

const _flagInFlight = new Set()

async function toggleFlag(id, el, noteEl) {
  if (_flagInFlight.has(id)) return  // same item already in-flight (e.g. double-tap)
  _flagInFlight.add(id)
  el.style.pointerEvents = 'none'
  const note = noteEl ? noteEl.value : ''
  const ok = await saveFlag(id, note)
  if (ok) {
    const flagged = isFlagged(id)
    el.classList.toggle('flagged', flagged)
    if (noteEl) {
      noteEl.style.display = flagged ? 'block' : 'none'
      noteEl.value = flagged ? getNote(id) : ''
    }
    renderTags()
  } else {
    const ft = el.querySelector('.flag-text')
    if (ft) {
      const prev = ft.textContent
      ft.textContent = '⚠ failed'
      ft.style.color = '#ef4444'
      setTimeout(() => { ft.textContent = prev; ft.style.color = '' }, 2500)
    }
  }
  _flagInFlight.delete(id)
  el.style.pointerEvents = ''
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
  if (authState.unlocked && Object.keys(globalFlags).length > 0) tagList.push(`flagged (${Object.keys(globalFlags).length})`)
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
  const b = document.createElement('span')
  const editorClass = authState.unlocked ? ' editor-toggle' : ''
  if (piece.wosVerified) {
    b.className = 'wos-badge wos-verified' + editorClass
    b.textContent = '✅ WoS'
    b.title = authState.unlocked ? 'Click to mark unverified' : 'Verified works in WoS chat'
  } else {
    b.className = 'wos-badge wos-unverified' + editorClass
    b.textContent = '? WoS'
    b.title = authState.unlocked ? 'Click to mark verified' : 'WoS compatibility not confirmed'
  }
  if (authState.unlocked) b.onclick = (e) => { e.stopPropagation(); toggleWosBadge(piece) }
  return b
}

async function toggleWosBadge(piece) {
  const idx = artData.findIndex(p => p.id === piece.id)
  if (idx < 0) return
  if (artData[idx].wosVerified) {
    delete artData[idx].wosVerified
  } else {
    artData[idx].wosVerified = true
  }
  delete artData[idx].wosRisk
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
      <textarea class="flag-note" placeholder="Why flagged? Add a note…" rows="2"></textarea>
      <button class="copy-btn">📋 Copy</button>
      <label class="flag-label">
        <span class="flag-box"></span>
        <span class="flag-text">flag</span>
      </label>
    `
    card.querySelector('.card-title').textContent = piece.title
    const sizeEl = card.querySelector('.card-size')
    const dims = autoDimensions(piece.art)
    sizeEl.textContent = `${dims.width}×${dims.height}`
    if (dims.width > 27) {
      sizeEl.classList.add('over-limit')
      sizeEl.title = 'Width exceeds WoS 27-char limit — may clip in chat'
    }
    const previewEl = card.querySelector('.preview')
    const preEl = card.querySelector('.preview pre')
    preEl.textContent = piece.art

    const tagBox = card.querySelector('.card-tags')
    for (const t of piece.tags) {
      const tEl = document.createElement('span')
      tEl.className = 'card-tag'
      tEl.textContent = t
      tagBox.appendChild(tEl)
    }

    const actions = card.querySelector('.card-actions')

    card.appendChild(makeBadge(piece))
    const auditIssues = wosAudit(piece.art)
    const charIssue = auditIssues.find(i => i.type === 'char')
    if (charIssue) {
      const warn = document.createElement('span')
      warn.className = 'wos-warn'
      warn.title = charIssue.msg
      warn.textContent = '⚠'
      card.querySelector('.card-head').appendChild(warn)
    }

    const flagLabel = card.querySelector('.flag-label')
    const flagNote  = card.querySelector('.flag-note')
    if (isFlagged(piece.id)) {
      flagLabel.classList.add('flagged')
      flagNote.style.display = 'block'
      flagNote.value = getNote(piece.id)
    }
    flagLabel.onclick = (e) => { e.stopPropagation(); toggleFlag(piece.id, flagLabel, flagNote) }
    flagNote.addEventListener('blur', () => { if (isFlagged(piece.id)) saveNote(piece.id, flagNote.value) })
    let _noteTimer
    flagNote.addEventListener('input', () => {
      if (!isFlagged(piece.id)) return
      clearTimeout(_noteTimer)
      _noteTimer = setTimeout(() => saveNote(piece.id, flagNote.value), 900)
    })
    flagNote.addEventListener('click', e => e.stopPropagation())

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
    btn.onclick = (e) => { e.stopPropagation(); copyToClipboard(normalizeSpaces(piece.art) || '', btn) }
    card.onclick = () => openModal(piece)
    $grid.appendChild(card)
  }
  setTimeout(fitAllPreviews, 50)
}

// ── Delete ─────────────────────────────────────────────────────────────────
async function deletePiece(id) {
  if (!confirm('Delete this piece?')) return
  deletedIds.add(id)
  artData = artData.filter(p => p.id !== id)
  const result = await saveArt()
  if (result.ok) renderGrid()
  else { deletedIds.delete(id); artData.push(...ART.filter(p => p.id === id)); renderGrid(); alert('Save failed (HTTP ' + result.status + '): ' + (result.data?.error || 'check your connection')) }
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
const $editAudit      = document.getElementById('edit-audit')
let editTarget = null

function updateEditAudit() {
  const issues = wosAudit($editArt.value)
  $editAudit.innerHTML = issues.map(i =>
    `<div class="audit-${i.type}">${i.msg}</div>`
  ).join('')
}
$editArt.addEventListener('input', updateEditAudit)

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
  updateEditAudit()
  $editModal.classList.add('open')
  // Reset to text mode when opening
  const drawContainer = document.getElementById('draw-canvas-container')
  const artDiv = $editArt.closest('div')
  if (drawContainer) {
    drawContainer.style.display = 'none'
    if (artDiv) artDiv.style.display = ''
  }
  const textBtn = document.getElementById('edit-text-mode-btn')
  const drawBtn = document.getElementById('edit-draw-mode-btn')
  if (textBtn) { textBtn.classList.add('active'); drawBtn.classList.remove('active') }
  drawGrid = []
  drawHistory = []
  drawEraseMode = false
  setTimeout(() => $editTitle.focus(), 50)
}
function closeEditModal() {
  $editModal.classList.remove('open')
  editTarget = null
  drawGrid = []; drawHistory = []; drawEraseMode = false; drawIsPainting = false
}

document.getElementById('edit-modal-close').onclick = closeEditModal
document.getElementById('edit-cancel').onclick = closeEditModal
$editModal.addEventListener('click', e => { if (e.target === $editModal) closeEditModal() })

document.getElementById('edit-save').onclick = async () => {
  // Sync art from draw grid if draw mode is active
  const drawContainer = document.getElementById('draw-canvas-container')
  if (drawContainer && drawContainer.style.display !== 'none' && drawGrid.length > 0) {
    $editArt.value = gridToArt(drawGrid)
  }
  const title = $editTitle.value.trim()
  const tags  = $editTags.value.split(',').map(t => t.trim()).filter(Boolean)
  const art   = normalizeSpaces($editArt.value)
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

  const result = await saveArt()
  if (result.ok) { closeEditModal(); renderGrid() }
  else alert('Save failed (HTTP ' + result.status + '): ' + (result.data?.error || 'check your connection'))
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
  $modalPreviewWrap.classList.add('wos-mode')
  $modalPreview.innerHTML = wosRenderLines(normalizeSpaces(piece.art) || '')
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
  $modalCopy.onclick = () => copyToClipboard(normalizeSpaces(piece.art) || '', $modalCopy)
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

// ── Secret snowflake trigger (7 taps) ─────────────────────────────────────
let snowTaps = 0, snowTimer = null
document.getElementById('snowflake-trigger').addEventListener('click', () => {
  snowTaps++
  clearTimeout(snowTimer)
  if (snowTaps >= 7) {
    snowTaps = 0
    $lockBtn.onclick()
  } else {
    snowTimer = setTimeout(() => { snowTaps = 0 }, 3000)
  }
})

// ── Tag strip scroll arrows ────────────────────────────────────────────────
const $tagsEl    = document.getElementById('tags')
const $tagsLeft  = document.getElementById('tags-left')
const $tagsRight = document.getElementById('tags-right')

function updateTagArrows() {
  const { scrollLeft, scrollWidth, clientWidth } = $tagsEl
  $tagsLeft.classList.toggle('visible', scrollLeft > 4)
  $tagsRight.classList.toggle('visible', scrollLeft + clientWidth < scrollWidth - 4)
}

$tagsEl.addEventListener('scroll', updateTagArrows)
$tagsLeft.addEventListener('click',  () => { $tagsEl.scrollLeft -= 120; updateTagArrows() })
$tagsRight.addEventListener('click', () => { $tagsEl.scrollLeft += 120; updateTagArrows() })
new ResizeObserver(updateTagArrows).observe($tagsEl)

// ── Draw mode functions ───────────────────────────────────────────────────────

function artToGrid(art, cols) {
  const lines = art.split('\n')
  const parsedLines = lines.map(line => {
    if (segmenter) {
      return [...segmenter.segment(line)].map(s => s.segment)
    }
    return [...line]
  })
  const maxCols = cols ?? Math.max(1, ...parsedLines.map(r => r.length))
  return parsedLines.map(row => {
    const padded = row.slice(0, maxCols)
    while (padded.length < maxCols) padded.push(' ')
    return padded
  })
}

function gridToArt(grid) {
  const rows = grid.map(row => row.join('').replace(/ +$/, ''))
  // rtrim trailing empty lines
  let end = rows.length
  while (end > 0 && rows[end - 1] === '') end--
  return rows.slice(0, end).join('\n')
}

function renderDrawPalette() {
  const palette = document.getElementById('draw-palette')
  if (!palette) return
  palette.innerHTML = ''
  for (const sym of DRAW_PALETTE) {
    const btn = document.createElement('button')
    btn.className = 'draw-palette-btn' + (sym === drawCurrentSymbol ? ' active' : '')
    btn.textContent = sym
    btn.title = sym
    btn.onclick = () => {
      drawCurrentSymbol = sym
      drawEraseMode = false
      const eraserBtn = document.getElementById('draw-eraser-btn')
      if (eraserBtn) eraserBtn.classList.remove('active')
      palette.querySelectorAll('.draw-palette-btn').forEach(b => b.classList.remove('active'))
      btn.classList.add('active')
    }
    palette.appendChild(btn)
  }

  const undoBtn = document.getElementById('draw-undo-btn')
  if (undoBtn) {
    undoBtn.onclick = () => {
      if (drawHistory.length === 0) return
      drawGrid = drawHistory.pop()
      renderDrawCanvas()
    }
  }

  const eraserBtn = document.getElementById('draw-eraser-btn')
  if (eraserBtn) {
    eraserBtn.onclick = () => {
      drawEraseMode = !drawEraseMode
      eraserBtn.classList.toggle('active', drawEraseMode)
      if (drawEraseMode) {
        palette.querySelectorAll('.draw-palette-btn').forEach(b => b.classList.remove('active'))
      } else {
        palette.querySelectorAll('.draw-palette-btn').forEach(b => {
          b.classList.toggle('active', b.textContent === drawCurrentSymbol)
        })
      }
    }
  }
}

function renderDrawCanvas() {
  const canvas = document.getElementById('draw-canvas')
  if (!canvas) return
  canvas.innerHTML = ''
  for (let r = 0; r < drawGrid.length; r++) {
    const rowEl = document.createElement('div')
    rowEl.className = 'draw-row'
    for (let c = 0; c < drawGrid[r].length; c++) {
      const cell = document.createElement('span')
      cell.className = 'draw-cell'
      cell.dataset.row = r
      cell.dataset.col = c
      cell.textContent = drawGrid[r][c]
      rowEl.appendChild(cell)
    }
    canvas.appendChild(rowEl)
  }
}

function pushDrawHistory() {
  drawHistory.push(drawGrid.map(row => row.slice()))
  if (drawHistory.length > 20) drawHistory.shift()
}

function paintDrawCell(row, col) {
  if (row < 0 || row >= drawGrid.length || col < 0 || col >= drawGrid[row].length) return
  if (drawEraseMode) {
    drawGrid[row][col] = ' '
  } else {
    drawGrid[row][col] = drawCurrentSymbol
  }
  const canvas = document.getElementById('draw-canvas')
  if (!canvas) return
  const cellEl = canvas.querySelector(`[data-row="${row}"][data-col="${col}"]`)
  if (cellEl) cellEl.textContent = drawGrid[row][col]
}

function initDrawMode() {
  drawGrid = artToGrid($editArt.value)
  drawHistory = []
  drawEraseMode = false
  drawIsPainting = false
  renderDrawPalette()

  // Replace canvas node to shed any stale event listeners from a previous open
  const oldCanvas = document.getElementById('draw-canvas')
  if (!oldCanvas) return
  const freshCanvas = oldCanvas.cloneNode(false)
  oldCanvas.parentNode.replaceChild(freshCanvas, oldCanvas)

  // Render cells into the fresh node
  renderDrawCanvas()

  freshCanvas.addEventListener('pointerdown', e => {
    const target = e.target
    if (!target.classList.contains('draw-cell')) return
    pushDrawHistory()
    drawIsPainting = true
    const row = parseInt(target.dataset.row, 10)
    const col = parseInt(target.dataset.col, 10)
    paintDrawCell(row, col)
    freshCanvas.setPointerCapture(e.pointerId)
    e.preventDefault()
  })

  freshCanvas.addEventListener('pointermove', e => {
    if (!drawIsPainting) return
    const el = document.elementFromPoint(e.clientX, e.clientY)
    if (!el || !el.classList.contains('draw-cell')) return
    const row = parseInt(el.dataset.row, 10)
    const col = parseInt(el.dataset.col, 10)
    if (!isNaN(row) && !isNaN(col)) paintDrawCell(row, col)
    e.preventDefault()
  })

  const stopPainting = () => { drawIsPainting = false }
  document.addEventListener('pointerup', stopPainting)
  document.addEventListener('pointercancel', stopPainting)
}

// ── Draw mode toggle ──────────────────────────────────────────────────────────
function setupDrawModeToggle() {
  const textBtn = document.getElementById('edit-text-mode-btn')
  const drawBtn = document.getElementById('edit-draw-mode-btn')
  const drawContainer = document.getElementById('draw-canvas-container')
  if (!textBtn || !drawBtn || !drawContainer) return

  textBtn.onclick = () => {
    // Sync textarea from current draw grid if draw mode was active
    if (drawGrid.length > 0) $editArt.value = gridToArt(drawGrid)
    const artDiv = $editArt.closest('div')
    if (artDiv) artDiv.style.display = ''
    drawContainer.style.display = 'none'
    textBtn.classList.add('active')
    drawBtn.classList.remove('active')
    updateEditAudit()
  }

  drawBtn.onclick = () => {
    const artDiv = $editArt.closest('div')
    if (artDiv) artDiv.style.display = 'none'
    drawContainer.style.display = ''
    textBtn.classList.remove('active')
    drawBtn.classList.add('active')
    initDrawMode()
  }
}
setupDrawModeToggle()

// ── Init ───────────────────────────────────────────────────────────────────
async function initApp() {
  await Promise.all([loadArt(), loadFlags()])
  renderTags()
  updateTagArrows()
  renderGrid()
  document.getElementById('export-btn').disabled = false
}

initApp()
