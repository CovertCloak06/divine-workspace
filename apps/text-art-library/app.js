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
  const { ok, status, data } = await apiFetch(API.saveFlags, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id }),
  })
  if (ok && Array.isArray(data?.flags)) globalFlags = data.flags
  if (!ok) console.warn(`save-flags failed: HTTP ${status}`, data)
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

// ── Flag helpers ───────────────────────────────────────────────────────────
function isFlagged(id) { return globalFlags.includes(id) }

async function toggleFlag(id, el) {
  el.style.pointerEvents = 'none'
  const ok = await saveFlag(id)
  if (ok) {
    el.classList.toggle('flagged', isFlagged(id))
    renderTags()
  }
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
      <label class="flag-label">
        <span class="flag-box"></span>
        <span class="flag-text">flag</span>
      </label>
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

    const badge = makeBadge(piece)
    if (badge) actions.appendChild(badge)

    const flagLabel = card.querySelector('.flag-label')
    if (isFlagged(piece.id)) flagLabel.classList.add('flagged')
    flagLabel.onclick = (e) => { e.stopPropagation(); toggleFlag(piece.id, flagLabel) }

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

// ── Init ───────────────────────────────────────────────────────────────────
async function initApp() {
  await Promise.all([loadArt(), loadFlags()])
  renderTags()
  updateTagArrows()
  renderGrid()
}

initApp()
