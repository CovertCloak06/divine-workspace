/* TurfPro — Field Turf job & material estimator
 *
 * Pure client-side, no build step, works offline. All state lives in the DOM
 * inputs; saved jobs persist to localStorage. Every calculation is an estimate
 * — real orders should add a safety margin and confirm supplier pack sizes.
 *
 * Calculation model
 * -----------------
 *   net area      = Σ(length × width) of each measured rectangle
 *   gross area    = net × (1 + waste%)          ← turf you actually buy/lay
 *   turf rolls    = ceil(gross / rollWidth)  linear-ft strips (informational)
 *   infill        = net × infillRate (lb)        ← infill covers laid area
 *   base material = net × (depth_ft) / 27 (yd³)  ← sub-base under the turf
 *   nails         = round(net × nailRate)
 *   seam          = seamLen × seamPrice
 *   labor         = net × laborRate
 *   markup        = subtotal × markup%
 */

const STORE_KEY = 'turfpro.jobs.v1';
const VERSION = 'v1';

/* ---------- tiny helpers ---------- */
const $ = (id) => document.getElementById(id);
const num = (el) => {
  const v = parseFloat(el && el.value);
  return Number.isFinite(v) ? v : 0;
};
const money = (n) =>
  '$' + (Math.round(n * 100) / 100).toLocaleString('en-US', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
const fmt = (n, digits = 0) =>
  n.toLocaleString('en-US', { maximumFractionDigits: digits });
// Local YYYY-MM-DD. Avoids toISOString() (UTC), which rolls to tomorrow in the
// evening for users west of UTC and would default the job date a day ahead.
const todayLocal = () => {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
};

/* ---------- area rows ---------- */
const areaRows = $('area-rows');

function addAreaRow(len = '', wid = '') {
  const row = document.createElement('div');
  row.className = 'area-row';
  row.innerHTML = `
    <input class="len" type="number" min="0" step="0.1" inputmode="decimal" placeholder="Length" />
    <span class="times">×</span>
    <input class="wid" type="number" min="0" step="0.1" inputmode="decimal" placeholder="Width" />
    <span class="sqft">0 ft²</span>
    <button class="remove" type="button" aria-label="Remove area">✕</button>`;
  row.querySelector('.len').value = len;
  row.querySelector('.wid').value = wid;
  areaRows.appendChild(row);
  return row;
}

function netArea() {
  let total = 0;
  areaRows.querySelectorAll('.area-row').forEach((row) => {
    const l = num(row.querySelector('.len'));
    const w = num(row.querySelector('.wid'));
    const sq = l * w;
    row.querySelector('.sqft').textContent = fmt(sq, 1) + ' ft²';
    total += sq;
  });
  return total;
}

/* ---------- core estimate ---------- */
function calc() {
  const net = netArea();
  const waste = num($('waste')) / 100;
  const gross = net * (1 + waste);

  const rollWidth = num($('roll-width')) || 15;
  const turfPrice = num($('turf-price'));
  const infillRate = num($('infill-rate'));
  const infillPrice = num($('infill-price'));
  const baseDepthIn = num($('base-depth'));
  const basePrice = num($('base-price'));
  const nailRate = num($('nail-rate'));
  const nailPrice = num($('nail-price'));
  const seamLen = num($('seam-len'));
  const seamPrice = num($('seam-price'));
  const laborRate = num($('labor-rate'));
  const markupPct = num($('markup')) / 100;

  // Quantities
  const turfSqft = gross;                       // buy turf at gross (waste incl.)
  const rollStrips = rollWidth > 0 ? Math.ceil(gross / rollWidth) : 0;
  const infillLb = net * infillRate;
  const infillBags = Math.ceil(infillLb / 50);  // typical 50 lb bag
  const baseYd3 = (net * (baseDepthIn / 12)) / 27;
  const nails = Math.round(net * nailRate);

  // Costs
  const items = [
    {
      name: 'Turf',
      qty: `${fmt(turfSqft, 0)} ft²`,
      sub: `${rollStrips} strip${rollStrips === 1 ? '' : 's'} @ ${fmt(rollWidth, 0)}ft`,
      cost: turfSqft * turfPrice,
    },
    {
      name: 'Infill',
      qty: `${fmt(infillLb, 0)} lb`,
      sub: `~${infillBags} × 50 lb bag`,
      cost: infillLb * infillPrice,
    },
    {
      name: 'Base material',
      qty: `${fmt(baseYd3, 1)} yd³`,
      sub: `${fmt(baseDepthIn, 1)}" deep`,
      cost: baseYd3 * basePrice,
    },
    {
      name: 'Nails / staples',
      qty: `${fmt(nails, 0)} pcs`,
      sub: '',
      cost: nails * nailPrice,
    },
    {
      name: 'Seaming',
      qty: `${fmt(seamLen, 0)} ft`,
      sub: '',
      cost: seamLen * seamPrice,
    },
    {
      name: 'Labor',
      qty: `${fmt(net, 0)} ft²`,
      sub: '',
      cost: net * laborRate,
    },
  ];

  const subtotal = items.reduce((s, it) => s + it.cost, 0);
  const markup = subtotal * markupPct;
  const total = subtotal + markup;

  return { net, gross, items, subtotal, markup, total };
}

/* ---------- render ---------- */
function render() {
  const r = calc();

  $('net-area').textContent = fmt(r.net, 0) + ' ft²';
  $('gross-area').textContent = fmt(r.gross, 0) + ' ft² with waste';

  const body = $('est-body');
  body.innerHTML = '';
  r.items.forEach((it) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${it.name}</td>
      <td>${it.qty}${it.sub ? `<span class="qty-sub">${it.sub}</span>` : ''}</td>
      <td class="num">${money(it.cost)}</td>`;
    body.appendChild(tr);
  });

  $('est-subtotal').textContent = money(r.subtotal);
  $('est-markup').textContent = money(r.markup);
  $('est-total').textContent = money(r.total);
}

/* ---------- serialize / restore form ---------- */
const FIELD_IDS = [
  'job-name', 'job-date', 'job-address', 'waste', 'roll-width', 'turf-price',
  'infill-rate', 'infill-price', 'base-depth', 'base-price', 'nail-rate',
  'nail-price', 'seam-len', 'seam-price', 'labor-rate', 'markup',
];

function collectJob() {
  const fields = {};
  FIELD_IDS.forEach((id) => { fields[id] = $(id).value; });
  const areas = [];
  areaRows.querySelectorAll('.area-row').forEach((row) => {
    areas.push({
      len: row.querySelector('.len').value,
      wid: row.querySelector('.wid').value,
    });
  });
  const r = calc();
  return {
    id: 'j' + Date.now().toString(36),
    savedAt: new Date().toISOString(),
    fields,
    areas,
    total: r.total,
    net: r.net,
  };
}

function loadJob(job) {
  FIELD_IDS.forEach((id) => {
    if (job.fields && id in job.fields) $(id).value = job.fields[id];
  });
  areaRows.innerHTML = '';
  (job.areas && job.areas.length ? job.areas : [{ len: '', wid: '' }])
    .forEach((a) => addAreaRow(a.len, a.wid));
  render();
}

/* ---------- localStorage ---------- */
function readJobs() {
  try {
    return JSON.parse(localStorage.getItem(STORE_KEY)) || [];
  } catch {
    return [];
  }
}
function writeJobs(jobs) {
  localStorage.setItem(STORE_KEY, JSON.stringify(jobs));
}

function renderSaved() {
  const jobs = readJobs().sort((a, b) => (a.savedAt < b.savedAt ? 1 : -1));
  const list = $('saved-list');
  const empty = $('saved-empty');
  list.innerHTML = '';
  empty.style.display = jobs.length ? 'none' : '';

  jobs.forEach((job) => {
    const name = (job.fields && job.fields['job-name']) || 'Untitled job';
    const date = (job.fields && job.fields['job-date']) || job.savedAt.slice(0, 10);
    const item = document.createElement('div');
    item.className = 'saved-item';
    item.innerHTML = `
      <div class="meta">
        <span class="name"></span>
        <span class="sub">${date} · ${fmt(job.net || 0, 0)} ft²</span>
      </div>
      <span class="price">${money(job.total || 0)}</span>
      <div class="row-actions">
        <button class="open" title="Open">📂</button>
        <button class="del" title="Delete">🗑</button>
      </div>`;
    item.querySelector('.name').textContent = name; // textContent = XSS-safe
    item.querySelector('.open').addEventListener('click', () => {
      loadJob(job);
      toast('Job loaded');
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
    item.querySelector('.del').addEventListener('click', () => {
      writeJobs(readJobs().filter((j) => j.id !== job.id));
      renderSaved();
      toast('Job deleted');
    });
    list.appendChild(item);
  });
}

/* ---------- share ---------- */
function jobText() {
  const r = calc();
  const name = $('job-name').value || 'Turf job';
  const addr = $('job-address').value;
  const lines = [
    `TurfPro estimate — ${name}`,
    addr ? addr : null,
    `Area: ${fmt(r.net, 0)} ft² (net) / ${fmt(r.gross, 0)} ft² w/ waste`,
    '',
    ...r.items.map((it) => `${it.name}: ${it.qty} — ${money(it.cost)}`),
    '',
    `Subtotal: ${money(r.subtotal)}`,
    `Markup:   ${money(r.markup)}`,
    `TOTAL:    ${money(r.total)}`,
    '',
    'Estimate only.',
  ];
  return lines.filter((l) => l !== null).join('\n');
}

async function shareJob() {
  const text = jobText();
  if (navigator.share) {
    try {
      await navigator.share({ title: 'TurfPro estimate', text });
      return;
    } catch {
      /* user cancelled — fall through to clipboard */
    }
  }
  try {
    await navigator.clipboard.writeText(text);
    toast('Estimate copied');
  } catch {
    toast('Copy not supported');
  }
}

/* ---------- toast ---------- */
let toastTimer;
function toast(msg) {
  const t = $('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 1800);
}

/* ---------- reset ---------- */
function newJob() {
  FIELD_IDS.forEach((id) => {
    const el = $(id);
    if (id === 'job-name' || id === 'job-address') el.value = '';
    else if (id === 'job-date') el.value = todayLocal();
    // numeric settings keep their defaults from the HTML
  });
  areaRows.innerHTML = '';
  addAreaRow();
  render();
  window.scrollTo({ top: 0, behavior: 'smooth' });
  toast('New job');
}

/* ---------- wire up ---------- */
function init() {
  // Default date = today
  if (!$('job-date').value) $('job-date').value = todayLocal();

  // Start with two area rows
  addAreaRow();
  addAreaRow();

  // Recalc on any input, anywhere
  document.addEventListener('input', render);

  // Remove-area (event delegation)
  areaRows.addEventListener('click', (e) => {
    if (e.target.classList.contains('remove')) {
      const rows = areaRows.querySelectorAll('.area-row');
      if (rows.length > 1) e.target.closest('.area-row').remove();
      else { // keep at least one row, just clear it
        const row = e.target.closest('.area-row');
        row.querySelector('.len').value = '';
        row.querySelector('.wid').value = '';
      }
      render();
    }
  });

  $('add-area').addEventListener('click', () => { addAreaRow(); });
  $('new-job').addEventListener('click', newJob);
  $('save-job').addEventListener('click', () => {
    const jobs = readJobs();
    jobs.push(collectJob());
    writeJobs(jobs);
    renderSaved();
    toast('Job saved');
  });
  $('share-job').addEventListener('click', shareJob);

  renderSaved();
  render();

  // Version label from version.json (best effort)
  fetch('version.json', { cache: 'no-store' })
    .then((r) => r.json())
    .then((v) => { $('app-version').textContent = v.version || VERSION; })
    .catch(() => { $('app-version').textContent = VERSION; });

  // Service worker for offline
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').catch(() => {});
  }
}

document.addEventListener('DOMContentLoaded', init);
