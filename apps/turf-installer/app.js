/* TurfPro — on-the-job Field Turf calculators (prototype)
 *
 * Pure client-side, no build step, offline-capable. Six calculator modules
 * behind a tab bar: Turf & Rolls, Base Rock, Infill, Seam & Nails, Estimate,
 * Convert. Each reusable "area block" lets a worker measure once per module.
 *
 * Specs baked into the defaults come from published turf-install guidance:
 *   - Base: Class II road base ≈ 1.5 t/yd³, crushed rock ≈ 1.4, DG ≈ 1.45;
 *     order ~15–20% extra loose to cover compaction. yd³ = area·(in/12)/27.
 *   - Infill: residential ~2 lb/ft², pet/play ~3, sports fields ≥6 lb/ft².
 *   - Fasteners: perimeter nails every 4–8″, seams zig-zag every 2–3″.
 * All outputs are ESTIMATES — confirm supplier pack sizes and add margin.
 */

const STORE_KEY = 'turfpro.jobs.v2';
const VERSION = 'v4';

/* ---------- helpers ---------- */
const $ = (id) => document.getElementById(id);
const num = (el) => {
  const v = parseFloat(typeof el === 'string' ? $(el)?.value : el?.value);
  return Number.isFinite(v) ? v : 0;
};
const money = (n) =>
  '$' + (Math.round(n * 100) / 100).toLocaleString('en-US', {
    minimumFractionDigits: 2, maximumFractionDigits: 2,
  });
const fmt = (n, d = 0) => n.toLocaleString('en-US', { maximumFractionDigits: d });
const todayLocal = () => {
  const d = new Date(); const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
};
// HTML-escape anything that round-trips through localStorage or an input
// before it reaches an innerHTML template.
const esc = (s) => String(s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
// Collision-proof id: Date.now alone can collide on same-ms double taps.
const uid = (prefix) =>
  prefix + Date.now().toString(36) + Math.random().toString(36).slice(2, 7);

/* ---------- reusable area block ---------- */
/* Each <div class="area-block" data-area="KEY"> becomes a mini measurer with
 * length×width rows and a live square-footage readout. areaTotal(KEY) reads it. */
const areaBlocks = {};

function buildAreaBlock(el) {
  const key = el.dataset.area;
  el.innerHTML = `
    <div class="rows"></div>
    <button class="btn small add-area" type="button">+ Add area</button>
    <div class="readout">
      <span class="readout-label">Measured area</span>
      <span class="readout-value net">0 ft²</span>
    </div>`;
  const rows = el.querySelector('.rows');
  areaBlocks[key] = { el, rows };

  const addRow = (l = '', w = '') => {
    const row = document.createElement('div');
    row.className = 'area-row';
    row.innerHTML = `
      <input class="len" type="number" min="0" step="0.1" inputmode="decimal" placeholder="Length" />
      <span class="times">×</span>
      <input class="wid" type="number" min="0" step="0.1" inputmode="decimal" placeholder="Width" />
      <span class="sqft">0 ft²</span>
      <button class="remove" type="button" aria-label="Remove">✕</button>`;
    row.querySelector('.len').value = l;
    row.querySelector('.wid').value = w;
    rows.appendChild(row);
  };
  areaBlocks[key].addRow = addRow;

  addRow();
  el.querySelector('.add-area').addEventListener('click', () => { addRow(); render(); });
  rows.addEventListener('click', (e) => {
    if (!e.target.classList.contains('remove')) return;
    if (rows.querySelectorAll('.area-row').length > 1) e.target.closest('.area-row').remove();
    else {
      const r = e.target.closest('.area-row');
      r.querySelector('.len').value = ''; r.querySelector('.wid').value = '';
    }
    render();
  });
}

function areaTotal(key) {
  const b = areaBlocks[key];
  if (!b) return 0;
  let total = 0;
  b.rows.querySelectorAll('.area-row').forEach((row) => {
    const sq = num(row.querySelector('.len')) * num(row.querySelector('.wid'));
    row.querySelector('.sqft').textContent = fmt(sq, 1) + ' ft²';
    total += sq;
  });
  b.el.querySelector('.net').textContent = fmt(total, 0) + ' ft²';
  return total;
}

/* small result-line renderer */
function lines(targetId, items) {
  $(targetId).innerHTML = items.map((it) =>
    `<div class="res-line${it.big ? ' big' : ''}">
       <span class="res-k">${esc(it.k)}</span>
       <span class="res-v">${esc(it.v)}</span>
     </div>`).join('');
}

/* ---------- calculators ---------- */
function calcTurf() {
  const net = areaTotal('turf');
  const waste = num('turf-waste') / 100;
  const gross = net * (1 + waste);
  const width = num('turf-roll-width') || 15;
  const linear = width > 0 ? gross / width : 0;   // total linear ft off the roll
  lines('turf-results', [
    { k: 'Net area', v: fmt(net, 0) + ' ft²' },
    { k: `With ${fmt(waste * 100, 0)}% waste`, v: fmt(gross, 0) + ' ft²', big: true },
    { k: `Roll to buy @ ${fmt(width, 0)} ft wide`, v: fmt(linear, 1) + ' linear ft' },
    { k: 'That covers', v: fmt(linear * width, 0) + ' ft²' },
  ]);
  calcCutPlan(width);
}

/* Cut plan: for each measured area, lay strips of roll-width `rw` in both
 * orientations, compare waste, and estimate seam length. Real jobs often
 * force one orientation (grain direction) — this is an estimate. */
function planRect(L, W, rw) {
  // strips run along the L dimension, stacked across W
  const across = (len, span) => {
    const strips = Math.ceil(span / rw);
    return {
      strips,
      linear: strips * len,
      seamFt: Math.max(0, strips - 1) * len,
      wasteArea: (strips * rw - span) * len,
    };
  };
  const a = across(L, W);   // strips along length
  const b = across(W, L);   // strips along width
  const best = a.wasteArea < b.wasteArea ? a
    : b.wasteArea < a.wasteArea ? b
    : (a.seamFt <= b.seamFt ? a : b);
  return { a, b, best };
}

let cutSeamTotal = 0;

function calcCutPlan(rw) {
  const rowsEl = areaBlocks.turf && areaBlocks.turf.rows;
  const container = $('cut-plan');
  if (!rowsEl || !container) return;
  container.innerHTML = '';
  let seamTotal = 0, linearTotal = 0, wasteTotal = 0, idx = 0;

  rowsEl.querySelectorAll('.area-row').forEach((row) => {
    const L = num(row.querySelector('.len'));
    const W = num(row.querySelector('.wid'));
    if (L <= 0 || W <= 0) return;
    idx += 1;
    const { a, b, best } = planRect(L, W, rw);
    seamTotal += best.seamFt;
    linearTotal += best.linear;
    wasteTotal += best.wasteArea;
    const div = document.createElement('div');
    div.className = 'cut-area';
    const opt = (o, tag) =>
      `<span class="cut-opt${o === best ? ' best' : ''}">${tag}: ${o.strips} strip${o.strips === 1 ? '' : 's'}, ` +
      `${fmt(o.seamFt, 0)} ft seam, ${fmt(o.wasteArea, 0)} ft² waste</span>`;
    div.innerHTML = `<span class="cut-title">Area ${idx} — ${fmt(L, 1)} × ${fmt(W, 1)} ft</span>` +
      opt(a, 'Strips along length') + opt(b, 'Strips along width');
    container.appendChild(div);
  });

  cutSeamTotal = seamTotal;
  lines('cut-results', idx === 0 ? [
    { k: 'Cut plan', v: 'enter areas above' },
  ] : [
    { k: 'Linear roll (best layout)', v: fmt(linearTotal, 0) + ' ft' },
    { k: 'Layout waste', v: fmt(wasteTotal, 0) + ' ft²' },
    { k: 'Estimated seams', v: fmt(seamTotal, 0) + ' ft', big: true },
  ]);
}

function calcBase() {
  const net = areaTotal('base');
  const depthFt = num('base-depth') / 12;
  const comp = 1 + num('base-compaction') / 100;
  const tonsPerYd = num('base-material') || 1.5;
  const yd3Compacted = (net * depthFt) / 27;
  const yd3Order = yd3Compacted * comp;          // loose volume to buy
  const tons = yd3Order * tonsPerYd;
  const cost = tons * num('base-price');
  lines('base-results', [
    { k: 'Compacted volume', v: fmt(yd3Compacted, 2) + ' yd³' },
    { k: 'Order (loose)', v: fmt(yd3Order, 2) + ' yd³' },
    { k: 'Weight', v: fmt(tons, 2) + ' tons', big: true },
    { k: 'Cost', v: money(cost) },
  ]);
}

const SAND_TONS_PER_YD3 = 1.35;   // dry masonry/silica sand ≈ 2700 lb/yd³

function calcInfill() {
  const net = areaTotal('infill');

  // --- Layer 1: sand ---
  const sandLb = net * num('sand-rate');
  const sandTons = sandLb / 2000;
  const sandYd3 = sandTons / SAND_TONS_PER_YD3;
  const sandBagSize = num('sand-bag') || 50;
  const sandBags = Math.ceil(sandLb / sandBagSize);
  const supply = $('sand-supply').value;
  // show/hide bulk vs bag inputs
  document.querySelectorAll('.sand-bulk').forEach((n) => n.style.display = supply === 'bulk' ? '' : 'none');
  document.querySelectorAll('.sand-bag').forEach((n) => n.style.display = supply === 'bags' ? '' : 'none');
  const sandCost = supply === 'bulk'
    ? sandTons * num('sand-ton-price')
    : sandBags * num('sand-bag-price');
  lines('sand-results', [
    { k: 'Total sand', v: fmt(sandLb, 0) + ' lb', big: true },
    { k: 'If bulk', v: `${fmt(sandTons, 2)} tons · ${fmt(sandYd3, 2)} yd³` },
    { k: `If bagged (${fmt(sandBagSize, 0)} lb)`, v: `${sandBags} bag${sandBags === 1 ? '' : 's'}` },
    { k: `Cost (${supply})`, v: money(sandCost) },
  ]);

  // --- Layer 2: top fill (priced per bag, matching the label) ---
  const topLb = net * num('top-rate');
  const topBagSize = num('top-bag') || 50;
  const topBags = Math.ceil(topLb / topBagSize);
  const topCost = topBags * num('top-price');
  lines('top-results', [
    { k: 'Product', v: $('top-product').value },
    { k: 'Total top fill', v: fmt(topLb, 0) + ' lb', big: true },
    { k: `Bags (${fmt(topBagSize, 0)} lb)`, v: `${topBags} bag${topBags === 1 ? '' : 's'}` },
    { k: 'Cost', v: money(topCost) },
  ]);

  // --- combined ---
  lines('infill-results', [
    { k: 'Combined infill', v: fmt(sandLb + topLb, 0) + ' lb', big: true },
    { k: 'Combined rate', v: fmt(net > 0 ? (sandLb + topLb) / net : 0, 1) + ' lb/ft²' },
    { k: 'Infill cost', v: money(sandCost + topCost) },
  ]);
  return { sandLb, topLb, sandCost, topCost, net };
}

function calcSeam() {
  const len = num('seam-len');
  const glueCover = num('glue-cover') || 60;
  const tapeRoll = num('tape-roll') || 100;
  const gallons = len > 0 ? Math.ceil(len / glueCover) : 0;
  const tapeRolls = len > 0 ? Math.ceil(len / tapeRoll) : 0;
  const cost = gallons * num('glue-price');
  lines('seam-results', [
    { k: 'Seam tape', v: `${tapeRolls} roll${tapeRolls === 1 ? '' : 's'} (${fmt(len, 0)} ft)` },
    { k: 'Glue', v: `${gallons} gal`, big: true },
    { k: 'Glue cost', v: money(cost) },
  ]);
}

function calcNails() {
  const net = areaTotal('fasten');
  const perim = num('perimeter');
  const perimSp = num('perim-spacing') || 6;
  const seam = num('seam-len-2');
  const seamSp = num('seam-spacing') || 3;
  const fieldRate = num('field-rate');
  const box = num('nail-box') || 250;
  // spacing in inches → nails = length_ft × 12 / spacing_in
  const perimNails = perimSp > 0 ? (perim * 12) / perimSp : 0;
  const seamNails = seamSp > 0 ? (seam * 12) / seamSp : 0;
  const fieldNails = net * fieldRate;
  const total = Math.round(perimNails + seamNails + fieldNails);
  const boxes = Math.ceil(total / box);
  lines('nail-results', [
    { k: 'Perimeter', v: fmt(perimNails, 0) + ' nails' },
    { k: 'Seams', v: fmt(seamNails, 0) + ' nails' },
    { k: 'Field', v: fmt(fieldNails, 0) + ' nails' },
    { k: 'Total', v: fmt(total, 0) + ' nails', big: true },
    { k: `Boxes (${fmt(box, 0)})`, v: `${boxes} box${boxes === 1 ? '' : 'es'}` },
  ]);
}

/* ---------- estimate (pulls area + rates from the other tabs) ---------- */
function calcEstimate() {
  const net = areaTotal('estimate');
  const waste = num('est-waste') / 100;
  const gross = net * (1 + waste);

  const turf = gross * num('est-turf-price');
  // infill: sand layer + top fill, using the rates from the Infill tab
  const sandLb = net * num('sand-rate');
  const topLb = net * num('top-rate');
  const infillLb = sandLb + topLb;
  const sandCost = $('sand-supply').value === 'bulk'
    ? (sandLb / 2000) * num('sand-ton-price')
    : Math.ceil(sandLb / (num('sand-bag') || 50)) * num('sand-bag-price');
  const topBags = Math.ceil(topLb / (num('top-bag') || 50));
  const infill = sandCost + topBags * num('top-price');
  const depthFt = num('base-depth') / 12;
  const yd3 = (net * depthFt) / 27 * (1 + num('base-compaction') / 100);
  const base = yd3 * (num('base-material') || 1.5) * num('base-price');
  const seamGal = num('seam-len') > 0 ? Math.ceil(num('seam-len') / (num('glue-cover') || 60)) : 0;
  const seam = seamGal * num('glue-price');
  const labor = net * num('est-labor');

  const items = [
    { name: 'Turf', qty: `${fmt(gross, 0)} ft²`, cost: turf },
    { name: 'Infill', qty: `${fmt(infillLb, 0)} lb`, cost: infill },
    { name: 'Base rock', qty: `${fmt(yd3, 1)} yd³`, cost: base },
    { name: 'Seam glue', qty: `${seamGal} gal`, cost: seam },
    { name: 'Labor', qty: `${fmt(net, 0)} ft²`, cost: labor },
  ];
  const subtotal = items.reduce((s, it) => s + it.cost, 0);
  const markup = subtotal * (num('est-markup') / 100);
  const total = subtotal + markup;

  const body = $('est-body');
  body.innerHTML = '';
  items.forEach((it) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${it.name}</td><td>${it.qty}</td><td class="num">${money(it.cost)}</td>`;
    body.appendChild(tr);
  });
  $('est-subtotal').textContent = money(subtotal);
  $('est-markup-val').textContent = money(markup);
  $('est-total').textContent = money(total);
  return { net, gross, items, subtotal, markup, total };
}

/* ---------- converters ---------- */
function calcConvert() {
  $('c-in').textContent = fmt(num('c-ft') * 12, 1) + ' in';
  $('c-sqyd').textContent = fmt(num('c-sqft') / 9, 2) + ' yd²';
  $('c-ton').textContent = fmt(num('c-lb') / 2000, 3) + ' tons';
  $('c-area').textContent = fmt(num('c-l') * num('c-w'), 1) + ' ft²';
}

/* ---------- master render ---------- */
function render() {
  calcTurf(); calcBase(); calcInfill(); calcSeam(); calcNails();
  calcEstimate(); calcConvert();
}

/* ---------- save / load / share ---------- */
function readJobs() { try { return JSON.parse(localStorage.getItem(STORE_KEY)) || []; } catch { return []; } }
function writeJobs(j) { localStorage.setItem(STORE_KEY, JSON.stringify(j)); }

/* Every input that feeds the estimate. Snapshotted into each saved job so
 * reopening a job shows the total it was saved with, not whatever rates
 * happen to be in the inputs from the last job quoted. */
const RATE_IDS = [
  'est-turf-price', 'est-labor', 'est-waste', 'est-markup',
  'turf-roll-width', 'turf-waste',
  'base-depth', 'base-compaction', 'base-material', 'base-price',
  'sand-rate', 'sand-supply', 'sand-ton-price', 'sand-bag', 'sand-bag-price',
  'top-product', 'top-rate', 'top-bag', 'top-price',
  'seam-len', 'glue-cover', 'tape-roll', 'glue-price',
  'seam-len-2', 'perimeter', 'perim-spacing', 'seam-spacing', 'field-rate', 'nail-box',
];

function collectJob() {
  const areas = [];
  areaBlocks.estimate.rows.querySelectorAll('.area-row').forEach((r) =>
    areas.push({ len: r.querySelector('.len').value, wid: r.querySelector('.wid').value }));
  const est = calcEstimate();
  return {
    id: uid('j'),
    savedAt: todayLocal(),
    name: $('job-name').value || 'Untitled job',
    date: $('job-date').value || todayLocal(),
    rates: Object.fromEntries(RATE_IDS.map((id) => [id, $(id).value])),
    areas, net: est.net, total: est.total,
  };
}

function loadJob(job) {
  $('job-name').value = job.name || '';
  $('job-date').value = job.date || todayLocal();
  if (job.rates) RATE_IDS.forEach((id) => {
    if (id in job.rates) $(id).value = job.rates[id];
  });
  areaBlocks.estimate.rows.innerHTML = '';
  (job.areas && job.areas.length ? job.areas : [{ len: '', wid: '' }])
    .forEach((a) => areaBlocks.estimate.addRow(a.len, a.wid));
  render();
}

function renderSaved() {
  const jobs = readJobs().sort((a, b) => (a.savedAt < b.savedAt ? 1 : -1));
  const list = $('saved-list');
  $('saved-empty').style.display = jobs.length ? 'none' : '';
  list.innerHTML = '';
  jobs.forEach((job) => {
    const item = document.createElement('div');
    item.className = 'saved-item';
    item.innerHTML = `
      <div class="meta"><span class="name"></span>
        <span class="sub">${esc(job.date)} · ${fmt(job.net || 0, 0)} ft²</span></div>
      <span class="price">${money(job.total || 0)}</span>
      <div class="row-actions"><button class="open" title="Open">📂</button>
        <button class="del" title="Delete">🗑</button></div>`;
    item.querySelector('.name').textContent = job.name;   // XSS-safe
    item.querySelector('.open').addEventListener('click', () => {
      loadJob(job); toast('Job loaded');
    });
    item.querySelector('.del').addEventListener('click', () => {
      writeJobs(readJobs().filter((j) => j.id !== job.id)); renderSaved(); toast('Deleted');
    });
    list.appendChild(item);
  });
}

function jobText() {
  const r = calcEstimate();
  const lines2 = [
    `TurfPro estimate — ${$('job-name').value || 'Turf job'}`,
    `Area: ${fmt(r.net, 0)} ft² net / ${fmt(r.gross, 0)} ft² w/ waste`, '',
    ...r.items.map((it) => `${it.name}: ${it.qty} — ${money(it.cost)}`), '',
    `Subtotal: ${money(r.subtotal)}`, `Markup: ${money(r.markup)}`,
    `TOTAL: ${money(r.total)}`, '', 'Estimate only.',
  ];
  return lines2.join('\n');
}

async function shareJob() {
  const text = jobText();
  if (navigator.share) { try { await navigator.share({ title: 'TurfPro estimate', text }); return; } catch { /* cancelled */ } }
  try { await navigator.clipboard.writeText(text); toast('Estimate copied'); }
  catch { toast('Copy not supported'); }
}

/* ---------- job guide (phase checklist) ---------- */
/* Phases mirror docs/WORK_PROCESS.md. Steps stay generic where the real spec
 * is still unconfirmed — the job sheet wins over anything written here. */
const GUIDE_KEY = 'turfpro.guide.v1';
const GUIDE_PHASES = [
  {
    title: 'Measure & plan',
    steps: [
      'Walk the site — mark obstacles, sprinklers, utilities',
      'Measure every area (L × W) and enter them in Turf & Rolls',
      'Plan roll/grain direction (one way, toward main view)',
      'Confirm equipment and material access',
    ],
    tools: 'Tape / measuring wheel, marking paint',
    watch: 'Call 811 before digging. Watch for sprinkler lines.',
  },
  {
    title: 'Demo / removal',
    steps: [
      'Remove sod, old turf, or mulch',
      'Excavate to spec depth for base + turf',
      'Haul off spoils',
    ],
    tools: 'Sod cutter, shovels, skid steer, wheelbarrow',
    watch: 'Keep the grade consistent — don’t over-dig.',
  },
  {
    title: 'Grade & drainage',
    steps: [
      'Rough-grade with slope away from structures',
      'Fix any low spots that would pool water',
      'Install drainage if the job calls for it',
    ],
    tools: 'Rake, laser/level, drain pipe if spec’d',
    watch: 'Standing water later = callback. Check slope now.',
  },
  {
    title: 'Base install',
    steps: [
      'Lay weed barrier per spec',
      'Spread base rock (tons from the Base Rock tab)',
      'Wet and compact in lifts — multiple passes',
      'Screed and level to final grade',
    ],
    tools: 'Plate compactor, screed board, rake, hose',
    watch: 'A soft base means a wavy lawn. Compact in lifts.',
  },
  {
    title: 'Turf layout',
    steps: [
      'Roll turf out and let it relax',
      'Grain the same direction on every piece',
      'Position seams where they’ll show least',
    ],
    tools: 'Turf dolly/cart',
    watch: 'Grain mismatch between pieces shows badly.',
  },
  {
    title: 'Cut & seam',
    steps: [
      'Trim the factory selvage edge',
      'Cut pieces to fit (see Cut plan in Turf & Rolls)',
      'Seam with tape + glue or nails per spec',
      'Weight seams while they cure',
    ],
    tools: 'Turf knife, seam tape, glue + trowel, weights',
    watch: 'Don’t trap blades in the glue line.',
  },
  {
    title: 'Fasten',
    steps: [
      'Stretch out wrinkles before nailing',
      'Nail the perimeter (4–8″ spacing)',
      'Nail seams zig-zag (2–3″ spacing)',
    ],
    tools: 'Turf nails/staples, hammer or nail gun',
    watch: 'Over-driven nails dimple the turf.',
  },
  {
    title: 'Infill',
    steps: [
      'Spread the sand layer and broom it in',
      'Spread the customer’s top-fill product',
      'Power-broom between lifts until blades stand',
    ],
    tools: 'Drop spreader, power broom',
    watch: 'Quantities come from the Infill tab. Brush every lift.',
  },
  {
    title: 'Cleanup & walkthrough',
    steps: [
      'Final brush across the whole lawn',
      'Blow off surrounding hardscape',
      'Walk the job with the customer — punch list',
      'Leave care instructions',
    ],
    tools: 'Blower, broom',
    watch: 'Sweep for dropped nails before you leave.',
  },
];

function readGuide() {
  try { return JSON.parse(localStorage.getItem(GUIDE_KEY)) || { done: {}, notes: {} }; }
  catch { return { done: {}, notes: {} }; }
}
function writeGuide(g) { localStorage.setItem(GUIDE_KEY, JSON.stringify(g)); }

function renderGuide() {
  const host = $('guide-phases');
  if (!host) return;
  const g = readGuide();
  host.innerHTML = '';
  let total = 0, done = 0;

  GUIDE_PHASES.forEach((phase, pi) => {
    const card = document.createElement('div');
    card.className = 'card guide-phase';
    const phaseDone = phase.steps.filter((_, si) => g.done[`p${pi}s${si}`]).length;
    total += phase.steps.length;
    done += phaseDone;

    const h = document.createElement('h3');
    h.className = 'layer-h';
    h.textContent = `${pi + 1}. ${phase.title} — ${phaseDone}/${phase.steps.length}`;
    card.appendChild(h);

    phase.steps.forEach((step, si) => {
      const key = `p${pi}s${si}`;
      const label = document.createElement('label');
      label.className = 'guide-step' + (g.done[key] ? ' done' : '');
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.checked = !!g.done[key];
      cb.addEventListener('change', () => {
        const cur = readGuide();
        if (cb.checked) cur.done[key] = true; else delete cur.done[key];
        writeGuide(cur);
        renderGuide();
      });
      const span = document.createElement('span');
      span.textContent = step;
      label.appendChild(cb);
      label.appendChild(span);
      card.appendChild(label);
    });

    const meta = document.createElement('p');
    meta.className = 'guide-meta';
    meta.innerHTML = `<strong>Tools:</strong> ${phase.tools}<br><strong>Watch:</strong> ${phase.watch}`;
    card.appendChild(meta);

    const notes = document.createElement('textarea');
    notes.className = 'guide-notes';
    notes.placeholder = 'Phase notes…';
    notes.value = g.notes[pi] || '';
    notes.addEventListener('input', () => {
      const cur = readGuide();
      cur.notes[pi] = notes.value;
      writeGuide(cur);
    });
    card.appendChild(notes);

    host.appendChild(card);
  });

  const pct = total ? Math.round((done / total) * 100) : 0;
  const fill = $('guide-bar-fill');
  if (fill) fill.style.width = pct + '%';
  const lbl = $('guide-progress-label');
  if (lbl) lbl.textContent = `${pct}% — ${done}/${total} steps`;
}

/* ---------- expenses (foreman job-cost tracking) ---------- */
const EXP_KEY = 'turfpro.expenses.v1';
const META_KEY = 'turfpro.foreman.v1';

function readExp() { try { return JSON.parse(localStorage.getItem(EXP_KEY)) || []; } catch { return []; } }
function writeExp(x) { localStorage.setItem(EXP_KEY, JSON.stringify(x)); }

function addExpense() {
  const amount = num('exp-amount');
  if (amount <= 0) { toast('Enter an amount'); return; }
  const exp = readExp();
  exp.push({
    id: uid('e'),
    cat: $('exp-cat').value,
    amount,
    date: $('exp-date').value || todayLocal(),
    note: $('exp-note').value.trim(),
    foreman: $('exp-foreman').value.trim(),
    job: $('exp-job').value.trim(),
  });
  writeExp(exp);
  $('exp-amount').value = '';
  $('exp-note').value = '';
  renderExpenses();
  toast('Expense added');
}

function renderExpenses() {
  const exp = readExp().sort((a, b) => (a.date < b.date ? 1 : -1));
  const list = $('exp-list');
  $('exp-empty').style.display = exp.length ? 'none' : '';
  list.innerHTML = '';

  // totals by category + grand total
  const byCat = {};
  let grand = 0;
  exp.forEach((e) => { byCat[e.cat] = (byCat[e.cat] || 0) + e.amount; grand += e.amount; });
  const totalLines = Object.entries(byCat)
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => ({ k, v: money(v) }));
  totalLines.push({ k: 'Total', v: money(grand), big: true });
  lines('exp-totals', totalLines);

  exp.forEach((e) => {
    const item = document.createElement('div');
    item.className = 'saved-item';
    item.innerHTML = `
      <div class="meta"><span class="name"></span>
        <span class="sub">${esc(e.date)}${e.note ? ' · ' : ''}<span class="note"></span></span></div>
      <span class="price">${money(e.amount)}</span>
      <div class="row-actions"><button class="del" title="Delete">🗑</button></div>`;
    item.querySelector('.name').textContent = e.cat;      // XSS-safe
    item.querySelector('.note').textContent = e.note || '';
    item.querySelector('.del').addEventListener('click', () => {
      writeExp(readExp().filter((x) => x.id !== e.id)); renderExpenses(); toast('Deleted');
    });
    list.appendChild(item);
  });
}

async function shareExpenses() {
  const exp = readExp().sort((a, b) => (a.date < b.date ? 1 : -1));
  if (!exp.length) { toast('Nothing to export'); return; }
  const foreman = $('exp-foreman').value.trim();
  const job = $('exp-job').value.trim();
  const grand = exp.reduce((s, e) => s + e.amount, 0);
  const text = [
    'TurfPro expenses' + (foreman ? ` — ${foreman}` : ''),
    job ? `Job: ${job}` : null, '',
    ...exp.map((e) => `${e.date}  ${e.cat}  ${money(e.amount)}${e.note ? '  (' + e.note + ')' : ''}`),
    '', `TOTAL: ${money(grand)}`,
  ].filter((l) => l !== null).join('\n');
  if (navigator.share) { try { await navigator.share({ title: 'TurfPro expenses', text }); return; } catch { /* cancelled */ } }
  try { await navigator.clipboard.writeText(text); toast('Expenses copied'); }
  catch { toast('Copy not supported'); }
}

function saveForemanMeta() {
  localStorage.setItem(META_KEY, JSON.stringify({
    foreman: $('exp-foreman').value, job: $('exp-job').value,
  }));
}
function loadForemanMeta() {
  try {
    const m = JSON.parse(localStorage.getItem(META_KEY)) || {};
    if (m.foreman) $('exp-foreman').value = m.foreman;
    if (m.job) $('exp-job').value = m.job;
  } catch { /* ignore */ }
}

/* ---------- toast ---------- */
let toastTimer;
function toast(msg) {
  const t = $('toast'); t.textContent = msg; t.classList.add('show');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('show'), 1800);
}

/* ---------- tabs ---------- */
function initTabs() {
  const tabs = document.querySelectorAll('.tab');
  tabs.forEach((tab) => tab.addEventListener('click', () => {
    tabs.forEach((t) => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach((p) => p.classList.remove('active'));
    tab.classList.add('active');
    $('panel-' + tab.dataset.tab).classList.add('active');
    window.scrollTo({ top: 0 });
  }));
}

/* ---------- init ---------- */
function init() {
  document.querySelectorAll('.area-block').forEach(buildAreaBlock);
  initTabs();

  if (!$('job-date').value) $('job-date').value = todayLocal();
  if (!$('exp-date').value) $('exp-date').value = todayLocal();
  loadForemanMeta();

  document.addEventListener('input', render);

  $('save-job').addEventListener('click', () => {
    const jobs = readJobs(); jobs.push(collectJob()); writeJobs(jobs); renderSaved(); toast('Job saved');
  });
  $('share-job').addEventListener('click', shareJob);

  // cut plan → seam length handoff
  $('use-seams').addEventListener('click', () => {
    $('seam-len').value = Math.round(cutSeamTotal);
    $('seam-len-2').value = Math.round(cutSeamTotal);
    render();
    toast(`Seam length set to ${Math.round(cutSeamTotal)} ft`);
  });

  // job guide
  renderGuide();
  $('guide-reset').addEventListener('click', () => {
    if (confirm('Reset the whole job checklist and phase notes?')) {
      writeGuide({ done: {}, notes: {} });
      renderGuide();
      toast('Checklist reset');
    }
  });

  // expenses
  $('exp-add').addEventListener('click', addExpense);
  $('exp-share').addEventListener('click', shareExpenses);
  $('exp-clear').addEventListener('click', () => {
    if (!readExp().length) { toast('Nothing to clear'); return; }
    if (confirm('Clear ALL logged expenses on this device?')) { writeExp([]); renderExpenses(); toast('Cleared'); }
  });
  $('exp-foreman').addEventListener('input', saveForemanMeta);
  $('exp-job').addEventListener('input', saveForemanMeta);

  renderSaved();
  renderExpenses();
  render();

  fetch('version.json', { cache: 'no-store' })
    .then((r) => r.json()).then((v) => { $('app-version').textContent = v.version || VERSION; })
    .catch(() => { $('app-version').textContent = VERSION; });

  if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
}

document.addEventListener('DOMContentLoaded', init);
