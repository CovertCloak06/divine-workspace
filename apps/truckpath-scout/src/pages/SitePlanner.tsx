import { useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import MapView from '../components/MapView';
import RiskBadge from '../components/RiskBadge';
import TopBar from '../components/TopBar';
import { HAZARD_TYPES, HAZARD_TYPE_MAP } from '../data/hazardTypes';
import { directionLabel, generateInstructions, generateSms, generateWithAi } from '../lib/instructions';
import { scoreRisk } from '../lib/risk';
import {
  deleteDrawing,
  deleteHazard,
  getSite,
  getTruck,
  listDrawings,
  listHazards,
  listTrucks,
  nowIso,
  saveDrawing,
  saveHazard,
  savePlan,
  saveSite,
  uid,
} from '../lib/storage';
import type {
  ApproachDirection,
  ApproachPlan,
  Drawing,
  DrawingKind,
  Hazard,
  HazardType,
  LatLng,
  Severity,
  Site,
} from '../types';

type Tool =
  | { kind: 'pan' }
  | { kind: 'place'; hazardType: HazardType }
  | { kind: 'draw'; drawingKind: DrawingKind };

const DIRECTIONS: ApproachDirection[] = [
  'north', 'northeast', 'east', 'southeast', 'south', 'southwest', 'west', 'northwest', 'unspecified',
];

const SKETCH_TOOLS: { kind: DrawingKind; label: string; icon: string }[] = [
  { kind: 'approach_arrow', label: 'Approach Arrow', icon: '🟢' },
  { kind: 'no_go', label: 'No-Go Road', icon: '🔴' },
  { kind: 'staging_zone', label: 'Staging Area', icon: '🟦' },
];

export default function SitePlanner() {
  const { siteId = '' } = useParams();
  const navigate = useNavigate();

  const [site, setSite] = useState<Site | undefined>(() => getSite(siteId));
  const [hazards, setHazards] = useState<Hazard[]>(() => listHazards(siteId));
  const [drawings, setDrawings] = useState<Drawing[]>(() => listDrawings(siteId));

  const [tool, setTool] = useState<Tool>({ kind: 'pan' });
  const [draftPoints, setDraftPoints] = useState<LatLng[]>([]);
  const [selectedHazardId, setSelectedHazardId] = useState<string | null>(null);
  const [sheet, setSheet] = useState<'none' | 'markers' | 'sketch' | 'site' | 'generate'>('none');
  const [generating, setGenerating] = useState(false);

  const trucks = listTrucks();
  const truck = getTruck(site?.truck_profile_id ?? '') ?? trucks[0];
  const risk = useMemo(
    () => (site ? scoreRisk(site, hazards, drawings) : { score: 1, label: 'Low' as const, breakdown: [] }),
    [site, hazards, drawings],
  );

  // Generate-plan form state
  const [direction, setDirection] = useState<ApproachDirection>('unspecified');
  const [avoidStreets, setAvoidStreets] = useState('');
  const [stagingNotes, setStagingNotes] = useState('');
  const [backingNotes, setBackingNotes] = useState('');
  const [unloadingNotes, setUnloadingNotes] = useState('');

  if (!site) {
    return (
      <div className="p-6 text-center">
        <p className="mb-4">Site not found.</p>
        <button className="btn-primary" onClick={() => navigate('/')}>Back to Dashboard</button>
      </div>
    );
  }

  const selectedHazard = hazards.find((h) => h.id === selectedHazardId) ?? null;

  function updateSite(patch: Partial<Site>) {
    setSite((prev) => {
      if (!prev) return prev;
      const next = { ...prev, ...patch };
      saveSite(next);
      return next;
    });
  }

  function handleMapTap(point: LatLng) {
    if (tool.kind === 'place') {
      const def = HAZARD_TYPE_MAP[tool.hazardType];
      const hazard: Hazard = {
        id: uid(),
        site_id: siteId,
        type: tool.hazardType,
        latitude: point.lat,
        longitude: point.lng,
        severity: def.defaultSeverity,
        notes: '',
      };
      saveHazard(hazard);
      setHazards((h) => [...h, hazard]);
      setSelectedHazardId(hazard.id);
      setTool({ kind: 'pan' });
    } else if (tool.kind === 'draw') {
      setDraftPoints((p) => [...p, point]);
    } else {
      setSelectedHazardId(null);
    }
  }

  function finishDrawing() {
    if (tool.kind !== 'draw') return;
    const min = tool.drawingKind === 'staging_zone' ? 3 : 2;
    if (draftPoints.length < min) {
      alert(`Tap at least ${min} points on the map first.`);
      return;
    }
    const drawing: Drawing = {
      id: uid(),
      site_id: siteId,
      kind: tool.drawingKind,
      points: draftPoints,
      notes: '',
    };
    saveDrawing(drawing);
    setDrawings((d) => [...d, drawing]);
    setDraftPoints([]);
    setTool({ kind: 'pan' });
  }

  function cancelDrawing() {
    setDraftPoints([]);
    setTool({ kind: 'pan' });
  }

  function patchHazard(id: string, patch: Partial<Hazard>) {
    setHazards((prev) => {
      const next = prev.map((h) => (h.id === id ? { ...h, ...patch } : h));
      const updated = next.find((h) => h.id === id);
      if (updated) saveHazard(updated);
      return next;
    });
  }

  function removeHazard(id: string) {
    deleteHazard(id);
    setHazards((prev) => prev.filter((h) => h.id !== id));
    setSelectedHazardId(null);
  }

  function removeDrawing(id: string) {
    const d = drawings.find((x) => x.id === id);
    const label = d ? SKETCH_TOOLS.find((s) => s.kind === d.kind)?.label : 'sketch';
    if (!confirm(`Delete this ${label}?`)) return;
    deleteDrawing(id);
    setDrawings((prev) => prev.filter((x) => x.id !== id));
  }

  async function generatePlan() {
    if (!site || !truck) return;
    setGenerating(true);
    const avoid = avoidStreets.split(/[\n;,]+/).map((s) => s.trim()).filter(Boolean);
    const input = {
      site, truck, hazards, drawings, direction,
      avoidStreets: avoid,
      stagingNotes: stagingNotes.trim(),
      backingNotes: backingNotes.trim(),
      unloadingNotes: unloadingNotes.trim(),
      risk,
    };
    const instructions = await generateWithAi(input).catch(() => generateInstructions(input));
    const plan: ApproachPlan = {
      id: uid(),
      site_id: site.id,
      truck_profile_id: truck.id,
      preferred_approach_direction: direction,
      avoid_streets: avoid,
      staging_area_notes: input.stagingNotes,
      backing_notes: input.backingNotes,
      unloading_notes: input.unloadingNotes,
      generated_driver_instructions: instructions,
      sms_text: generateSms(input),
      risk_score: risk.score,
      risk_label: risk.label,
      created_at: nowIso(),
    };
    savePlan(plan);
    setGenerating(false);
    navigate(`/sites/${site.id}/plan/${plan.id}`);
  }

  const center: LatLng = { lat: site.latitude, lng: site.longitude };

  return (
    <div className="h-full flex flex-col">
      <TopBar
        title={site.name}
        back="/"
        right={
          <div className="flex items-center gap-2">
            <RiskBadge score={risk.score} />
            <button className="btn-secondary !px-3" onClick={() => setSheet('site')} aria-label="Site settings">
              ⚙️
            </button>
          </div>
        }
      />

      <div className="relative flex-1 min-h-0">
        <MapView
          center={center}
          hazards={hazards}
          drawings={drawings}
          draftPoints={draftPoints}
          draftKind={tool.kind === 'draw' ? tool.drawingKind : null}
          selectedHazardId={selectedHazardId}
          onMapTap={handleMapTap}
          onHazardTap={(id) => setSelectedHazardId(id)}
          onHazardMove={(id, p) => patchHazard(id, { latitude: p.lat, longitude: p.lng })}
          onDrawingTap={removeDrawing}
        />

        {/* Active tool banner */}
        {tool.kind !== 'pan' && (
          <div className="absolute left-1/2 top-3 z-[1000] -translate-x-1/2 rounded-full bg-hivis text-ink px-4 py-2 font-bold shadow-lg whitespace-nowrap">
            {tool.kind === 'place'
              ? `Tap map: ${HAZARD_TYPE_MAP[tool.hazardType].label}`
              : `Tap points (${draftPoints.length})`}
          </div>
        )}

        {/* Drawing controls */}
        {tool.kind === 'draw' && (
          <div className="absolute bottom-4 left-1/2 z-[1000] flex -translate-x-1/2 gap-2">
            <button className="btn-secondary shadow-lg" onClick={cancelDrawing}>Cancel</button>
            <button className="btn-primary shadow-lg" onClick={finishDrawing}>✓ Done</button>
          </div>
        )}
      </div>

      {/* Bottom toolbar */}
      <nav className="no-print grid grid-cols-4 gap-2 border-t border-edge bg-panel p-2">
        <button className="btn-secondary flex-col !gap-0 !py-1 text-sm" onClick={() => setSheet('markers')}>
          <span className="text-xl">📍</span>Markers
        </button>
        <button className="btn-secondary flex-col !gap-0 !py-1 text-sm" onClick={() => setSheet('sketch')}>
          <span className="text-xl">✏️</span>Sketch
        </button>
        <select
          className="input !min-h-0 text-sm"
          value={truck?.id ?? ''}
          onChange={(e) => updateSite({ truck_profile_id: e.target.value })}
          aria-label="Truck profile"
        >
          {trucks.map((t) => (
            <option key={t.id} value={t.id}>{t.name}</option>
          ))}
        </select>
        <button className="btn-primary flex-col !gap-0 !py-1 text-sm" onClick={() => setSheet('generate')}>
          <span className="text-xl">📋</span>Plan
        </button>
      </nav>

      {/* Marker palette sheet */}
      {sheet === 'markers' && (
        <Sheet title="Drop a marker" onClose={() => setSheet('none')}>
          <div className="grid grid-cols-2 gap-2">
            {HAZARD_TYPES.map((h) => (
              <button
                key={h.type}
                className="btn-secondary justify-start !px-3 text-left text-sm"
                style={{ borderLeft: `6px solid ${h.color}` }}
                onClick={() => {
                  setTool({ kind: 'place', hazardType: h.type });
                  setSheet('none');
                }}
              >
                <span className="text-lg">{h.icon}</span>
                {h.label}
              </button>
            ))}
          </div>
        </Sheet>
      )}

      {/* Sketch tools sheet */}
      {sheet === 'sketch' && (
        <Sheet title="Sketch on map" onClose={() => setSheet('none')}>
          <div className="space-y-2">
            {SKETCH_TOOLS.map((s) => (
              <button
                key={s.kind}
                className="btn-secondary w-full justify-start"
                onClick={() => {
                  setTool({ kind: 'draw', drawingKind: s.kind });
                  setDraftPoints([]);
                  setSheet('none');
                }}
              >
                <span className="text-lg">{s.icon}</span>
                {s.label}
              </button>
            ))}
            <p className="text-sm text-gray-400">
              Tap points on the map, then hit <strong>Done</strong>. Tap an existing sketch to delete it.
            </p>
          </div>
        </Sheet>
      )}

      {/* Site settings sheet */}
      {sheet === 'site' && (
        <Sheet title="Site settings" onClose={() => setSheet('none')}>
          <div className="space-y-3">
            <Toggle
              label="Backing required"
              checked={site.backing_required}
              onChange={(v) => updateSite({ backing_required: v })}
            />
            <Toggle
              label="Residential road"
              checked={site.residential_road}
              onChange={(v) => updateSite({ residential_road: v })}
            />
            <div>
              <label className="label">Site contact</label>
              <input
                className="input"
                value={site.contact}
                placeholder="Name + phone"
                onChange={(e) => updateSite({ contact: e.target.value })}
              />
            </div>
            <div>
              <label className="label">Notes</label>
              <textarea
                className="input min-h-[80px] py-2"
                value={site.notes}
                onChange={(e) => updateSite({ notes: e.target.value })}
              />
            </div>
            <div className="card !p-3 text-sm space-y-1">
              <div className="font-bold text-gray-300">Risk breakdown — {risk.score}/10</div>
              {risk.breakdown.map((b, i) => (
                <div key={i} className="flex justify-between text-gray-400">
                  <span>{b.label}</span>
                  <span>+{b.points}</span>
                </div>
              ))}
            </div>
          </div>
        </Sheet>
      )}

      {/* Generate plan sheet */}
      {sheet === 'generate' && (
        <Sheet title="Generate approach plan" onClose={() => setSheet('none')}>
          <div className="space-y-3">
            <div>
              <label className="label">Best approach direction</label>
              <div className="grid grid-cols-3 gap-1.5">
                {DIRECTIONS.map((d) => (
                  <button
                    key={d}
                    className={`btn text-sm ${direction === d ? 'bg-hivis text-ink' : 'bg-edge text-gray-100'}`}
                    onClick={() => setDirection(d)}
                  >
                    {d === 'unspecified' ? 'N/A' : d.toUpperCase().slice(0, 2) === 'NO' || d.length > 5 ? abbrev(d) : d.toUpperCase()}
                  </button>
                ))}
              </div>
              <p className="text-xs text-gray-500 mt-1">Driver will be told: “Approach {directionLabel(direction)}”.</p>
            </div>
            <div>
              <label className="label">Streets to avoid (one per line)</label>
              <textarea
                className="input min-h-[64px] py-2"
                placeholder={'W Elm alley\n47th St (weight limit)'}
                value={avoidStreets}
                onChange={(e) => setAvoidStreets(e.target.value)}
              />
            </div>
            <div>
              <label className="label">Staging</label>
              <input className="input" placeholder="Church lot on 48th, north side" value={stagingNotes} onChange={(e) => setStagingNotes(e.target.value)} />
            </div>
            <div>
              <label className="label">Backing</label>
              <input className="input" placeholder="Back in from the east with spotter" value={backingNotes} onChange={(e) => setBackingNotes(e.target.value)} />
            </div>
            <div>
              <label className="label">Unloading</label>
              <input className="input" placeholder="Pour from street side, pump on driveway" value={unloadingNotes} onChange={(e) => setUnloadingNotes(e.target.value)} />
            </div>
            <button className="btn-primary w-full !min-h-[56px] text-lg" onClick={generatePlan} disabled={generating}>
              {generating ? 'Generating…' : `Generate Plan — Risk ${risk.score}/10`}
            </button>
          </div>
        </Sheet>
      )}

      {/* Hazard editor sheet */}
      {selectedHazard && sheet === 'none' && tool.kind === 'pan' && (
        <Sheet
          title={`${HAZARD_TYPE_MAP[selectedHazard.type].icon} ${HAZARD_TYPE_MAP[selectedHazard.type].label}`}
          onClose={() => setSelectedHazardId(null)}
        >
          <div className="space-y-3">
            <div>
              <label className="label">Severity</label>
              <div className="grid grid-cols-4 gap-1.5">
                {(['low', 'medium', 'high', 'critical'] as Severity[]).map((s) => (
                  <button
                    key={s}
                    className={`btn text-sm capitalize ${
                      selectedHazard.severity === s ? 'bg-hivis text-ink' : 'bg-edge text-gray-100'
                    }`}
                    onClick={() => patchHazard(selectedHazard.id, { severity: s })}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>
            <div>
              <label className="label">Notes</label>
              <textarea
                className="input min-h-[64px] py-2"
                placeholder="Wires ~13 ft over east driveway…"
                value={selectedHazard.notes}
                onChange={(e) => patchHazard(selectedHazard.id, { notes: e.target.value })}
              />
            </div>
            <p className="text-sm text-gray-500">Drag the pin on the map to reposition it.</p>
            <button className="btn-danger w-full" onClick={() => removeHazard(selectedHazard.id)}>
              Delete marker
            </button>
          </div>
        </Sheet>
      )}
    </div>
  );
}

function abbrev(d: string): string {
  return d
    .replace('north', 'N')
    .replace('south', 'S')
    .replace('east', 'E')
    .replace('west', 'W')
    .toUpperCase();
}

function Sheet({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <div className="no-print fixed inset-0 z-[1200] flex flex-col justify-end" onClick={onClose}>
      <div className="absolute inset-0 bg-black/50" />
      <div
        className="relative max-h-[75vh] overflow-y-auto rounded-t-2xl bg-panel border-t border-edge p-4 pb-8"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-lg font-bold">{title}</h2>
          <button className="btn-secondary !px-4" onClick={onClose} aria-label="Close">✕</button>
        </div>
        {children}
      </div>
    </div>
  );
}

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      className="flex w-full items-center justify-between rounded-lg bg-edge px-4 min-h-touch"
      onClick={() => onChange(!checked)}
      role="switch"
      aria-checked={checked}
    >
      <span className="font-semibold">{label}</span>
      <span className={`text-2xl ${checked ? '' : 'grayscale opacity-50'}`}>{checked ? '🟢' : '⚪'}</span>
    </button>
  );
}
