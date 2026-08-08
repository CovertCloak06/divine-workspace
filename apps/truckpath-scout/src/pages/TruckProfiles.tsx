import { useState } from 'react';
import TopBar from '../components/TopBar';
import { deleteTruck, listTrucks, saveTruck, uid } from '../lib/storage';
import type { TruckProfile } from '../types';

const EMPTY: Omit<TruckProfile, 'id'> = {
  name: '',
  vehicle_type: 'custom',
  length_ft: 40,
  width_ft: 8.5,
  height_ft: 13.5,
  gross_weight_lbs: 60000,
  trailer_type: '',
  turning_notes: '',
  preset: false,
};

export default function TruckProfiles() {
  const [trucks, setTrucks] = useState(() => listTrucks());
  const [editing, setEditing] = useState<TruckProfile | null>(null);

  function refresh() {
    setTrucks(listTrucks());
  }

  function save() {
    if (!editing) return;
    saveTruck({ ...editing, name: editing.name.trim() || 'Custom Truck' });
    setEditing(null);
    refresh();
  }

  return (
    <div className="min-h-full flex flex-col">
      <TopBar title="Truck Profiles" back="/" />
      <main className="flex-1 p-4 space-y-3 max-w-2xl w-full mx-auto">
        <button
          className="btn-primary w-full !min-h-[56px]"
          onClick={() => setEditing({ ...EMPTY, id: uid() })}
        >
          ＋ Custom Truck
        </button>

        {trucks.map((t) => (
          <div key={t.id} className="card">
            <div className="flex items-start justify-between gap-2">
              <div>
                <div className="font-bold text-lg">
                  {t.name}
                  {t.preset && <span className="ml-2 text-xs font-semibold text-gray-500 uppercase">Preset</span>}
                </div>
                <div className="text-sm text-gray-400">
                  {t.length_ft}′L × {t.width_ft}′W × {t.height_ft}′H · {t.gross_weight_lbs.toLocaleString()} lbs
                  {t.trailer_type && ` · ${t.trailer_type}`}
                </div>
                {t.turning_notes && <p className="text-sm text-gray-500 mt-1">{t.turning_notes}</p>}
              </div>
              {!t.preset && (
                <div className="flex flex-col gap-1 shrink-0">
                  <button className="btn-secondary !min-h-touch !px-3 text-sm" onClick={() => setEditing(t)}>
                    Edit
                  </button>
                  <button
                    className="btn-danger !min-h-touch !px-3 text-sm"
                    onClick={() => {
                      if (confirm(`Delete "${t.name}"?`)) {
                        deleteTruck(t.id);
                        refresh();
                      }
                    }}
                  >
                    Delete
                  </button>
                </div>
              )}
            </div>
          </div>
        ))}
      </main>

      {editing && (
        <div className="fixed inset-0 z-[1200] flex flex-col justify-end" onClick={() => setEditing(null)}>
          <div className="absolute inset-0 bg-black/50" />
          <div
            className="relative max-h-[85vh] overflow-y-auto rounded-t-2xl bg-panel border-t border-edge p-4 pb-8 space-y-3"
            onClick={(e) => e.stopPropagation()}
          >
            <h2 className="text-lg font-bold">Custom truck</h2>
            <div>
              <label className="label">Name</label>
              <input
                className="input"
                value={editing.name}
                placeholder="Water truck, crane carrier…"
                onChange={(e) => setEditing({ ...editing, name: e.target.value })}
              />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <NumField label="Length (ft)" value={editing.length_ft} onChange={(v) => setEditing({ ...editing, length_ft: v })} />
              <NumField label="Width (ft)" value={editing.width_ft} onChange={(v) => setEditing({ ...editing, width_ft: v })} />
              <NumField label="Height (ft)" value={editing.height_ft} onChange={(v) => setEditing({ ...editing, height_ft: v })} />
              <NumField label="GVW (lbs)" value={editing.gross_weight_lbs} onChange={(v) => setEditing({ ...editing, gross_weight_lbs: v })} />
            </div>
            <div>
              <label className="label">Trailer type</label>
              <input
                className="input"
                value={editing.trailer_type}
                onChange={(e) => setEditing({ ...editing, trailer_type: e.target.value })}
              />
            </div>
            <div>
              <label className="label">Turning notes</label>
              <textarea
                className="input min-h-[64px] py-2"
                value={editing.turning_notes}
                onChange={(e) => setEditing({ ...editing, turning_notes: e.target.value })}
              />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <button className="btn-secondary" onClick={() => setEditing(null)}>Cancel</button>
              <button className="btn-primary" onClick={save}>Save</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function NumField({ label, value, onChange }: { label: string; value: number; onChange: (v: number) => void }) {
  return (
    <div>
      <label className="label">{label}</label>
      <input
        className="input"
        type="number"
        inputMode="decimal"
        value={Number.isFinite(value) ? value : ''}
        onChange={(e) => onChange(parseFloat(e.target.value) || 0)}
      />
    </div>
  );
}
