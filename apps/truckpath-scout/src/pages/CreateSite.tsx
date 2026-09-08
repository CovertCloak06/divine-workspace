import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import TopBar from '../components/TopBar';
import { geocode, type GeocodeResult } from '../lib/geocode';
import { listTrucks, nowIso, saveSite, uid } from '../lib/storage';
import type { Site } from '../types';

export default function CreateSite() {
  const navigate = useNavigate();
  const trucks = listTrucks();

  const [name, setName] = useState('');
  const [address, setAddress] = useState('');
  const [results, setResults] = useState<GeocodeResult[]>([]);
  const [picked, setPicked] = useState<GeocodeResult | null>(null);
  const [truckId, setTruckId] = useState(trucks[0]?.id ?? '');
  const [contact, setContact] = useState('');
  const [notes, setNotes] = useState('');
  const [searching, setSearching] = useState(false);
  const [error, setError] = useState('');

  async function search() {
    if (!address.trim()) return;
    setSearching(true);
    setError('');
    try {
      const found = await geocode(address.trim());
      setResults(found);
      if (found.length === 0) setError('No matches. Try adding city/state, or skip and place the pin manually.');
    } catch {
      setError('Address search failed (offline?). You can still create the site and position the map manually.');
    } finally {
      setSearching(false);
    }
  }

  function create() {
    const site: Site = {
      id: uid(),
      name: name.trim() || picked?.label.split(',')[0] || address.trim() || 'Untitled Site',
      address: picked?.label ?? address.trim(),
      latitude: picked?.lat ?? 39.8283, // fall back to CONUS center; user repositions on map
      longitude: picked?.lng ?? -98.5795,
      created_at: nowIso(),
      updated_at: nowIso(),
      notes: notes.trim(),
      residential_road: false,
      backing_required: false,
      truck_profile_id: truckId || null,
      contact: contact.trim(),
    };
    saveSite(site);
    navigate(`/sites/${site.id}`, { replace: true });
  }

  return (
    <div className="min-h-full flex flex-col">
      <TopBar title="New Site" back="/" />
      <main className="flex-1 p-4 space-y-4 max-w-2xl w-full mx-auto">
        <div>
          <label className="label" htmlFor="site-address">Delivery address</label>
          <div className="flex gap-2">
            <input
              id="site-address"
              className="input"
              placeholder="4820 Maple St, Omaha NE"
              value={address}
              onChange={(e) => setAddress(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && search()}
            />
            <button className="btn-primary shrink-0" onClick={search} disabled={searching}>
              {searching ? '…' : 'Search'}
            </button>
          </div>
          {error && <p className="text-warn text-sm mt-2">{error}</p>}
          {results.length > 0 && (
            <ul className="mt-2 space-y-1">
              {results.map((r, i) => (
                <li key={i}>
                  <button
                    className={`w-full text-left rounded-lg px-3 py-3 text-sm border ${
                      picked === r ? 'border-hivis bg-edge' : 'border-edge bg-panel'
                    }`}
                    onClick={() => setPicked(r)}
                  >
                    {picked === r ? '✅ ' : '📍 '}
                    {r.label}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div>
          <label className="label" htmlFor="site-name">Site name</label>
          <input
            id="site-name"
            className="input"
            placeholder="Maple St pour, Lot 14 delivery…"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>

        <div>
          <label className="label" htmlFor="site-truck">Truck type</label>
          <select id="site-truck" className="input" value={truckId} onChange={(e) => setTruckId(e.target.value)}>
            {trucks.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name} ({t.length_ft} ft, {t.height_ft} ft tall)
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="label" htmlFor="site-contact">Site contact (name + phone)</label>
          <input
            id="site-contact"
            className="input"
            placeholder="Foreman Mike 402-555-0147"
            value={contact}
            onChange={(e) => setContact(e.target.value)}
          />
        </div>

        <div>
          <label className="label" htmlFor="site-notes">Notes</label>
          <textarea
            id="site-notes"
            className="input min-h-[88px] py-2"
            placeholder="Gate code, delivery window, ground conditions…"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
          />
        </div>

        <button className="btn-primary w-full text-lg !min-h-[56px]" onClick={create}>
          Create Site → Open Map
        </button>
        {!picked && (
          <p className="text-sm text-gray-500 text-center">
            No address match selected — the map opens at a default view and you can pan to the site.
          </p>
        )}
      </main>
    </div>
  );
}
