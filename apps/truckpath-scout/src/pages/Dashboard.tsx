import { useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import TopBar from '../components/TopBar';
import RiskBadge from '../components/RiskBadge';
import { deleteSite, listDrawings, listHazards, listPlans, listSites } from '../lib/storage';
import { scoreRisk } from '../lib/risk';

export default function Dashboard() {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [refresh, setRefresh] = useState(0);

  const sites = useMemo(() => {
    const all = listSites();
    const q = query.trim().toLowerCase();
    return q
      ? all.filter((s) => s.name.toLowerCase().includes(q) || s.address.toLowerCase().includes(q))
      : all;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, refresh]);

  return (
    <div className="min-h-full flex flex-col">
      <TopBar
        title="TruckPath Scout"
        right={
          <Link to="/trucks" className="btn-secondary !px-3">
            🚚 Trucks
          </Link>
        }
      />
      <main className="flex-1 p-4 space-y-4 max-w-2xl w-full mx-auto">
        <button className="btn-primary w-full text-lg !min-h-[56px]" onClick={() => navigate('/sites/new')}>
          ＋ New Site
        </button>

        <input
          className="input"
          type="search"
          placeholder="Search saved sites…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />

        <h2 className="label !mb-0">Recent sites</h2>
        {sites.length === 0 && (
          <p className="text-gray-400 text-center py-8">
            No sites yet. Tap <strong>New Site</strong> to plan your first delivery.
          </p>
        )}
        <ul className="space-y-3">
          {sites.map((site) => {
            const hazards = listHazards(site.id);
            const drawings = listDrawings(site.id);
            const risk = scoreRisk(site, hazards, drawings);
            const plans = listPlans(site.id);
            return (
              <li key={site.id} className="card !p-0 overflow-hidden">
                <Link to={`/sites/${site.id}`} className="block p-4 active:bg-edge">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="font-bold text-lg truncate">{site.name}</div>
                      <div className="text-sm text-gray-400 truncate">{site.address}</div>
                      <div className="text-sm text-gray-500 mt-1">
                        {hazards.length} marker{hazards.length === 1 ? '' : 's'} · {plans.length} plan
                        {plans.length === 1 ? '' : 's'}
                      </div>
                    </div>
                    <RiskBadge score={risk.score} />
                  </div>
                </Link>
                <div className="flex border-t border-edge">
                  {plans.length > 0 && (
                    <Link
                      to={`/sites/${site.id}/plan/${plans[0].id}`}
                      className="flex-1 text-center py-3 font-semibold text-hivis active:bg-edge"
                    >
                      Latest plan
                    </Link>
                  )}
                  <button
                    className="flex-1 py-3 font-semibold text-danger active:bg-edge"
                    onClick={() => {
                      if (confirm(`Delete "${site.name}" and all its markers/plans?`)) {
                        deleteSite(site.id);
                        setRefresh((r) => r + 1);
                      }
                    }}
                  >
                    Delete
                  </button>
                </div>
              </li>
            );
          })}
        </ul>
      </main>
    </div>
  );
}
