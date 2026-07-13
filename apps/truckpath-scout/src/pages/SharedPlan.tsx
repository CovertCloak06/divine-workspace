import { useMemo } from 'react';
import { Link, useParams } from 'react-router-dom';
import PlanSheet from '../components/PlanSheet';
import TopBar from '../components/TopBar';
import { decodePlanFromParam } from '../lib/share';

/** Read-only view for shared plan links. All data lives in the URL — no server, no account. */
export default function SharedPlan() {
  const { payload = '' } = useParams();
  const bundle = useMemo(() => decodePlanFromParam(payload), [payload]);

  if (!bundle) {
    return (
      <div className="p-6 text-center">
        <p className="mb-4">This shared plan link is invalid or corrupted.</p>
        <Link to="/" className="btn-primary inline-flex">Open TruckPath Scout</Link>
      </div>
    );
  }

  return (
    <div className="min-h-full flex flex-col">
      <TopBar title={`Shared: ${bundle.site.name}`} />
      <main className="flex-1 p-4 max-w-2xl w-full mx-auto space-y-4">
        <PlanSheet bundle={bundle} />
        <button className="no-print btn-primary w-full" onClick={() => window.print()}>
          🖨️ Export PDF
        </button>
      </main>
    </div>
  );
}
