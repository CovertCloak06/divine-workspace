import MapView from './MapView';
import RiskBadge from './RiskBadge';
import { HAZARD_TYPE_MAP } from '../data/hazardTypes';
import { directionLabel } from '../lib/instructions';
import type { PlanBundle } from '../types';

/** Read-only rendering of a plan bundle. Used by Plan Review, Shared links, and PDF export (print). */
export default function PlanSheet({ bundle }: { bundle: PlanBundle }) {
  const { site, truck, hazards, drawings, plan } = bundle;
  const markedHazards = hazards.filter((h) => HAZARD_TYPE_MAP[h.type].category === 'hazard');

  return (
    <div className="print-sheet space-y-4">
      <div className="card">
        <div className="flex items-start justify-between gap-2">
          <div>
            <h2 className="text-xl font-bold">{site.name}</h2>
            <p className="text-gray-400">{site.address}</p>
          </div>
          <RiskBadge score={plan.risk_score} large />
        </div>
        <dl className="mt-3 grid grid-cols-2 gap-2 text-sm">
          <div>
            <dt className="label !mb-0">Truck</dt>
            <dd>{truck.name}</dd>
            <dd className="text-gray-400">
              {truck.length_ft}′L × {truck.width_ft}′W × {truck.height_ft}′H · {truck.gross_weight_lbs.toLocaleString()} lbs
            </dd>
          </div>
          <div>
            <dt className="label !mb-0">Best approach</dt>
            <dd className="capitalize">Approach {directionLabel(plan.preferred_approach_direction)}</dd>
            {site.contact && <dd className="text-gray-400">Contact: {site.contact}</dd>}
          </div>
        </dl>
      </div>

      <div className="card !p-0 overflow-hidden h-64 no-print">
        <MapView
          center={{ lat: site.latitude, lng: site.longitude }}
          hazards={hazards}
          drawings={drawings}
          interactive={false}
        />
      </div>

      {plan.avoid_streets.length > 0 && (
        <div className="card">
          <h3 className="label">Avoid</h3>
          <ul className="list-disc pl-5 space-y-1">
            {plan.avoid_streets.map((s, i) => (
              <li key={i}>{s}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="card">
        <h3 className="label">Hazards ({markedHazards.length})</h3>
        {markedHazards.length === 0 && <p className="text-gray-400">None marked.</p>}
        <ul className="space-y-2">
          {markedHazards.map((h) => {
            const def = HAZARD_TYPE_MAP[h.type];
            return (
              <li key={h.id} className="flex items-start gap-2">
                <span className="text-lg leading-6">{def.icon}</span>
                <div>
                  <span className="font-semibold">{def.label}</span>{' '}
                  <span className="text-xs uppercase font-bold" style={{ color: def.color }}>
                    {h.severity}
                  </span>
                  {h.notes && <div className="text-sm text-gray-400">{h.notes}</div>}
                </div>
              </li>
            );
          })}
        </ul>
      </div>

      <div className="card">
        <h3 className="label">Driver instructions</h3>
        <pre className="whitespace-pre-wrap font-mono text-sm leading-relaxed">
          {plan.generated_driver_instructions}
        </pre>
      </div>

      <div className="card">
        <h3 className="label">Driver text (SMS · {plan.sms_text.length} chars)</h3>
        <p className="text-sm leading-relaxed">{plan.sms_text}</p>
      </div>
    </div>
  );
}
