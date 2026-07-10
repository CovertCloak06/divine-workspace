import type { Drawing, Hazard, RiskLabel, RiskResult, Site } from '../types';
import { HAZARD_TYPE_MAP, SEVERITY_POINTS } from '../data/hazardTypes';

/**
 * Deterministic risk scoring per spec:
 *   Base 1. Severity: low +0.5, medium +1, high +2, critical +3.
 *   Type bonuses: tight turn +1, low wire/bridge +3, dead end/cul-de-sac +2.
 *   Backing required +1.5, residential road +1, no staging area +1. Cap 10.
 */
export function scoreRisk(site: Site, hazards: Hazard[], drawings: Drawing[]): RiskResult {
  const breakdown: RiskResult['breakdown'] = [{ label: 'Base score', points: 1 }];
  let score = 1;

  for (const hazard of hazards) {
    const def = HAZARD_TYPE_MAP[hazard.type];
    if (def.category !== 'hazard') continue;
    const points = SEVERITY_POINTS[hazard.severity] + def.riskBonus;
    score += points;
    breakdown.push({ label: `${def.label} (${hazard.severity})`, points });
  }

  if (site.backing_required) {
    score += 1.5;
    breakdown.push({ label: 'Backing required', points: 1.5 });
  }
  if (site.residential_road) {
    score += 1;
    breakdown.push({ label: 'Residential road', points: 1 });
  }

  const hasStaging =
    hazards.some((h) => h.type === 'staging_area') ||
    drawings.some((d) => d.kind === 'staging_zone');
  if (!hasStaging) {
    score += 1;
    breakdown.push({ label: 'No staging area marked', points: 1 });
  }

  score = Math.min(10, Math.round(score * 2) / 2);
  return { score, label: riskLabel(score), breakdown };
}

export function riskLabel(score: number): RiskLabel {
  if (score <= 3) return 'Low';
  if (score <= 6) return 'Moderate';
  if (score <= 8) return 'High';
  return 'Critical';
}

export function riskColor(score: number): string {
  if (score <= 3) return '#22c55e';
  if (score <= 6) return '#eab308';
  if (score <= 8) return '#f97316';
  return '#ef4444';
}
