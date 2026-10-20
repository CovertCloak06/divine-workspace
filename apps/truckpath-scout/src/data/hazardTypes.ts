import type { HazardType, Severity } from '../types';

export interface HazardTypeDef {
  type: HazardType;
  label: string;
  icon: string;
  /** Marker color on the map. */
  color: string;
  /** 'hazard' adds risk; 'zone' is operational info (entrance, staging, etc). */
  category: 'hazard' | 'zone';
  defaultSeverity: Severity;
  /** Extra deterministic risk points beyond severity (see lib/risk.ts). */
  riskBonus: number;
}

export const HAZARD_TYPES: HazardTypeDef[] = [
  { type: 'correct_entrance', label: 'Correct Entrance', icon: '✅', color: '#22c55e', category: 'zone', defaultSeverity: 'low', riskBonus: 0 },
  { type: 'wrong_entrance', label: 'Wrong Entrance', icon: '⛔', color: '#ef4444', category: 'zone', defaultSeverity: 'medium', riskBonus: 0 },
  { type: 'loading_zone', label: 'Loading Zone', icon: '📦', color: '#3b82f6', category: 'zone', defaultSeverity: 'low', riskBonus: 0 },
  { type: 'staging_area', label: 'Staging Area', icon: '🅿️', color: '#06b6d4', category: 'zone', defaultSeverity: 'low', riskBonus: 0 },
  { type: 'gate', label: 'Gate', icon: '🚧', color: '#a855f7', category: 'zone', defaultSeverity: 'low', riskBonus: 0 },
  { type: 'tight_turn', label: 'Tight Turn', icon: '↩️', color: '#f97316', category: 'hazard', defaultSeverity: 'medium', riskBonus: 1 },
  { type: 'narrow_road', label: 'Narrow Road', icon: '↔️', color: '#f97316', category: 'hazard', defaultSeverity: 'medium', riskBonus: 0 },
  { type: 'low_bridge', label: 'Low Bridge', icon: '🌉', color: '#b91c1c', category: 'hazard', defaultSeverity: 'critical', riskBonus: 3 },
  { type: 'low_wire', label: 'Low Wires', icon: '⚡', color: '#b91c1c', category: 'hazard', defaultSeverity: 'high', riskBonus: 3 },
  { type: 'tree_canopy', label: 'Low Trees', icon: '🌳', color: '#65a30d', category: 'hazard', defaultSeverity: 'medium', riskBonus: 0 },
  { type: 'steep_grade', label: 'Steep Grade', icon: '⛰️', color: '#f97316', category: 'hazard', defaultSeverity: 'medium', riskBonus: 0 },
  { type: 'dead_end', label: 'Dead End', icon: '🚫', color: '#ef4444', category: 'hazard', defaultSeverity: 'high', riskBonus: 2 },
  { type: 'cul_de_sac', label: 'Cul-de-sac', icon: '🔄', color: '#ef4444', category: 'hazard', defaultSeverity: 'medium', riskBonus: 2 },
  { type: 'soft_shoulder', label: 'Soft Shoulder', icon: '🏖️', color: '#eab308', category: 'hazard', defaultSeverity: 'medium', riskBonus: 0 },
  { type: 'bad_backing_angle', label: 'Bad Backing Angle', icon: '📐', color: '#f97316', category: 'hazard', defaultSeverity: 'medium', riskBonus: 0 },
  { type: 'power_pole', label: 'Power Pole', icon: '🗼', color: '#eab308', category: 'hazard', defaultSeverity: 'medium', riskBonus: 0 },
  { type: 'parked_cars', label: 'Parked Cars', icon: '🚗', color: '#eab308', category: 'hazard', defaultSeverity: 'low', riskBonus: 0 },
  { type: 'blind_corner', label: 'Blind Corner', icon: '👁️', color: '#f97316', category: 'hazard', defaultSeverity: 'high', riskBonus: 0 },
  { type: 'school_zone', label: 'School Zone', icon: '🏫', color: '#eab308', category: 'hazard', defaultSeverity: 'medium', riskBonus: 0 },
  { type: 'residential_restriction', label: 'Residential Restriction', icon: '🏠', color: '#eab308', category: 'hazard', defaultSeverity: 'medium', riskBonus: 0 },
  { type: 'weight_limit', label: 'Weight Limit', icon: '⚖️', color: '#ef4444', category: 'hazard', defaultSeverity: 'high', riskBonus: 0 },
  { type: 'one_way', label: 'One-Way', icon: '➡️', color: '#ef4444', category: 'hazard', defaultSeverity: 'medium', riskBonus: 0 },
  { type: 'rough_surface', label: 'Rough Surface', icon: '🕳️', color: '#eab308', category: 'hazard', defaultSeverity: 'low', riskBonus: 0 },
  { type: 'construction_obstruction', label: 'Construction Obstruction', icon: '🏗️', color: '#f97316', category: 'hazard', defaultSeverity: 'medium', riskBonus: 0 },
  { type: 'other', label: 'Other', icon: '📌', color: '#94a3b8', category: 'hazard', defaultSeverity: 'low', riskBonus: 0 },
];

export const HAZARD_TYPE_MAP: Record<HazardType, HazardTypeDef> = Object.fromEntries(
  HAZARD_TYPES.map((h) => [h.type, h]),
) as Record<HazardType, HazardTypeDef>;

export const SEVERITY_POINTS: Record<Severity, number> = {
  low: 0.5,
  medium: 1,
  high: 2,
  critical: 3,
};

export const SEVERITY_COLORS: Record<Severity, string> = {
  low: '#eab308',
  medium: '#f97316',
  high: '#ef4444',
  critical: '#b91c1c',
};
