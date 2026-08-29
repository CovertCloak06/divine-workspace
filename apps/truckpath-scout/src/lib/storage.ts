import type { ApproachPlan, Drawing, Hazard, Site, TruckProfile } from '../types';
import { TRUCK_PRESETS } from '../data/truckPresets';
import { DEMO_DRAWINGS, DEMO_HAZARDS, DEMO_SITE } from '../data/demoData';

/**
 * Local-first persistence layer backed by localStorage.
 * Swap this module for an API client when a backend is added.
 */

const KEYS = {
  sites: 'tps.sites',
  trucks: 'tps.trucks',
  hazards: 'tps.hazards',
  drawings: 'tps.drawings',
  plans: 'tps.plans',
  seeded: 'tps.seeded.v1',
} as const;

function read<T>(key: string): T[] {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T[]) : [];
  } catch {
    return [];
  }
}

function write<T>(key: string, items: T[]): void {
  localStorage.setItem(key, JSON.stringify(items));
}

export function uid(): string {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

export function nowIso(): string {
  return new Date().toISOString();
}

/** Seed presets + demo site once. */
export function ensureSeeded(): void {
  if (localStorage.getItem(KEYS.seeded)) return;
  write(KEYS.sites, [DEMO_SITE]);
  write(KEYS.hazards, DEMO_HAZARDS);
  write(KEYS.drawings, DEMO_DRAWINGS);
  localStorage.setItem(KEYS.seeded, nowIso());
}

// ---- Sites ----

export function listSites(): Site[] {
  return read<Site>(KEYS.sites).sort((a, b) => b.updated_at.localeCompare(a.updated_at));
}

export function getSite(id: string): Site | undefined {
  return read<Site>(KEYS.sites).find((s) => s.id === id);
}

export function saveSite(site: Site): void {
  const sites = read<Site>(KEYS.sites).filter((s) => s.id !== site.id);
  sites.push({ ...site, updated_at: nowIso() });
  write(KEYS.sites, sites);
}

export function deleteSite(id: string): void {
  write(KEYS.sites, read<Site>(KEYS.sites).filter((s) => s.id !== id));
  write(KEYS.hazards, read<Hazard>(KEYS.hazards).filter((h) => h.site_id !== id));
  write(KEYS.drawings, read<Drawing>(KEYS.drawings).filter((d) => d.site_id !== id));
  write(KEYS.plans, read<ApproachPlan>(KEYS.plans).filter((p) => p.site_id !== id));
}

// ---- Truck profiles ----

export function listTrucks(): TruckProfile[] {
  return [...TRUCK_PRESETS, ...read<TruckProfile>(KEYS.trucks)];
}

export function getTruck(id: string): TruckProfile | undefined {
  return listTrucks().find((t) => t.id === id);
}

export function saveTruck(truck: TruckProfile): void {
  if (truck.preset) return;
  const trucks = read<TruckProfile>(KEYS.trucks).filter((t) => t.id !== truck.id);
  trucks.push(truck);
  write(KEYS.trucks, trucks);
}

export function deleteTruck(id: string): void {
  write(KEYS.trucks, read<TruckProfile>(KEYS.trucks).filter((t) => t.id !== id));
}

// ---- Hazards ----

export function listHazards(siteId: string): Hazard[] {
  return read<Hazard>(KEYS.hazards).filter((h) => h.site_id === siteId);
}

export function saveHazard(hazard: Hazard): void {
  const hazards = read<Hazard>(KEYS.hazards).filter((h) => h.id !== hazard.id);
  hazards.push(hazard);
  write(KEYS.hazards, hazards);
}

export function deleteHazard(id: string): void {
  write(KEYS.hazards, read<Hazard>(KEYS.hazards).filter((h) => h.id !== id));
}

// ---- Drawings ----

export function listDrawings(siteId: string): Drawing[] {
  return read<Drawing>(KEYS.drawings).filter((d) => d.site_id === siteId);
}

export function saveDrawing(drawing: Drawing): void {
  const drawings = read<Drawing>(KEYS.drawings).filter((d) => d.id !== drawing.id);
  drawings.push(drawing);
  write(KEYS.drawings, drawings);
}

export function deleteDrawing(id: string): void {
  write(KEYS.drawings, read<Drawing>(KEYS.drawings).filter((d) => d.id !== id));
}

// ---- Plans ----

export function listPlans(siteId?: string): ApproachPlan[] {
  const plans = read<ApproachPlan>(KEYS.plans);
  const filtered = siteId ? plans.filter((p) => p.site_id === siteId) : plans;
  return filtered.sort((a, b) => b.created_at.localeCompare(a.created_at));
}

export function getPlan(id: string): ApproachPlan | undefined {
  return read<ApproachPlan>(KEYS.plans).find((p) => p.id === id);
}

export function savePlan(plan: ApproachPlan): void {
  const plans = read<ApproachPlan>(KEYS.plans).filter((p) => p.id !== plan.id);
  plans.push(plan);
  write(KEYS.plans, plans);
}
