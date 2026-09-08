import type { Drawing, Hazard, Site } from '../types';

/** Demo site seeded on first run so the app is explorable immediately. */

export const DEMO_SITE: Site = {
  id: 'demo-site-1',
  name: 'Demo: Maple St Concrete Pour',
  address: '4820 Maple St, Omaha, NE 68104',
  latitude: 41.29081,
  longitude: -95.99937,
  created_at: '2026-07-01T14:00:00.000Z',
  updated_at: '2026-07-01T14:00:00.000Z',
  notes: 'Residential pour. Narrow street, wires on south side. Pump truck stages in church lot.',
  residential_road: true,
  backing_required: true,
  truck_profile_id: 'preset-concrete',
  contact: 'Foreman Mike 402-555-0147',
};

export const DEMO_HAZARDS: Hazard[] = [
  {
    id: 'demo-hz-1',
    site_id: 'demo-site-1',
    type: 'correct_entrance',
    latitude: 41.29105,
    longitude: -95.99885,
    severity: 'low',
    notes: 'East driveway — enter here',
  },
  {
    id: 'demo-hz-2',
    site_id: 'demo-site-1',
    type: 'wrong_entrance',
    latitude: 41.29066,
    longitude: -95.99995,
    severity: 'medium',
    notes: 'West alley too narrow for mixer',
  },
  {
    id: 'demo-hz-3',
    site_id: 'demo-site-1',
    type: 'low_wire',
    latitude: 41.29055,
    longitude: -95.99920,
    severity: 'high',
    notes: 'Service drop over driveway, ~13 ft',
  },
  {
    id: 'demo-hz-4',
    site_id: 'demo-site-1',
    type: 'tight_turn',
    latitude: 41.29120,
    longitude: -95.99850,
    severity: 'medium',
    notes: 'Right turn off 48th — swing wide',
  },
  {
    id: 'demo-hz-5',
    site_id: 'demo-site-1',
    type: 'staging_area',
    latitude: 41.29150,
    longitude: -95.99800,
    severity: 'low',
    notes: 'Church parking lot — OK per office',
  },
];

export const DEMO_DRAWINGS: Drawing[] = [
  {
    id: 'demo-dr-1',
    site_id: 'demo-site-1',
    kind: 'approach_arrow',
    points: [
      { lat: 41.29190, lng: -95.99760 },
      { lat: 41.29140, lng: -95.99845 },
      { lat: 41.29105, lng: -95.99885 },
    ],
    notes: 'Come in from 48th St heading southwest',
  },
  {
    id: 'demo-dr-2',
    site_id: 'demo-site-1',
    kind: 'no_go',
    points: [
      { lat: 41.29060, lng: -96.00040 },
      { lat: 41.29068, lng: -95.99960 },
    ],
    notes: 'West alley — do not enter',
  },
];
