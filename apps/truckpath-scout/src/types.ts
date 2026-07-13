/** Core domain types for TruckPath Scout. */

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export type HazardType =
  | 'tight_turn'
  | 'narrow_road'
  | 'low_bridge'
  | 'low_wire'
  | 'tree_canopy'
  | 'steep_grade'
  | 'dead_end'
  | 'cul_de_sac'
  | 'soft_shoulder'
  | 'bad_backing_angle'
  | 'wrong_entrance'
  | 'correct_entrance'
  | 'loading_zone'
  | 'staging_area'
  | 'power_pole'
  | 'parked_cars'
  | 'blind_corner'
  | 'school_zone'
  | 'residential_restriction'
  | 'weight_limit'
  | 'one_way'
  | 'gate'
  | 'rough_surface'
  | 'construction_obstruction'
  | 'other';

export interface LatLng {
  lat: number;
  lng: number;
}

export interface Site {
  id: string;
  name: string;
  address: string;
  latitude: number;
  longitude: number;
  created_at: string;
  updated_at: string;
  notes: string;
  /** Site-level flags that feed risk scoring. */
  residential_road: boolean;
  backing_required: boolean;
  /** Default truck profile for this site. */
  truck_profile_id: string | null;
  contact: string;
}

export type VehicleType =
  | 'semi_53'
  | 'semi_48'
  | 'box_truck'
  | 'dump_truck'
  | 'concrete_truck'
  | 'lowboy'
  | 'roll_off'
  | 'custom';

export interface TruckProfile {
  id: string;
  name: string;
  vehicle_type: VehicleType;
  length_ft: number;
  width_ft: number;
  height_ft: number;
  gross_weight_lbs: number;
  trailer_type: string;
  turning_notes: string;
  /** Preset profiles ship with the app and cannot be deleted. */
  preset: boolean;
}

export interface Hazard {
  id: string;
  site_id: string;
  type: HazardType;
  latitude: number;
  longitude: number;
  severity: Severity;
  notes: string;
  photo_url?: string;
}

/** Sketches drawn on the map: approach arrows, no-go roads, staging areas. */
export type DrawingKind = 'approach_arrow' | 'no_go' | 'staging_zone';

export interface Drawing {
  id: string;
  site_id: string;
  kind: DrawingKind;
  points: LatLng[];
  notes: string;
}

export type ApproachDirection =
  | 'north'
  | 'northeast'
  | 'east'
  | 'southeast'
  | 'south'
  | 'southwest'
  | 'west'
  | 'northwest'
  | 'unspecified';

export interface ApproachPlan {
  id: string;
  site_id: string;
  truck_profile_id: string;
  preferred_approach_direction: ApproachDirection;
  avoid_streets: string[];
  staging_area_notes: string;
  backing_notes: string;
  unloading_notes: string;
  generated_driver_instructions: string;
  sms_text: string;
  risk_score: number;
  risk_label: RiskLabel;
  created_at: string;
}

export type RiskLabel = 'Low' | 'Moderate' | 'High' | 'Critical';

export interface RiskBreakdownItem {
  label: string;
  points: number;
}

export interface RiskResult {
  score: number;
  label: RiskLabel;
  breakdown: RiskBreakdownItem[];
}

/** Everything needed to render or share one plan, bundled. */
export interface PlanBundle {
  site: Site;
  truck: TruckProfile;
  hazards: Hazard[];
  drawings: Drawing[];
  plan: ApproachPlan;
}
