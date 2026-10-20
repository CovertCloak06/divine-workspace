# 🚛 TruckPath Scout

**Last-mile truck access planning and delivery guidance tool.**

Normal GPS gets a driver to an address. It does not solve the last mile: tight turns, low wires,
wrong entrances, dead-end streets, bad backing angles, soft shoulders. TruckPath Scout is a
field tool for foremen, dispatchers, flaggers, and delivery coordinators to walk a site,
mark hazards on a satellite map, and hand the driver a clear approach plan.

This is not a consumer navigation app. It is a professional field-planning tool: the user
marks the hazards, the app organizes them into a plan, a risk score, driver instructions,
an SMS message, and a shareable link/PDF.

## Quick start

```bash
cd apps/truckpath-scout
npm install
npm run dev        # http://localhost:5180
```

```bash
npm run build      # type-check + production build to dist/
npm run preview    # serve the production build
```

**Zero configuration required.** No API keys are needed to run the MVP. A demo site
("Demo: Maple St Concrete Pour") is seeded on first launch so every screen is explorable
immediately.

## Environment variables (all optional)

See [`env.example`](./env.example). Copy to `.env` to use.

| Variable | Purpose | Default |
|----------|---------|---------|
| `VITE_AI_ENDPOINT` | OpenAI/Claude-compatible chat completions endpoint to polish driver instructions with an LLM | unset → deterministic template generator |
| `VITE_AI_API_KEY` | Bearer token for that endpoint | unset |
| `VITE_AI_MODEL` | Model name sent to that endpoint | `claude-sonnet-5` |

## Maps & geocoding (which APIs are used)

| Concern | Provider | Key needed |
|---------|----------|------------|
| Street basemap | OpenStreetMap standard tiles | No |
| Satellite layer | Esri World Imagery (ArcGIS Online) | No |
| Geocoding | OpenStreetMap **Nominatim** (`nominatim.openstreetmap.org`) | No |
| Map engine | Leaflet 1.9 | — |

Nominatim's usage policy allows light, user-triggered lookups (searches here are
button-triggered, never typed-ahead). To switch to Mapbox or Google geocoding, replace one
function in [`src/lib/geocode.ts`](./src/lib/geocode.ts); tile URLs live at the top of
[`src/components/MapView.tsx`](./src/components/MapView.tsx).

## How it works

**Workflow:** Dashboard → New Site (address search) → Site Planner map → mark hazards / sketch
approach → Generate Plan → review, text the driver, share link, export PDF.

- **Storage is local-first.** Everything persists in `localStorage` (`src/lib/storage.ts` is
  the single persistence layer — swap it for an API client to add a backend). No login, no
  server. Saved sites work offline; map tiles need a connection.
- **Markers:** 25 hazard/zone types (tight turn, low wire, wrong entrance, staging area, …),
  each with severity (low/medium/high/critical), notes, drag-to-move, tap-to-edit/delete.
- **Sketches:** approach arrows (green, with arrowhead), no-go roads (red dashed), staging
  zones (cyan polygon). Tap points → Done. Tap a sketch to delete it.
- **Truck profiles:** 7 seeded presets (53/48 ft semi, box, dump, concrete, lowboy, roll-off)
  plus custom dimensions.
- **Risk score** (deterministic, `src/lib/risk.ts`): base 1; +0.5/+1/+2/+3 per hazard by
  severity; type bonuses (low wire/bridge +3, dead end/cul-de-sac +2, tight turn +1); backing
  required +1.5; residential road +1; no staging area +1; capped at 10.
  Labels: 1–3 Low · 4–6 Moderate · 7–8 High · 9–10 Critical.
- **Driver instructions** are generated from the structured plan by a template
  (`src/lib/instructions.ts`), plus an SMS version guaranteed ≤ 600 characters with a
  one-tap `sms:` compose link. If `VITE_AI_ENDPOINT` is set, an LLM rewrites the template
  (falls back to the template on any failure).
- **Share links** compress the entire plan bundle into the URL hash (lz-string) — the
  recipient needs no account and nothing is stored on any server.
- **PDF export** uses the browser print dialog with a print stylesheet (works with
  Android Chrome → Share/Print → Save as PDF).

## Example site plan (from the seeded demo)

```
TRUCK DELIVERY APPROACH PLAN

Truck:
Concrete Truck — 30 ft L × 8.5 ft W × 12.5 ft H, 66,000 lbs GVW

Destination:
Demo: Maple St Concrete Pour — 4820 Maple St, Omaha, NE 68104

Best approach:
Approach from the NORTHEAST

Do:
- Approach from the NORTHEAST
- Use the marked entrance: East driveway — enter here
- Stage first: Church parking lot on 48th
- Backing: Back in from the east with spotter
- Call Foreman Mike 402-555-0147 before final approach

Avoid:
- West alley (too narrow for mixer)
- Low Wires: Service drop over driveway, ~13 ft

Arrival:
- Stage at Church parking lot on 48th
- Call Foreman Mike 402-555-0147 before entering
- Use the marked entrance (East driveway — enter here)
- Back in — from the east with spotter

Hazards:
- Low Wires — Service drop over driveway, ~13 ft [HIGH]
- Tight Turn — Right turn off 48th — swing wide [MEDIUM]

Risk:
10/10 — Critical
```

(The demo intentionally scores at the cap: high-severity low wires (+5), a tight turn (+2),
backing required (+1.5), and a residential street (+1) on top of the base score. Delete a
hazard or clear a site flag in the planner and the badge recalculates live.)

## Project structure

```
src/
├── types.ts               # Site, TruckProfile, Hazard, Drawing, ApproachPlan
├── data/
│   ├── hazardTypes.ts     # 25 hazard/zone definitions (icons, colors, risk bonuses)
│   ├── truckPresets.ts    # 7 seeded truck profiles
│   └── demoData.ts        # Demo site + hazards + sketches
├── lib/
│   ├── storage.ts         # localStorage persistence (swap for API later)
│   ├── risk.ts            # deterministic risk scoring
│   ├── instructions.ts    # plan + SMS generator, AI hook
│   ├── geocode.ts         # Nominatim (swap provider here)
│   └── share.ts           # lz-string URL-encoded share links
├── components/
│   ├── MapView.tsx        # Leaflet wrapper: pins, sketches, sat toggle, locate
│   ├── PlanSheet.tsx      # read-only plan rendering (review/share/print)
│   ├── RiskBadge.tsx
│   └── TopBar.tsx
└── pages/
    ├── Dashboard.tsx      # recent sites, search, delete
    ├── CreateSite.tsx     # address search + site details
    ├── SitePlanner.tsx    # full-screen map, marker/sketch tools, plan generator
    ├── PlanReview.tsx     # instructions, SMS, share, PDF
    ├── SharedPlan.tsx     # read-only view for shared links
    └── TruckProfiles.tsx  # presets + custom trucks
```

Field-friendly UI rules used throughout: 48 px minimum touch targets, high-contrast
hi-vis palette, bottom sheets instead of tiny dialogs, one-thumb reachable toolbar.

## Future roadmap (hooks already in place)

- **Computer vision analysis** of satellite/street imagery (hazard suggestions).
- **Automatic road-width estimation** from imagery.
- **Turn-radius simulation** using the truck profile dimensions already captured.
- **Truck-restriction / DOT data overlays** (bridge heights, weight limits).
- **Photo uploads** from site walks (`Hazard.photo_url` field already exists).
- **Voice notes** on markers.
- **Live driver location sharing.**
- **Team/company accounts** — replace `lib/storage.ts` with an API client
  (FastAPI + PostgreSQL/PostGIS recommended); the data model mirrors the entities 1:1.
- **AI route audit** — `generateWithAi()` in `lib/instructions.ts` is the entry point.
- **Weather/road condition risk** added to the risk breakdown.

## Notes

- shadcn/ui was intentionally skipped for the MVP: the field-grade UI needs oversized,
  high-contrast controls, which are simpler as ~10 Tailwind component classes than as a
  themed component library. Adding shadcn later doesn't conflict with anything here.
- SQLite/FastAPI backend was deferred per the local-first MVP requirement; every entity in
  the spec (`Site`, `TruckProfile`, `Hazard`, `ApproachPlan`) exists as a typed interface in
  `src/types.ts`, so a backend can adopt the schema directly.
