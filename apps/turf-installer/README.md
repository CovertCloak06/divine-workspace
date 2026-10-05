# TurfPro — Field Turf Job & Material Estimator

A tiny, offline-first PWA for estimating artificial turf installs on the job
site. Punch in the measured areas, adjust your material rates and prices, and
get a per-item material list plus a total you can share or copy to a customer.

Built as a plain static app (HTML + CSS + vanilla JS, no build step) to match
the other apps in this monorepo. Everything runs in the browser; saved jobs
live in `localStorage`. **All numbers are estimates** — confirm supplier pack
sizes and add your own safety margin before ordering.

## Features

- **Measured areas** — add as many `length × width` rectangles as the job needs;
  break irregular shapes into rectangles. Live square-footage per row and total.
- **Waste / cut factor** — net area vs. gross area (what you actually buy/lay).
- **Material estimator** with editable defaults:
  - Turf (ft² at gross, plus how many roll-width strips)
  - Infill (lb + 50 lb bag count)
  - Base material (yd³ for a given depth)
  - Nails / staples
  - Seaming tape + glue (by linear ft)
  - Labor (per ft²)
  - Markup (%)
- **Estimate table** — per-item quantity and cost, subtotal, markup, total.
- **Save / load jobs** — persisted locally, reopen or delete any time.
- **Share / copy** — native share sheet on mobile, clipboard fallback on desktop.
- **Installable PWA** — works fully offline once loaded.

## Calculation model

```
net area      = Σ(length × width) of each rectangle
gross area    = net × (1 + waste%)              # turf purchased/laid
turf strips   = ceil(gross ÷ roll width)        # informational
infill (lb)   = net × infill rate
base (yd³)    = net × (depth_in ÷ 12) ÷ 27
nails         = round(net × nails per ft²)
seam cost     = seam length × seam price
labor         = net × labor rate
subtotal      = Σ item costs
markup        = subtotal × markup%
total         = subtotal + markup
```

Turf is bought at **gross** area (waste included). Infill, base, nails, and
labor are figured on **net** installed area. Adjust every rate to match your
crew's real spec and your supplier's pricing.

## Run locally

No dependencies — serve the folder with any static server:

```bash
cd apps/turf-installer
python3 -m http.server 8080
# open http://localhost:8080
```

## Files

| File | Purpose |
|------|---------|
| `index.html` | Layout + inputs |
| `style.css` | Turf-green, thumb-friendly styling |
| `app.js` | Calculator, save/load, share, service-worker registration |
| `sw.js` | Offline app-shell cache |
| `manifest.webmanifest` | PWA install metadata |
| `assets/icon.svg` | App icon |
| `version.json` | Version label shown in the footer |

## Ideas / next steps

- Photos per job (camera capture)
- Roll-layout optimizer (minimize seams for a given roll width)
- Export estimate as PDF
- Multiple infill types (silica vs. rubber) with separate rates
- Cloud sync so estimates follow you across devices
