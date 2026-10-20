import { useEffect, useRef, useState } from 'react';
import L from 'leaflet';
import type { Drawing, DrawingKind, Hazard, LatLng } from '../types';
import { HAZARD_TYPE_MAP } from '../data/hazardTypes';

export interface MapViewProps {
  center: LatLng;
  zoom?: number;
  hazards: Hazard[];
  drawings: Drawing[];
  /** In-progress sketch points (tap-to-add). */
  draftPoints?: LatLng[];
  draftKind?: DrawingKind | null;
  selectedHazardId?: string | null;
  interactive?: boolean;
  onMapTap?: (point: LatLng) => void;
  onHazardTap?: (id: string) => void;
  onHazardMove?: (id: string, point: LatLng) => void;
  onDrawingTap?: (id: string) => void;
}

const STREET_URL = 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png';
const STREET_ATTR = '&copy; OpenStreetMap contributors';
const SAT_URL =
  'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}';
const SAT_ATTR = 'Imagery &copy; Esri';

const DRAWING_STYLES: Record<DrawingKind, L.PolylineOptions> = {
  approach_arrow: { color: '#22c55e', weight: 5, opacity: 0.9 },
  no_go: { color: '#ef4444', weight: 6, opacity: 0.9, dashArray: '10 8' },
  staging_zone: { color: '#06b6d4', weight: 3, opacity: 0.9, fillColor: '#06b6d4', fillOpacity: 0.25 },
};

function pinIcon(hazard: Hazard, selected: boolean): L.DivIcon {
  const def = HAZARD_TYPE_MAP[hazard.type];
  return L.divIcon({
    className: '',
    html: `<div class="tps-pin ${selected ? 'tps-pin-selected' : ''}" style="background:${def.color}">${def.icon}</div>`,
    iconSize: [38, 38],
    iconAnchor: [19, 34],
  });
}

function bearing(a: LatLng, b: LatLng): number {
  return (Math.atan2(b.lng - a.lng, a.lat - b.lat) * 180) / Math.PI;
}

function arrowheadIcon(angle: number): L.DivIcon {
  return L.divIcon({
    className: '',
    html: `<div class="tps-arrowhead" style="transform: rotate(${angle}deg)">▲</div>`,
    iconSize: [26, 26],
    iconAnchor: [13, 13],
  });
}

export default function MapView(props: MapViewProps) {
  const {
    center,
    zoom = 17,
    hazards,
    drawings,
    draftPoints = [],
    draftKind = null,
    selectedHazardId = null,
    interactive = true,
    onMapTap,
    onHazardTap,
    onHazardMove,
    onDrawingTap,
  } = props;

  const containerRef = useRef<HTMLDivElement>(null);
  const mapRef = useRef<L.Map | null>(null);
  const overlayRef = useRef<L.LayerGroup | null>(null);
  const baseLayersRef = useRef<{ street: L.TileLayer; sat: L.TileLayer } | null>(null);
  const [satellite, setSatellite] = useState(true);

  // Keep latest callbacks without re-binding map events.
  const cbRef = useRef({ onMapTap, onHazardTap, onHazardMove, onDrawingTap });
  cbRef.current = { onMapTap, onHazardTap, onHazardMove, onDrawingTap };

  // Init map once.
  useEffect(() => {
    if (!containerRef.current || mapRef.current) return;
    const map = L.map(containerRef.current, {
      center: [center.lat, center.lng],
      zoom,
      zoomControl: false,
      attributionControl: true,
    });
    L.control.zoom({ position: 'bottomright' }).addTo(map);

    const street = L.tileLayer(STREET_URL, { attribution: STREET_ATTR, maxZoom: 19 });
    const sat = L.tileLayer(SAT_URL, { attribution: SAT_ATTR, maxZoom: 19 });
    sat.addTo(map);
    baseLayersRef.current = { street, sat };

    overlayRef.current = L.layerGroup().addTo(map);

    map.on('click', (e: L.LeafletMouseEvent) => {
      cbRef.current.onMapTap?.({ lat: e.latlng.lat, lng: e.latlng.lng });
    });

    mapRef.current = map;
    return () => {
      map.remove();
      mapRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Base layer toggle.
  useEffect(() => {
    const map = mapRef.current;
    const layers = baseLayersRef.current;
    if (!map || !layers) return;
    if (satellite) {
      map.removeLayer(layers.street);
      layers.sat.addTo(map);
    } else {
      map.removeLayer(layers.sat);
      layers.street.addTo(map);
    }
  }, [satellite]);

  // Recenter when the center prop changes (e.g. after geocoding).
  useEffect(() => {
    mapRef.current?.setView([center.lat, center.lng]);
  }, [center.lat, center.lng]);

  // Redraw overlays whenever data changes.
  useEffect(() => {
    const overlay = overlayRef.current;
    if (!overlay) return;
    overlay.clearLayers();

    for (const drawing of drawings) {
      addDrawing(overlay, drawing.kind, drawing.points, false, () =>
        cbRef.current.onDrawingTap?.(drawing.id),
      );
    }
    if (draftKind && draftPoints.length > 0) {
      addDrawing(overlay, draftKind, draftPoints, true);
    }

    for (const hazard of hazards) {
      const marker = L.marker([hazard.latitude, hazard.longitude], {
        icon: pinIcon(hazard, hazard.id === selectedHazardId),
        draggable: interactive,
      });
      marker.on('click', (e) => {
        L.DomEvent.stopPropagation(e);
        cbRef.current.onHazardTap?.(hazard.id);
      });
      marker.on('dragend', () => {
        const p = marker.getLatLng();
        cbRef.current.onHazardMove?.(hazard.id, { lat: p.lat, lng: p.lng });
      });
      overlay.addLayer(marker);
    }
  }, [hazards, drawings, draftPoints, draftKind, selectedHazardId, interactive]);

  function locate() {
    const map = mapRef.current;
    if (!map) return;
    navigator.geolocation?.getCurrentPosition(
      (pos) => map.setView([pos.coords.latitude, pos.coords.longitude], 18),
      () => alert('Could not get your location. Check location permissions.'),
      { enableHighAccuracy: true, timeout: 10000 },
    );
  }

  return (
    <div className="relative h-full w-full">
      <div ref={containerRef} className="h-full w-full" />
      <div className="absolute right-3 top-3 z-[1000] flex flex-col gap-2">
        <button
          className="btn-secondary !min-w-touch shadow-lg"
          onClick={() => setSatellite((s) => !s)}
          aria-label="Toggle satellite view"
        >
          {satellite ? '🗺️' : '🛰️'}
        </button>
        <button className="btn-secondary !min-w-touch shadow-lg" onClick={locate} aria-label="My location">
          📍
        </button>
      </div>
    </div>
  );
}

function addDrawing(
  overlay: L.LayerGroup,
  kind: DrawingKind,
  points: LatLng[],
  isDraft: boolean,
  onTap?: () => void,
) {
  if (points.length === 0) return;
  const latlngs = points.map((p) => [p.lat, p.lng]) as [number, number][];
  const style = { ...DRAWING_STYLES[kind], ...(isDraft ? { opacity: 0.6, dashArray: '4 6' } : {}) };

  let layer: L.Path;
  if (kind === 'staging_zone' && points.length >= 3) {
    layer = L.polygon(latlngs, style);
  } else {
    layer = L.polyline(latlngs, style);
  }
  if (onTap) {
    layer.on('click', (e) => {
      L.DomEvent.stopPropagation(e);
      onTap();
    });
  }
  overlay.addLayer(layer);

  // Draft vertices so the user can see each tapped point.
  if (isDraft) {
    for (const p of points) {
      overlay.addLayer(
        L.circleMarker([p.lat, p.lng], { radius: 6, color: '#fff', fillColor: '#ffb400', fillOpacity: 1 }),
      );
    }
  }

  // Arrowhead at the end of approach arrows.
  if (kind === 'approach_arrow' && points.length >= 2 && !isDraft) {
    const a = points[points.length - 2];
    const b = points[points.length - 1];
    overlay.addLayer(L.marker([b.lat, b.lng], { icon: arrowheadIcon(bearing(a, b)), interactive: false }));
  }
}
