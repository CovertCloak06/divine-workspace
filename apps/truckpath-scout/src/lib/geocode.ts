/**
 * Geocoding via OpenStreetMap Nominatim (free, no API key).
 * Swap the base URL / provider here to move to Mapbox or Google.
 * Nominatim usage policy: max 1 req/sec — searches are user-triggered, not typed-ahead.
 */

export interface GeocodeResult {
  label: string;
  lat: number;
  lng: number;
}

const NOMINATIM_URL = 'https://nominatim.openstreetmap.org/search';

export async function geocode(query: string): Promise<GeocodeResult[]> {
  const url = `${NOMINATIM_URL}?format=jsonv2&limit=5&q=${encodeURIComponent(query)}`;
  const res = await fetch(url, {
    headers: { Accept: 'application/json' },
  });
  if (!res.ok) throw new Error(`Geocoding failed (${res.status})`);
  const data: Array<{ display_name: string; lat: string; lon: string }> = await res.json();
  return data.map((d) => ({
    label: d.display_name,
    lat: parseFloat(d.lat),
    lng: parseFloat(d.lon),
  }));
}
