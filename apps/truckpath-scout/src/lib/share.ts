import { compressToEncodedURIComponent, decompressFromEncodedURIComponent } from 'lz-string';
import type { PlanBundle } from '../types';

/**
 * Shareable links: the whole plan bundle is compressed into the URL hash,
 * so recipients need no account and no server. Works fully offline-to-offline.
 */

export function encodePlanToUrl(bundle: PlanBundle): string {
  const payload = compressToEncodedURIComponent(JSON.stringify(bundle));
  return `${window.location.origin}${import.meta.env.BASE_URL}#/shared/${payload}`;
}

export function decodePlanFromParam(param: string): PlanBundle | null {
  try {
    const json = decompressFromEncodedURIComponent(param);
    if (!json) return null;
    return JSON.parse(json) as PlanBundle;
  } catch {
    return null;
  }
}
