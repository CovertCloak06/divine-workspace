import { readFileSync } from 'node:fs';

/**
 * Minimal .env loader (no dependency). Loads KEY=VALUE lines into process.env
 * without overwriting variables already set in the real environment.
 * Supports # comments, blank lines, and optional surrounding quotes.
 */
export function loadDotenv(path = '.env'): void {
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch {
    return; // no .env file — rely on real environment (e.g. in production)
  }

  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    if (!key || key in process.env) continue;
    let value = trimmed.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    process.env[key] = value;
  }
}
