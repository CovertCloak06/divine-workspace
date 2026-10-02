import { z } from 'zod';

/** Parse a comma-separated env value into a lowercased, trimmed string array. */
function csv(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

const boolish = (def: boolean) =>
  z
    .string()
    .optional()
    .transform((v) => (v === undefined ? def : /^(1|true|yes|on)$/i.test(v)));

const RawConfig = z.object({
  PUSHOVER_TOKEN: z.string().min(1, 'PUSHOVER_TOKEN is required'),
  PUSHOVER_USER: z.string().min(1, 'PUSHOVER_USER is required'),
  SUPREME_BASE_URL: z.string().url().default('https://www.supremenewyork.com'),
  POLL_INTERVAL_MS: z.coerce.number().int().min(10_000).default(60_000),
  JITTER_MS: z.coerce.number().int().min(0).default(15_000),
  WATCH_KEYWORDS: z.string().optional(),
  WATCH_CATEGORIES: z.string().optional(),
  MAX_PRICE: z
    .string()
    .optional()
    .transform((v) => (v && v.trim() ? Number(v) : undefined)),
  ALERT_ON_RESTOCK: boolish(true),
  ALERT_ON_PRICE_DROP: boolish(false),
  DRY_RUN: boolish(false),
  STORE_PATH: z.string().default('./data/state.json'),
});

export interface Config {
  pushoverToken: string;
  pushoverUser: string;
  baseUrl: string;
  pollIntervalMs: number;
  jitterMs: number;
  keywords: string[];
  categories: string[];
  maxPrice: number | undefined;
  alertOnRestock: boolean;
  alertOnPriceDrop: boolean;
  dryRun: boolean;
  storePath: string;
}

/** Load and validate configuration from process.env. Throws on invalid input. */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = RawConfig.safeParse(env);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `  - ${i.path.join('.')}: ${i.message}`);
    throw new Error(`Invalid configuration:\n${issues.join('\n')}`);
  }
  const r = parsed.data;
  return {
    pushoverToken: r.PUSHOVER_TOKEN,
    pushoverUser: r.PUSHOVER_USER,
    baseUrl: r.SUPREME_BASE_URL.replace(/\/$/, ''),
    pollIntervalMs: r.POLL_INTERVAL_MS,
    jitterMs: r.JITTER_MS,
    keywords: csv(r.WATCH_KEYWORDS),
    categories: csv(r.WATCH_CATEGORIES),
    maxPrice: r.MAX_PRICE,
    alertOnRestock: r.ALERT_ON_RESTOCK,
    alertOnPriceDrop: r.ALERT_ON_PRICE_DROP,
    dryRun: r.DRY_RUN,
    storePath: r.STORE_PATH,
  };
}
