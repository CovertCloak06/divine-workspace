import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Config } from './config.js';
import { runCycle } from './engine.js';
import { loadDotenv } from './env.js';
import { log } from './logger.js';
import type { Criteria } from './matcher.js';
import { MockSource } from './sources/mock.js';
import type { Listing } from './sources/types.js';
import { Store } from './store.js';

const BASE = 'https://www.supremenewyork.com';
const link = (id: number) => `${BASE}/shop/${id}`;

// Snapshot 1 — the initial catalog (recorded silently on the seed run).
const snapshot1: Listing[] = [
  { id: '1', name: 'Box Logo Tee', category: 'Tops/Sweaters', price: 48, soldOut: false, url: link(1) },
  { id: '2', name: 'Arc Logo Hooded Sweatshirt', category: 'Sweatshirts', price: 168, soldOut: true, url: link(2) },
  { id: '3', name: 'Camp Cap', category: 'Headwear', price: 58, soldOut: false, url: link(3) },
];

// Snapshot 2 — what the next poll sees. Three things changed:
//   #2 came back in stock (restock), #3 dropped in price, #4 is brand new.
const snapshot2: Listing[] = [
  { id: '1', name: 'Box Logo Tee', category: 'Tops/Sweaters', price: 48, soldOut: false, url: link(1) },
  { id: '2', name: 'Arc Logo Hooded Sweatshirt', category: 'Sweatshirts', price: 168, soldOut: false, url: link(2) },
  { id: '3', name: 'Camp Cap', category: 'Headwear', price: 48, soldOut: false, url: link(3) },
  { id: '4', name: 'Supreme Backpack', category: 'Bags', price: 128, soldOut: false, url: link(4) },
];

async function main(): Promise<void> {
  loadDotenv();

  const hasCreds = Boolean(process.env.PUSHOVER_TOKEN && process.env.PUSHOVER_USER);
  const storePath = join(await mkdtemp(join(tmpdir(), 'sw-demo-')), 'state.json');

  const cfg: Config = {
    pushoverToken: process.env.PUSHOVER_TOKEN ?? 'demo',
    pushoverUser: process.env.PUSHOVER_USER ?? 'demo',
    baseUrl: BASE,
    pollIntervalMs: 60_000,
    jitterMs: 0,
    keywords: [],
    categories: [],
    maxPrice: undefined,
    alertOnRestock: true,
    alertOnPriceDrop: true, // enabled so the demo shows price-drop too
    dryRun: !hasCreds, // no keys => just print; keys set => send real pushes
    storePath,
  };
  const criteria: Criteria = { keywords: [], categories: [], maxPrice: undefined };

  log.info('─'.repeat(60));
  log.info('DEMO: running the real detect→filter→alert pipeline on sample data');
  log.info(
    hasCreds
      ? 'Pushover keys detected → sending REAL notifications to your device.'
      : 'No Pushover keys → DRY RUN (prints alerts instead of sending). ' +
          'Set PUSHOVER_TOKEN and PUSHOVER_USER to get them on your phone.',
  );
  log.info('─'.repeat(60));

  const source = new MockSource([snapshot1, snapshot2]);
  const store = new Store(cfg.storePath);
  await store.load();

  log.info('Cycle 1 (seed): recording the current catalog, no alerts…');
  await runCycle(source, store, cfg, criteria, /* seeding */ true);

  log.info('Cycle 2: catalog changed — expect 3 alerts (restock, price-drop, new)…');
  const alerts = await runCycle(source, store, cfg, criteria, /* seeding */ false);

  log.info('─'.repeat(60));
  log.info(`DEMO complete: ${alerts} alert(s) ${hasCreds ? 'sent' : 'printed'}.`);
  if (hasCreds) log.info('Check the Pushover app — you should have 3 notifications.');
}

main().catch((err) => {
  log.error('Demo failed', err);
  process.exit(1);
});
