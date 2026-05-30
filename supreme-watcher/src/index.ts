import { type Config, loadConfig } from './config.js';
import { loadDotenv } from './env.js';
import { log } from './logger.js';
import { type Criteria, matches } from './matcher.js';
import { type AlertKind, notifyPushover } from './notify/pushover.js';
import { SupremeSource } from './sources/supreme.js';
import type { Listing, Source } from './sources/types.js';
import { Store } from './store.js';

let running = true;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Decide what kind of alert (if any) a listing warrants vs. its prior state. */
function classify(listing: Listing, store: Store, cfg: Config): AlertKind | null {
  const prev = store.get(listing.id);
  if (!prev) return 'new';
  if (cfg.alertOnRestock && prev.soldOut && !listing.soldOut) return 'restock';
  if (cfg.alertOnPriceDrop && listing.price < prev.price) return 'price-drop';
  return null;
}

async function runCycle(
  source: Source,
  store: Store,
  cfg: Config,
  criteria: Criteria,
  seeding: boolean,
): Promise<void> {
  const listings = await source.fetchListings();
  let alerts = 0;

  for (const listing of listings) {
    const kind = classify(listing, store, cfg);
    // Always record current state for next cycle.
    store.set(listing.id, { soldOut: listing.soldOut, price: listing.price });

    if (seeding || !kind) continue;
    if (!matches(listing, criteria)) continue;

    if (cfg.dryRun) {
      log.info(`[DRY_RUN] ${kind}: ${listing.name} ($${listing.price}) ${listing.url}`);
    } else {
      try {
        await notifyPushover(
          { token: cfg.pushoverToken, user: cfg.pushoverUser },
          kind,
          listing,
        );
        log.info(`Alerted (${kind}): ${listing.name}`);
      } catch (err) {
        log.error(`Failed to notify for ${listing.name}`, err);
      }
    }
    alerts++;
  }

  await store.save();
  if (seeding) {
    log.info(`Seeded ${listings.length} listings (no alerts on first run).`);
  } else {
    log.info(`Cycle complete: ${listings.length} listings, ${alerts} alert(s).`);
  }
}

async function main(): Promise<void> {
  loadDotenv();
  const cfg = loadConfig();
  const criteria: Criteria = {
    keywords: cfg.keywords,
    categories: cfg.categories,
    maxPrice: cfg.maxPrice,
  };

  const source = new SupremeSource(cfg.baseUrl);
  const store = new Store(cfg.storePath);
  await store.load();

  log.info(`Watching ${source.name} every ~${Math.round(cfg.pollIntervalMs / 1000)}s` +
    (cfg.dryRun ? ' [DRY_RUN]' : ''));
  if (cfg.keywords.length) log.info(`Keyword filter: ${cfg.keywords.join(', ')}`);
  if (cfg.categories.length) log.info(`Category filter: ${cfg.categories.join(', ')}`);
  if (cfg.maxPrice !== undefined) log.info(`Max price: $${cfg.maxPrice}`);

  const shutdown = () => {
    log.info('Shutting down…');
    running = false;
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  // Seed silently on first run (empty store) so we don't blast the whole catalog.
  let seeding = store.size() === 0;

  while (running) {
    try {
      await runCycle(source, store, cfg, criteria, seeding);
      seeding = false;
    } catch (err) {
      log.error('Cycle failed; will retry next interval.', err);
    }
    if (!running) break;
    const wait = cfg.pollIntervalMs + Math.floor(Math.random() * (cfg.jitterMs + 1));
    await sleep(wait);
  }

  await store.save().catch(() => {});
  log.info('Stopped.');
}

main().catch((err) => {
  log.error('Fatal error', err);
  process.exit(1);
});
