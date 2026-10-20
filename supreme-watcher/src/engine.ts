import type { Config } from './config.js';
import { log } from './logger.js';
import { type Criteria, matches } from './matcher.js';
import { type AlertKind, notifyPushover } from './notify/pushover.js';
import type { Listing, Source } from './sources/types.js';
import type { Store } from './store.js';

/** Decide what kind of alert (if any) a listing warrants vs. its prior state. */
export function classify(listing: Listing, store: Store, cfg: Config): AlertKind | null {
  const prev = store.get(listing.id);
  if (!prev) return 'new';
  if (cfg.alertOnRestock && prev.soldOut && !listing.soldOut) return 'restock';
  if (cfg.alertOnPriceDrop && listing.price < prev.price) return 'price-drop';
  return null;
}

/**
 * Run one poll cycle: fetch listings, classify each against saved state,
 * notify on matches, and persist. On `seeding` runs, state is recorded but
 * no alerts are sent (used for the very first run to avoid alert spam).
 */
export async function runCycle(
  source: Source,
  store: Store,
  cfg: Config,
  criteria: Criteria,
  seeding: boolean,
): Promise<number> {
  const listings = await source.fetchListings();
  let alerts = 0;

  for (const listing of listings) {
    const kind = classify(listing, store, cfg);

    if (!seeding && kind && matches(listing, criteria)) {
      if (cfg.dryRun) {
        log.info(`[DRY_RUN] ${kind}: ${listing.name} ($${listing.price}) ${listing.url}`);
      } else {
        try {
          await notifyPushover({ token: cfg.pushoverToken, user: cfg.pushoverUser }, kind, listing);
          log.info(`Alerted (${kind}): ${listing.name}`);
        } catch (err) {
          // Delivery failed: leave the prior state untouched so this alert is
          // re-detected and retried next cycle instead of being silently lost.
          log.error(`Failed to notify for ${listing.name}; will retry next cycle.`, err);
          continue;
        }
      }
      alerts++;
    }

    // Advance stored state only after a successful alert, or when none was due.
    store.set(listing.id, { soldOut: listing.soldOut, price: listing.price });
  }

  await store.save();
  if (seeding) {
    log.info(`Seeded ${listings.length} listings (no alerts on first run).`);
  } else {
    log.info(`Cycle complete: ${listings.length} listings, ${alerts} alert(s).`);
  }
  return alerts;
}
