import { type Config, loadConfig } from './config.js';
import { runCycle } from './engine.js';
import { loadDotenv } from './env.js';
import { log } from './logger.js';
import type { Criteria } from './matcher.js';
import { SupremeSource } from './sources/supreme.js';
import { Store } from './store.js';

let running = true;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function criteriaFrom(cfg: Config): Criteria {
  return { keywords: cfg.keywords, categories: cfg.categories, maxPrice: cfg.maxPrice };
}

async function main(): Promise<void> {
  loadDotenv();
  const cfg = loadConfig();
  const criteria = criteriaFrom(cfg);

  const source = new SupremeSource(cfg.baseUrl);
  const store = new Store(cfg.storePath);
  await store.load();

  log.info(
    `Watching ${source.name} every ~${Math.round(cfg.pollIntervalMs / 1000)}s` +
      (cfg.dryRun ? ' [DRY_RUN]' : ''),
  );
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
