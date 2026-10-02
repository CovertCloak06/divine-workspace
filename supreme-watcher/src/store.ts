import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { log } from './logger.js';

/** Persisted per-item state used for dedupe and restock/price-drop detection. */
export interface ItemState {
  soldOut: boolean;
  price: number;
}

type StateMap = Record<string, ItemState>;

/**
 * A tiny JSON-file-backed state store. Zero dependencies, deploy-agnostic.
 * For Cloudflare Workers, swap this class for a KV/D1-backed implementation.
 */
export class Store {
  private state: StateMap = {};

  constructor(private readonly path: string) {}

  async load(): Promise<void> {
    try {
      const raw = await readFile(this.path, 'utf8');
      this.state = JSON.parse(raw) as StateMap;
      log.debug(`Loaded ${Object.keys(this.state).length} items from ${this.path}`);
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        log.info(`No existing state at ${this.path}; starting fresh.`);
        this.state = {};
      } else {
        throw err;
      }
    }
  }

  get(id: string): ItemState | undefined {
    return this.state[id];
  }

  has(id: string): boolean {
    return id in this.state;
  }

  /** Number of items currently tracked. */
  size(): number {
    return Object.keys(this.state).length;
  }

  set(id: string, value: ItemState): void {
    this.state[id] = value;
  }

  /** Atomically persist state (write temp + rename) to avoid corruption. */
  async save(): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    const tmp = `${this.path}.tmp`;
    await writeFile(tmp, JSON.stringify(this.state), 'utf8');
    await rename(tmp, this.path);
  }
}
