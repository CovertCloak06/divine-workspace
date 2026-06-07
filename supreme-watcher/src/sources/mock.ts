import type { Listing, Source } from './types.js';

/**
 * A test/demo Source that replays a fixed sequence of catalog snapshots.
 * Each call to fetchListings() returns the next snapshot (the last one repeats).
 * Used by `npm run demo` to exercise the real pipeline without hitting Supreme.
 */
export class MockSource implements Source {
  readonly name = 'Mock (demo)';
  private index = 0;

  constructor(private readonly snapshots: Listing[][]) {}

  async fetchListings(): Promise<Listing[]> {
    const snap = this.snapshots[Math.min(this.index, this.snapshots.length - 1)] ?? [];
    this.index++;
    return structuredClone(snap);
  }
}
