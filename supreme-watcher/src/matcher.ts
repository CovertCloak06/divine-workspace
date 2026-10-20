import type { Listing } from './sources/types.js';

export interface Criteria {
  /** Lowercased name substrings; empty = match any. */
  keywords: string[];
  /** Lowercased category names; empty = match any. */
  categories: string[];
  /** Max price in USD; undefined = no cap. */
  maxPrice: number | undefined;
}

/**
 * Returns true if a listing satisfies the watch criteria.
 * All provided filters must pass (AND). Empty filters are ignored.
 */
export function matches(listing: Listing, criteria: Criteria): boolean {
  const { keywords, categories, maxPrice } = criteria;

  if (keywords.length > 0) {
    const name = listing.name.toLowerCase();
    if (!keywords.some((k) => name.includes(k))) return false;
  }

  if (categories.length > 0) {
    if (!categories.includes(listing.category.toLowerCase())) return false;
  }

  if (maxPrice !== undefined && listing.price > maxPrice) {
    return false;
  }

  return true;
}
