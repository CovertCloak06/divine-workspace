import { log } from '../logger.js';
import type { Listing, Source } from './types.js';

/**
 * Shape of a product in supremenewyork.com's /mobile_stock.json feed.
 * Prices are integers in cents (e.g. 4800 => $48.00).
 */
interface SupremeProduct {
  id: number;
  name: string;
  image_url?: string;
  price: number;
  sale_price?: number;
  new_item?: boolean;
  category_name?: string;
  sold_out?: boolean;
}

interface MobileStock {
  products_and_categories?: Record<string, SupremeProduct[]>;
}

const DEFAULT_UA =
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 ' +
  '(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1';

async function fetchJson<T>(url: string, timeoutMs = 15_000): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        'User-Agent': process.env.USER_AGENT || DEFAULT_UA,
        Accept: 'application/json',
      },
    });
    if (!res.ok) {
      if (res.status === 403) {
        throw new Error(
          `HTTP 403 from Supreme — the host IP is likely blocked by anti-bot ` +
            `protection. Run from a residential connection (home network / Pi / phone) ` +
            `or use a residential proxy. (${url})`,
        );
      }
      throw new Error(`HTTP ${res.status} ${res.statusText} for ${url}`);
    }
    return (await res.json()) as T;
  } finally {
    clearTimeout(timer);
  }
}

/** Supreme official store adapter (US or EU, by base URL). */
export class SupremeSource implements Source {
  readonly name: string;

  constructor(private readonly baseUrl: string) {
    this.name = `Supreme (${baseUrl.includes('uk.') ? 'EU' : 'US'})`;
  }

  async fetchListings(): Promise<Listing[]> {
    const url = `${this.baseUrl}/mobile_stock.json`;
    const data = await fetchJson<MobileStock>(url);
    const groups = data.products_and_categories ?? {};
    const listings: Listing[] = [];

    for (const [category, products] of Object.entries(groups)) {
      if (!Array.isArray(products)) continue;
      for (const p of products) {
        if (p == null || typeof p.id !== 'number') continue;
        const cents = typeof p.sale_price === 'number' && p.sale_price > 0 ? p.sale_price : p.price;
        listings.push({
          id: String(p.id),
          name: p.name ?? 'Unknown',
          category: p.category_name ?? category,
          price: Math.round((cents ?? 0)) / 100,
          soldOut: Boolean(p.sold_out),
          imageUrl: p.image_url?.startsWith('//') ? `https:${p.image_url}` : p.image_url,
          url: `${this.baseUrl}/shop/${p.id}`,
        });
      }
    }

    log.debug(`Fetched ${listings.length} listings from ${this.name}`);
    return listings;
  }
}
