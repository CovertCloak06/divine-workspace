import { log } from '../logger.js';
import type { Listing } from '../sources/types.js';

export type AlertKind = 'new' | 'restock' | 'price-drop';

const KIND_LABEL: Record<AlertKind, string> = {
  new: '🆕 New',
  restock: '🔁 Restock',
  'price-drop': '💸 Price drop',
};

const PUSHOVER_API = 'https://api.pushover.net/1/messages.json';

export interface PushoverConfig {
  token: string;
  user: string;
}

/**
 * Send a Pushover notification for a listing.
 * Uses the item image as the notification icon (supplementary_url) and the
 * product page as the tap-through URL.
 */
export async function notifyPushover(
  cfg: PushoverConfig,
  kind: AlertKind,
  listing: Listing,
): Promise<void> {
  const title = `${KIND_LABEL[kind]}: ${listing.name}`;
  const price = listing.price > 0 ? `$${listing.price.toFixed(2)}` : 'n/a';
  const status = listing.soldOut ? 'SOLD OUT' : 'In stock';
  const message = `${listing.category} — ${price} (${status})`;

  const body = new URLSearchParams({
    token: cfg.token,
    user: cfg.user,
    title,
    message,
    url: listing.url,
    url_title: 'Open on Supreme',
    priority: kind === 'restock' || kind === 'new' ? '1' : '0',
  });

  const res = await fetch(PUSHOVER_API, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Pushover error ${res.status}: ${text}`);
  }
  log.debug(`Pushover sent: ${title}`);
}
