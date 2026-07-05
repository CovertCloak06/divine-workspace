/* Frostline service worker
 * Cache the app shell so the PWA opens instantly offline and qualifies for
 * the install prompt. Bumps the cache name on every release so old assets
 * are evicted cleanly.
 */
const CACHE = 'frostline-v15-wos73';
/* SHELL urls are stored WITHOUT version query strings; cache lookups use
 * { ignoreSearch: true } so a request for /app.js?v=wos60 still matches
 * the cached /app.js. This avoids re-listing every URL on each version bump. */
const SHELL = [
  '/',
  '/index.html',
  '/style.css',
  '/app.js',
  '/art.js',
  '/palette-data.js',
  '/manifest.webmanifest',
  '/assets/bg-frostline.webp',
  '/assets/snow-cap.png',
  '/assets/ice-frame.webp',
  '/assets/ice-card.webp',
  '/assets/icon-192.png',
  '/assets/icon-512.png',
  '/assets/icon-180.png',
  '/assets/favicon.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) =>
      cache.addAll(SHELL).catch(() => {
        // Don't fail install if a single asset 404s — gives a softer error.
      })
    )
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(names.filter((n) => n !== CACHE).map((n) => caches.delete(n)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  // Only intercept same-origin requests; let API + CDN go straight to network.
  if (url.origin !== self.location.origin) return;
  // Network-first for HTML so users see fresh content; fall back to cache offline.
  // ignoreSearch on the fallback so /?utm=... still matches the cached /.
  if (req.mode === 'navigate' || req.destination === 'document') {
    event.respondWith(
      fetch(req)
        .then((res) => {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy));
          return res;
        })
        .catch(() => caches.match(req, { ignoreSearch: true }).then((cached) =>
          cached || caches.match('/', { ignoreSearch: true })))
    );
    return;
  }
  // wos69: NETWORK-FIRST for static assets (CSS, JS, images). Previously
  // cache-first, which meant a returning PWA kept serving the OLD /style.css
  // and /app.js for a new ?v=... — users got stuck on a stale build until
  // they cleared data. Now: try the network, refresh the cache, and only
  // fall back to the cache when offline. Keeps offline support without
  // trapping users on old code.
  event.respondWith(
    fetch(req)
      .then((res) => {
        if (res.ok && res.type === 'basic') {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy));
        }
        return res;
      })
      .catch(() => caches.match(req, { ignoreSearch: true }))
  );
});
