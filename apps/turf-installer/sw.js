/* TurfPro service worker — offline-first app shell.
 * Bump CACHE on every release so stale assets are evicted.
 * version.json is always network-first so the version label stays honest.
 */
const CACHE = 'turfpro-v4';
// Relative to the SW's own location so the app works when hosted from a
// subdirectory (e.g. /apps/turf-installer/) as well as from the site root.
const SHELL = [
  './',
  './index.html',
  './style.css',
  './app.js',
  './manifest.webmanifest',
  './assets/icon.svg',
  './assets/icon-180.png',
  './assets/icon-192.png',
  './assets/icon-512.png',
];

self.addEventListener('install', (event) => {
  // No .catch() here on purpose: addAll is atomic, and swallowing a failure
  // would install a SW with an empty cache while activate deletes the old
  // working one — permanently broken offline until the next release. Failing
  // install keeps the previous SW+cache live and retries on the next visit.
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(SHELL)));
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
  if (url.origin !== self.location.origin) return;

  // version.json: never cache.
  if (url.pathname.endsWith('/version.json')) {
    event.respondWith(fetch(req).catch(() => new Response('{}', {
      headers: { 'Content-Type': 'application/json' },
    })));
    return;
  }

  // Network-first, cache fallback — keeps the app fresh but works offline.
  event.respondWith(
    fetch(req)
      .then((res) => {
        if (res && res.ok && res.type === 'basic') {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy));
        }
        return res;
      })
      .catch(() =>
        caches.match(req, { ignoreSearch: true }).then((cached) =>
          // Only navigations fall back to the HTML shell. Serving index.html
          // as the body of a missed asset/JSON request would hand callers a
          // 200 full of HTML instead of letting their .catch() run.
          cached || (req.mode === 'navigate'
            ? caches.match('./', { ignoreSearch: true })
            : undefined)
        )
      )
  );
});
