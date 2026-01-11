// Divine Node PWA Service Worker
// Version 1.0.0
// Provides offline support, caching, and background capabilities

const CACHE_NAME = 'divine-node-v1.0.0';
const RUNTIME_CACHE = 'divine-node-runtime';

// Files to cache immediately on install
const STATIC_CACHE_URLS = [
  '/pkn.html',
  '/css/main.css',
  '/css/multi_agent.css',
  '/css/osint.css',
  '/js/main.js',
  '/js/chat.js',
  '/js/multi_agent_ui.js',
  '/js/agent_quality.js',
  '/js/autocomplete.js',
  '/js/images.js',
  '/js/settings.js',
  '/js/storage.js',
  '/js/utils.js',
  '/js/models.js',
  '/js/files.js',
  '/js/projects.js',
  '/manifest.json'
];

// Install event - cache static assets
self.addEventListener('install', (event) => {
  console.log('[Service Worker] Installing...');

  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('[Service Worker] Caching static assets');
        return cache.addAll(STATIC_CACHE_URLS.map(url => new Request(url, { cache: 'reload' })));
      })
      .then(() => {
        console.log('[Service Worker] Installation complete');
        return self.skipWaiting(); // Activate immediately
      })
      .catch((error) => {
        console.error('[Service Worker] Installation failed:', error);
      })
  );
});

// Activate event - cleanup old caches
self.addEventListener('activate', (event) => {
  console.log('[Service Worker] Activating...');

  event.waitUntil(
    caches.keys()
      .then((cacheNames) => {
        return Promise.all(
          cacheNames
            .filter((cacheName) => {
              // Delete old caches
              return cacheName !== CACHE_NAME && cacheName !== RUNTIME_CACHE;
            })
            .map((cacheName) => {
              console.log('[Service Worker] Deleting old cache:', cacheName);
              return caches.delete(cacheName);
            })
        );
      })
      .then(() => {
        console.log('[Service Worker] Activation complete');
        return self.clients.claim(); // Take control immediately
      })
  );
});

// Fetch event - serve from cache, fallback to network
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET requests
  if (request.method !== 'GET') {
    return;
  }

  // Skip API calls (always go to network for fresh data)
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(
      fetch(request)
        .catch(() => {
          // Return offline message for API calls
          return new Response(
            JSON.stringify({
              error: 'Offline',
              message: 'No network connection. Please check your connection and try again.'
            }),
            {
              headers: { 'Content-Type': 'application/json' },
              status: 503
            }
          );
        })
    );
    return;
  }

  // Cache-first strategy for static assets
  event.respondWith(
    caches.match(request)
      .then((cachedResponse) => {
        if (cachedResponse) {
          console.log('[Service Worker] Serving from cache:', request.url);
          return cachedResponse;
        }

        // Not in cache, fetch from network
        console.log('[Service Worker] Fetching from network:', request.url);
        return fetch(request)
          .then((response) => {
            // Don't cache non-successful responses
            if (!response || response.status !== 200 || response.type === 'error') {
              return response;
            }

            // Clone response (can only use response body once)
            const responseToCache = response.clone();

            // Cache the fetched resource for future use
            caches.open(RUNTIME_CACHE)
              .then((cache) => {
                cache.put(request, responseToCache);
              });

            return response;
          })
          .catch((error) => {
            console.error('[Service Worker] Fetch failed:', error);

            // Return offline page for HTML requests
            if (request.headers.get('accept').includes('text/html')) {
              return caches.match('/pkn.html');
            }

            return new Response('Offline', { status: 503 });
          });
      })
  );
});

// Background sync for offline actions (future enhancement)
self.addEventListener('sync', (event) => {
  console.log('[Service Worker] Background sync:', event.tag);

  if (event.tag === 'sync-messages') {
    event.waitUntil(
      // Future: sync offline messages when back online
      Promise.resolve()
    );
  }
});

// Push notifications (future enhancement)
self.addEventListener('push', (event) => {
  console.log('[Service Worker] Push notification received');

  const options = {
    body: event.data ? event.data.text() : 'New update available',
    icon: '/img/icon-192.png',
    badge: '/img/icon-192.png',
    vibrate: [200, 100, 200],
    tag: 'divine-node-notification'
  };

  event.waitUntil(
    self.registration.showNotification('Divine Node', options)
  );
});

// Message handler for client communication
self.addEventListener('message', (event) => {
  console.log('[Service Worker] Message received:', event.data);

  if (event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }

  if (event.data.type === 'CACHE_URLS') {
    event.waitUntil(
      caches.open(RUNTIME_CACHE)
        .then((cache) => cache.addAll(event.data.urls))
    );
  }

  if (event.data.type === 'CLEAR_CACHE') {
    event.waitUntil(
      caches.keys()
        .then((cacheNames) => Promise.all(
          cacheNames.map((cacheName) => caches.delete(cacheName))
        ))
        .then(() => {
          event.ports[0].postMessage({ success: true });
        })
    );
  }
});

console.log('[Service Worker] Script loaded');
