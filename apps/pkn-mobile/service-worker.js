/**
 * Divine Node Service Worker
 * Version: 2.0.1 - Increment this to force cache refresh
 */

const CACHE_VERSION = 'v2.0.1';
const CACHE_NAME = `divine-node-${CACHE_VERSION}`;

// Files to cache (core app files)
const STATIC_ASSETS = [
    '/pkn.html',
    '/manifest.json',
    '/css/main.css',
    '/css/mobile.css',
    '/css/file-explorer.css',
    '/css/osint.css',
    '/js/debugger.js',
    '/js/pkn.js',
    '/js/core/app.js',
    '/js/core/main.js',
    '/js/core/event-bus.js',
    '/config.js',
    '/tools.js',
    '/img/icchat.png'
];

// Install event - cache static assets
self.addEventListener('install', (event) => {
    console.log('[SW] Installing version:', CACHE_VERSION);
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => {
                console.log('[SW] Caching static assets');
                return cache.addAll(STATIC_ASSETS);
            })
            .then(() => {
                // Force activation immediately
                return self.skipWaiting();
            })
            .catch((err) => {
                console.error('[SW] Cache failed:', err);
            })
    );
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
    console.log('[SW] Activating version:', CACHE_VERSION);
    event.waitUntil(
        caches.keys()
            .then((cacheNames) => {
                return Promise.all(
                    cacheNames
                        .filter((name) => name.startsWith('divine-node-') && name !== CACHE_NAME)
                        .map((name) => {
                            console.log('[SW] Deleting old cache:', name);
                            return caches.delete(name);
                        })
                );
            })
            .then(() => {
                // Take control of all pages immediately
                return self.clients.claim();
            })
    );
});

// Fetch event - network first, then cache
self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);

    // Skip non-GET requests
    if (event.request.method !== 'GET') {
        return;
    }

    // Skip API calls - always go to network
    if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/health')) {
        return;
    }

    // Skip external resources
    if (url.origin !== location.origin) {
        return;
    }

    // Network first strategy for HTML and JS (get fresh content)
    if (url.pathname.endsWith('.html') || url.pathname.endsWith('.js')) {
        event.respondWith(
            fetch(event.request)
                .then((response) => {
                    // Clone and cache the response
                    const responseClone = response.clone();
                    caches.open(CACHE_NAME).then((cache) => {
                        cache.put(event.request, responseClone);
                    });
                    return response;
                })
                .catch(() => {
                    // Fallback to cache if network fails
                    return caches.match(event.request);
                })
        );
        return;
    }

    // Cache first for CSS, images, fonts
    event.respondWith(
        caches.match(event.request)
            .then((cachedResponse) => {
                if (cachedResponse) {
                    return cachedResponse;
                }
                return fetch(event.request)
                    .then((response) => {
                        const responseClone = response.clone();
                        caches.open(CACHE_NAME).then((cache) => {
                            cache.put(event.request, responseClone);
                        });
                        return response;
                    });
            })
    );
});

// Message handler for manual cache clear
self.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'CLEAR_CACHE') {
        console.log('[SW] Manual cache clear requested');
        caches.keys().then((cacheNames) => {
            return Promise.all(
                cacheNames.map((name) => caches.delete(name))
            );
        }).then(() => {
            console.log('[SW] All caches cleared');
            event.ports[0].postMessage({ status: 'cleared' });
        });
    }

    if (event.data && event.data.type === 'SKIP_WAITING') {
        self.skipWaiting();
    }
});
