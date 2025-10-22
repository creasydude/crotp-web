const VERSION = 'v3';
const APP_CACHE = `crotp-app-${VERSION}`;
const RUNTIME_CACHE = `crotp-runtime-${VERSION}`;

const PRECACHE_URLS = [
  '/index.html',
  '/manifest.webmanifest',
  '/vite.svg',
];

// Install: pre-cache app shell
self.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      try {
        const cache = await caches.open(APP_CACHE);
        await Promise.all(
          PRECACHE_URLS.map((u) => cache.add(u).catch(() => undefined))
        );
      } finally {
        await self.skipWaiting();
      }
    })()
  );
});

// Activate: clean old caches and claim clients
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((k) => k !== APP_CACHE && k !== RUNTIME_CACHE)
            .map((k) => caches.delete(k))
        )
      )
      .then(() => self.clients.claim())
  );
});

function isNavigation(request) {
  return request.mode === 'navigate';
}

// Fetch: cache-first for assets; navigation fallback to cached index
self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // Only handle same-origin requests
  if (url.origin !== location.origin) {
    return;
  }

  // Navigation: network-first, fallback to cached index.html
  if (isNavigation(req)) {
    event.respondWith(
      (async () => {
        try {
          const net = await fetch(req, { cache: 'no-store' });
          if (net && net.ok) {
            caches.open(APP_CACHE).then((cache) => cache.put('/index.html', net.clone()));
            return net;
          }
        } catch {}
        const cached = await caches.match('/index.html');
        if (cached) return cached;
        try {
          const netIndex = await fetch('/index.html', { cache: 'no-store' });
          if (netIndex && netIndex.ok) {
            caches.open(APP_CACHE).then((cache) => cache.put('/index.html', netIndex.clone()));
          }
          return netIndex;
        } catch {}
        return new Response('', { status: 503 });
      })()
    );
    return;
  }

  // Cache-first for versioned static assets
  if (
    url.pathname.startsWith('/assets/') ||
    url.pathname.endsWith('.js') ||
    url.pathname.endsWith('.css') ||
    url.pathname.endsWith('.svg') ||
    url.pathname.endsWith('.png') ||
    url.pathname.endsWith('.ico')
  ) {
    event.respondWith(
      caches.match(req).then((resp) => {
        if (resp) return resp;
        return caches.open(RUNTIME_CACHE).then((cache) =>
          fetch(req, { cache: 'no-store' })
            .then((net) => {
              if (net.ok) cache.put(req, net.clone());
              return net;
            })
            // Do NOT fall back to index.html for asset requests; return 503 for offline/mismatch
            .catch(() => new Response('', { status: 503 }))
        );
      })
    );
    return;
  }

  // Fallback: cache or network
  event.respondWith(
    caches.match(req).then((resp) => resp || fetch(req).catch(() => new Response('', { status: 503 })))
  );
});