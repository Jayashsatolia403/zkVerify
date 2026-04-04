const STATIC_CACHE = 'zkverify-static-v4';
const PRECACHE_PATHS = [
  '/build/aadhaar-age-verifier_js/aadhaar-age-verifier.wasm',
  '/vendor/snarkjs/snarkjs.min.js',
  '/vendor/pako/pako.min.js',
  '/prover.worker.js',
];

const CACHEABLE_PATHS = [...PRECACHE_PATHS];

function canCacheResponse(request, response) {
  return (
    request.method === 'GET' &&
    response &&
    response.status === 200 &&
    (response.type === 'basic' || response.type === 'default')
  );
}

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE).then((cache) => cache.addAll(PRECACHE_PATHS)).catch(() => undefined)
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((key) => key !== STATIC_CACHE).map((key) => caches.delete(key)))
    )
  );
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;

  const requestUrl = new URL(event.request.url);
  if (requestUrl.origin !== self.location.origin) return;

  if (!CACHEABLE_PATHS.includes(requestUrl.pathname)) return;

  event.respondWith(
    caches.match(event.request).then((cached) => {
      if (cached) return cached;
      return fetch(event.request).then((response) => {
        if (!canCacheResponse(event.request, response)) return response;
        const copy = response.clone();

        event.waitUntil(
          caches
            .open(STATIC_CACHE)
            .then((cache) => cache.put(event.request, copy))
            .catch((error) => {
              // Quota/internal cache failures should not break responses.
              console.warn('SW cache put skipped:', requestUrl.pathname, error?.message || error);
            })
        );

        return response;
      });
    })
  );
});

