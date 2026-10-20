// Offline-Cache für die App-Dateien (die Daten kommen live aus Supabase)
const CACHE = 'teamkalender-v9';
const FILES = ['./', 'index.html', 'manifest.webmanifest', 'apple-touch-icon.png', 'icon-192.png', 'icon-512.png',
               'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2'];
self.addEventListener('install', e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(FILES)).catch(() => {})); self.skipWaiting(); });
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(k => Promise.all(k.filter(x => x !== CACHE).map(x => caches.delete(x)))));
  self.clients.claim();
});
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  const appFile = url.origin === location.origin || url.hostname === 'cdn.jsdelivr.net';
  if (e.request.method !== 'GET' || !appFile) return;          // Supabase-Anfragen nie cachen
  e.respondWith(fetch(e.request)
    .then(r => { const copy = r.clone(); caches.open(CACHE).then(c => c.put(e.request, copy)); return r; })
    .catch(() => caches.match(e.request).then(r => r || caches.match('index.html'))));
});
