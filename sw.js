// Service worker: guarda la página para que funcione sin conexión y se pueda instalar como
// una app. Todo se pide primero a la red, así que los cambios llegan solos; la caché es
// solo para cuando no hay conexión. Si se añade un archivo, hay que meterlo en FILES (una
// prueba lo comprueba).
const VERSION = "phish-lens-v1";
const FILES = [
  "./",
  "index.html",
  "css/style.css",
  "js/analyze.js",
  "js/app.js",
  "js/domains.js",
  "js/links.js",
  "js/mail.js",
  "manifest.webmanifest",
  "icons/icon.svg",
  "icons/icon-192.png",
  "icons/icon-512.png",
  "samples/correos-paquete.eml",
  "samples/dgt-multa.eml",
  "samples/factura-adjunto.eml",
  "samples/fraude-ceo.eml",
  "samples/pedido-legitimo.eml",
  "samples/seg-social-catala.eml",
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(VERSION).then((cache) => cache.addAll(FILES)));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k)))),
  );
  self.clients.claim();
});

// Primero la red (para tener siempre la última versión) y, si no hay, lo guardado.
self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET" || new URL(event.request.url).origin !== location.origin) return;
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        const copy = response.clone();
        caches.open(VERSION).then((cache) => cache.put(event.request, copy));
        return response;
      })
      .catch(() => caches.match(event.request, { ignoreSearch: true })),
  );
});
