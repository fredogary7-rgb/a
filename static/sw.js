self.addEventListener("install", event => {
  event.waitUntil(
    caches.open("lumina-cache").then(cache => {
      return cache.addAll([
        "/",
        "/inscription",
        "/connexion"
      ]);
    })
  );
});

self.addEventListener("fetch", event => {
  event.respondWith(
    caches.match(event.request).then(response => {
      return response || fetch(event.request);
    })
  );
});
