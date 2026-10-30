const CACHE_NAME = 'ennaby-cache-v36';
const urlsToCache = [
  '/',
  '/index.html',
  '/icon-192.png',
  '/icon-512.png',
  '/manifest.json'
];

self.addEventListener('install', event => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return cache.addAll(urlsToCache);
    })
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.map(key => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      )
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  const reqUrl = new URL(event.request.url);

  // عدم تخزين طلبات الـ API أو طلبات POST نهائياً لضمان المزامنة اللحظية
  if (event.request.method !== 'GET' || reqUrl.pathname.startsWith('/api/')) {
    return;
  }

  // استراتيجية Network-First لصفحات HTML لضمان ظهور أي تحديث فوراً
  if (event.request.mode === 'navigate' || reqUrl.pathname.endsWith('.html') || reqUrl.pathname === '/') {
    event.respondWith(
      fetch(event.request)
        .then(networkRes => {
          const resClone = networkRes.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, resClone));
          return networkRes;
        })
        .catch(() => caches.match(event.request))
    );
    return;
  }

  // استراتيجية Cache-First للأيقونات والملفات الثابتة لتوفير الاستهلاك
  event.respondWith(
    caches.match(event.request).then(response => {
      return response || fetch(event.request);
    })
  );
});

// استقبال وتشغيل إشعارات الـ Web Push
self.addEventListener('push', function(event) {
  let data = { title: 'الرجل العنابي 🛵', body: 'تحديث جديد في طلبك!', url: '/' };
  try {
    if (event.data) {
      data = event.data.json();
    }
  } catch (e) {
    console.error('Push data parsing error:', e);
  }

  const options = {
    body: data.body,
    icon: '/icon-192.png',
    badge: '/icon-192.png',
    dir: 'rtl',
    lang: 'ar',
    vibrate: [200, 100, 200, 100, 300], // اهتزاز مميز
    data: { url: data.url || '/' }
  };

  event.waitUntil(
    self.registration.showNotification(data.title, options)
  );
});

self.addEventListener('notificationclick', function(event) {
  event.notification.close();
  event.waitUntil(
    clients.openWindow(event.notification.data.url || '/')
  );
});