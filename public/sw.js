const CACHE_NAME = 'ennaby-cache-v56';
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
      return cache.addAll(urlsToCache).catch(() => {});
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

  // عدم تخزين طلبات النطاقات الخارجية أو الـ API أو ملف المشغل الخلفي نفسه نهائياً
  if (
    event.request.method !== 'GET' ||
    reqUrl.origin !== self.location.origin ||
    reqUrl.pathname.startsWith('/api/') ||
    reqUrl.pathname === '/sw.js'
  ) {
    return;
  }

  // استراتيجية Network-First لصفحات HTML والمسارات الرئيسية لضمان ظهور أي تحديث فوراً
  if (
    event.request.mode === 'navigate' ||
    reqUrl.pathname.endsWith('.html') ||
    reqUrl.pathname === '/' ||
    reqUrl.pathname === '/admin' ||
    reqUrl.pathname === '/install'
  ) {
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

  // استراتيجية Cache-First للأيقونات والملفات الثابتة المحلية
  event.respondWith(
    caches.match(event.request).then(response => {
      return response || fetch(event.request);
    })
  );
});

// استقبال وتشغيل إشعارات الـ Web Push على هواتف أندرويد و iOS
self.addEventListener('push', function(event) {
  let data = {
    title: 'الرجل العنابي 🛵',
    body: 'تحديث جديد في طلبك!',
    url: '/'
  };

  if (event.data) {
    try {
      const parsed = event.data.json();
      if (parsed && typeof parsed === 'object') {
        data = { ...data, ...parsed };
      }
    } catch (e) {
      try {
        const rawText = event.data.text();
        if (rawText) data.body = rawText;
      } catch (err) {}
    }
  }

  const title = data.title || 'الرجل العنابي 🛵';
  const options = {
    body: data.body || 'تحديث جديد من منصة الرجل العنابي 🛵',
    icon: '/icon-192.png',
    badge: '/icon-192.png',
    dir: 'rtl',
    lang: 'ar',
    vibrate: [220, 100, 220, 100, 320],
    tag: data.tag || ('ennaby-push-' + Date.now()),
    renotify: true,
    requireInteraction: false,
    data: { url: data.url || '/' }
  };

event.waitUntil(
    Promise.all([
      self.registration.showNotification(title, options),
      self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(clientList) {
        clientList.forEach(function(client) {
          client.postMessage({
            type: 'ENNABY_PUSH_RECEIVED',
            title: title,
            body: options.body,
            url: options.data.url
          });
        });
      }).catch(function() {})
    ])
  );
});

self.addEventListener('notificationclick', function(event) {
  event.notification.close();
  const targetUrl = (event.notification && event.notification.data && event.notification.data.url)
    ? event.notification.data.url
    : '/';

  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(clientList) {
      for (let i = 0; i < clientList.length; i++) {
        const client = clientList[i];
        if (client && 'focus' in client) {
          return client.focus();
        }
      }
      if (self.clients.openWindow) {
        return self.clients.openWindow(targetUrl);
      }
    })
  );
});