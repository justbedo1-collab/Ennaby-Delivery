const CACHE_NAME = 'ennaby-cache-v32-prod';
const urlsToCache = [
  '/',
  '/index.html',
  '/manifest.json'
];

// تثبيت ملفات الكاش الأساسية
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(urlsToCache))
  );
});

// التعامل مع الطلبات وقت تشغيل التطبيق
self.addEventListener('fetch', event => {
  // لا تقم بتخزين طلبات الـ API (البيانات الحية) في الكاش أبداً
  if (event.request.url.includes('/api/')) {
    return;
  }
  event.respondWith(
    caches.match(event.request).then(response => {
      return response || fetch(event.request);
    })
  );
});