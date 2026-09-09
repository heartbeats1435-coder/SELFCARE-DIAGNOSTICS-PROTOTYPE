/**
 * Selfcare Diagnostics - Service Worker (PWA Core)
 * File: service-worker.js
 * Version: 1.3.0
 * Provides offline shell caching, stale-while-revalidate for static assets,
 * network-only for sensitive patient APIs, and push notifications.
 */

const CACHE_VERSION = 'v1.3.0';
const STATIC_CACHE = `selfcare-static-${CACHE_VERSION}`;
const DYNAMIC_CACHE = `selfcare-dynamic-${CACHE_VERSION}`;

// Core Shell Assets for Offline Support
const STATIC_ASSETS = [
  './',
  './index.html',
  './customer.html',
  './login.html',
  './tests.html',
  './packages.html',
  './cart.html',
  './checkout.html',
  './reports.html',
  './profile.html',
  './admin.html',
  './technician.html',
  './manifest.json',

  // CSS Stylesheets
  './assets/css/global.css',
  './assets/css/components.css',
  './assets/css/login.css',
  './assets/css/customer.css',
  './assets/css/tests.css',
  './assets/css/packages.css',
  './assets/css/reports.css',
  './assets/css/profile.css',
  './assets/css/checkout.css',
  './assets/css/admin.css',
  './assets/css/technician.css',

  // Core JavaScript
  './assets/js/config.js',
  './assets/js/utils.js',
  './assets/js/api.js',
  './assets/js/auth.js',
  './assets/js/app.js'
];

// URLs/Actions containing sensitive customer health data that MUST NEVER be cached
const SENSITIVE_PATTERNS = [
  '/reports',
  '/bookings',
  '/patients',
  '/profile',
  'auth_',
  'action=reports',
  'action=bookings',
  'action=auth',
  'action=user',
  'ai_analyze'
];

function isSensitiveRequest(urlStr) {
  return SENSITIVE_PATTERNS.some((pattern) => urlStr.includes(pattern));
}

// Install Event: Pre-cache App Shell Core Assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(STATIC_CACHE)
      .then((cache) => cache.addAll(STATIC_ASSETS))
      .then(() => self.skipWaiting())
  );
});

// Activate Event: Clear Legacy & Outdated Caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => {
        return Promise.all(
          keys.map((key) => {
            if (key !== STATIC_CACHE && key !== DYNAMIC_CACHE) {
              return caches.delete(key);
            }
          })
        );
      })
      .then(() => self.clients.claim())
  );
});

// Fetch Event Interception
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Ignore non-GET requests and Chrome Extensions
  if (request.method !== 'GET' || url.protocol.startsWith('chrome-extension')) {
    return;
  }

  // Strategy 1: Sensitive Data & Apps Script Dynamic Endpoints -> Strictly Network-Only
  if (isSensitiveRequest(url.href) || url.hostname.includes('script.google.com')) {
    event.respondWith(
      fetch(request).catch(() => {
        return new Response(
          JSON.stringify({
            success: false,
            message: 'You are offline. Please reconnect to access live diagnostic records.'
          }),
          {
            status: 503,
            statusText: 'Service Unavailable',
            headers: { 'Content-Type': 'application/json; charset=utf-8' }
          }
        );
      })
    );
    return;
  }

  // Strategy 2: Static Assets & CSS/JS -> Stale-While-Revalidate
  if (STATIC_ASSETS.includes(url.pathname) || url.pathname.includes('/assets/')) {
    event.respondWith(
      caches.match(request).then((cachedResponse) => {
        const fetchPromise = fetch(request)
          .then((networkResponse) => {
            if (networkResponse && networkResponse.status === 200) {
              const clone = networkResponse.clone();
              caches.open(STATIC_CACHE).then((cache) => cache.put(request, clone));
            }
            return networkResponse;
          })
          .catch(() => {
            // Offline background sync silence
          });

        return cachedResponse || fetchPromise;
      })
    );
    return;
  }

  // Strategy 3: HTML Navigations -> Network-First with Offline Fallback
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request)
        .then((networkResponse) => {
          if (networkResponse && networkResponse.status === 200) {
            const clone = networkResponse.clone();
            caches.open(DYNAMIC_CACHE).then((cache) => cache.put(request, clone));
          }
          return networkResponse;
        })
        .catch(async () => {
          const cachedPage = await caches.match(request);
          if (cachedPage) return cachedPage;

          const fallbackShell = await caches.match('./customer.html') || await caches.match('./index.html');
          if (fallbackShell) return fallbackShell;

          return new Response('You are offline. Diagnostic services will reconnect when online.', {
            status: 503,
            statusText: 'Service Unavailable',
            headers: { 'Content-Type': 'text/plain; charset=utf-8' }
          });
        })
    );
    return;
  }

  // Fallback default
  event.respondWith(
    caches.match(request).then((cached) => cached || fetch(request))
  );
});

// Push Notification Listener
self.addEventListener('push', (event) => {
  let data = {
    title: 'Selfcare Diagnostics',
    body: 'You have a new update regarding your lab test report or booking status.',
    url: './reports.html'
  };

  if (event.data) {
    try {
      data = event.data.json();
    } catch (e) {
      data.body = event.data.text();
    }
  }

  const options = {
    body: data.body,
    icon: 'assets/images/logo.png',
    badge: 'assets/images/logo.png',
    vibrate: [100, 50, 100],
    data: {
      url: data.url || './reports.html'
    }
  };

  event.waitUntil(self.registration.showNotification(data.title, options));
});

// Notification Click Handler
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const targetUrl = (event.notification.data && event.notification.data.url) || './customer.html';

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if (client.url.includes(targetUrl) && 'focus' in client) {
          return client.focus();
        }
      }
      if (clients.openWindow) {
        return clients.openWindow(targetUrl);
      }
    })
  );
});
