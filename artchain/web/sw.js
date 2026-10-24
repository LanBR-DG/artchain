/* ArtChain Service Worker：应用外壳缓存 + 接口永远走网络。
 *
 * 缓存策略刻意分两条：
 *   /api/*        绝不缓存——链上数据必须实时，缓存出旧状态比断网更糟。
 *   页面（导航）    网络优先，失败才回退缓存外壳（离线时仍能打开 App 看到提示）。
 *   静态资源       缓存优先（图标等几乎不变的文件）。
 * 版本号写死在这里：发布新版本时递增 VERSION，旧缓存会被 activate 清掉。
 */
const VERSION = "artchain-shell-v2";
const SHELL = [
  "/",
  "/manifest.webmanifest",
  "/icons/icon-192.png",
  "/icons/icon-512.png",
  "/icons/icon-maskable-512.png",
];

self.addEventListener("install", event => {
  event.waitUntil(
    caches.open(VERSION)
      .then(cache => cache.addAll(SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== VERSION).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", event => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin || event.request.method !== "GET") return;

  if (url.pathname.startsWith("/api/")) return;   // 接口直连网络

  if (event.request.mode === "navigate") {
    event.respondWith(
      fetch(event.request)
        .then(resp => {
          const copy = resp.clone();
          caches.open(VERSION).then(cache => cache.put("/", copy));
          return resp;
        })
        .catch(() => caches.match("/"))
    );
    return;
  }

  event.respondWith(
    caches.match(event.request).then(hit =>
      hit || fetch(event.request).then(resp => {
        const copy = resp.clone();
        caches.open(VERSION).then(cache => cache.put(event.request, copy));
        return resp;
      })
    )
  );
});
