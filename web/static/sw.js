self.addEventListener("push", (event) => {
  let payload = {
    title: "Countersign",
    body: "Open Countersign to review.",
    url: "/",
    tag: "countersign",
  };
  if (event.data) {
    try {
      const parsed = event.data.json();
      if (parsed && typeof parsed === "object") {
        payload = {
          ...payload,
          ...parsed,
        };
      }
    } catch {
      const text = event.data.text();
      if (text) {
        payload.body = text;
      }
    }
  }
  event.waitUntil(
    self.registration.showNotification(payload.title, {
      body: payload.body,
      icon: "/icon.svg",
      badge: "/icon.svg",
      tag: payload.tag,
      renotify: true,
      data: {
        url: payload.url || "/",
      },
    }),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const target = (event.notification.data && event.notification.data.url) || "/";
  const targetUrl = new URL(target, self.location.origin).href;
  event.waitUntil(
    self.clients
      .matchAll({
        type: "window",
        includeUncontrolled: true,
      })
      .then((clients) => {
        for (const client of clients) {
          if (client.url === targetUrl && "focus" in client) {
            return client.focus();
          }
        }
        if (self.clients.openWindow) {
          return self.clients.openWindow(targetUrl);
        }
        return undefined;
      }),
  );
});
