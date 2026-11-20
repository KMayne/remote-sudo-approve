// Service worker: shows approval notifications and opens the page on tap.
// The push payload comes from the untrusted relay, so it's only ever text in
// a notification, and the URL it opens must be this page with an id.

const ID = /^[A-Za-z0-9_-]{22}$/;

self.addEventListener("push", (event) => {
  let p = {};
  try {
    p = event.data.json();
  } catch {}
  const id = typeof p.tag === "string" && ID.test(p.tag) ? p.tag : null;
  const title = typeof p.title === "string" ? p.title.slice(0, 80) : "sudo request";
  const body = typeof p.body === "string" ? p.body.slice(0, 200) : "";
  event.waitUntil(
    self.registration.showNotification(title, {
      body: body + "\n(Check the details on the page before approving.)",
      tag: id || undefined,
      data: { id },
      requireInteraction: true,
    }),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const id = event.notification.data && event.notification.data.id;
  const url = new URL("./", self.registration.scope);
  if (id && ID.test(id)) url.hash = id;
  event.waitUntil(self.clients.openWindow(url.href));
});
