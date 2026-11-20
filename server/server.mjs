// remote-sudo-approve server: one process, one address. It serves the approval
// page (static files) and the relay API under /v1/.
//
// The relay part is untrusted by design (DESIGN.md): it never sees a
// decision, only opaque requests and assertions that the machines verify
// themselves. It keeps pending requests and sends the web push.
//
// The page part is what must not be tampered with. Two things keep the API
// from becoming a way to do that:
//   - the page's files are a fixed list, read once at startup, and served
//     only at their exact paths;
//   - every /v1/ response is JSON or empty, with nosniff and a CSP of
//     default-src 'none', so nothing the agent sends can run as a page on
//     this origin.
//
// API (DESIGN.md "Approval"):
//   POST /v1/requests                          machine (bearer), body: request JSON
//   GET  /v1/requests/:id/assertions?from&wait machine (bearer), long-poll
//   DELETE /v1/requests/:id                    machine (bearer): decided, withdraw
//   GET  /v1/requests/:id                      page: the request text
//   POST /v1/requests/:id/assertions           page: an assertion
//   GET  /v1/vapid-public-key                  page
//   POST /v1/subscriptions                     page (bearer setup token)
//
// Config (environment):
//   PORT               default 8080
//   ORIGIN             this server's public origin, e.g. https://approve.example.ts.net
//   PAGE_DIR           the static files (page/ and register/ of the repo)
//   VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY   web-push keys
//   HOST_TOKENS_FILE   JSON {"<host>": "<sha256 hex of its token>"}
//   SETUP_TOKEN_SHA256 sha256 hex of the token that allows subscribing
//   SUBSCRIPTIONS_FILE where push subscriptions are kept

import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import webpush from "web-push";

const env = (k) => {
  const v = process.env[k];
  if (!v) throw new Error(`${k} is not set`);
  return v;
};

const PORT = Number(process.env.PORT || 8080);
const ORIGIN = env("ORIGIN");
const PAGE_DIR = env("PAGE_DIR");
const HOST_TOKENS = JSON.parse(fs.readFileSync(env("HOST_TOKENS_FILE"), "utf8"));
const SETUP_TOKEN_SHA256 = env("SETUP_TOKEN_SHA256");
const SUBSCRIPTIONS_FILE = env("SUBSCRIPTIONS_FILE");
const VAPID_PUBLIC_KEY = env("VAPID_PUBLIC_KEY");
webpush.setVapidDetails(ORIGIN, VAPID_PUBLIC_KEY, env("VAPID_PRIVATE_KEY"));

const ID = /^[A-Za-z0-9_-]{22}$/;
const MAX_REQUEST = 64 * 1024;
const MAX_ASSERTION = 16 * 1024;
const MAX_ASSERTIONS = 64;
const MAX_LIFETIME = 300; // seconds a request may ask to live
const MAX_PENDING_PER_HOST = 3;
const MAX_PER_HOST_PER_HOUR = 120;
const PUSH_HOSTS = [/^fcm\.googleapis\.com$/, /^[a-z0-9-]+\.push\.apple\.com$/, /^updates\.push\.services\.mozilla\.com$/, /^[a-z0-9-]+\.notify\.windows\.com$/];

/** id -> {raw, host, expires, assertions: [], waiters: Set<fn>} */
const pending = new Map();
/** host -> [timestamps] */
const recent = new Map();

let subscriptions = [];
try {
  subscriptions = JSON.parse(fs.readFileSync(SUBSCRIPTIONS_FILE, "utf8"));
} catch {
  subscriptions = [];
}
const saveSubscriptions = () => {
  fs.writeFileSync(SUBSCRIPTIONS_FILE + ".tmp", JSON.stringify(subscriptions));
  fs.renameSync(SUBSCRIPTIONS_FILE + ".tmp", SUBSCRIPTIONS_FILE);
};

const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");
const sameHex = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));

/** The host a bearer token belongs to, or null. */
function hostFor(req) {
  const m = /^Bearer ([A-Za-z0-9_-]{20,200})$/.exec(req.headers.authorization || "");
  if (!m) return null;
  const h = sha256(m[1]);
  for (const [host, want] of Object.entries(HOST_TOKENS)) {
    if (typeof want === "string" && sameHex(h, want)) return host;
  }
  return null;
}

function send(res, status, body, extra = {}) {
  const headers = {
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    ...extra,
  };
  if (body === undefined) {
    res.writeHead(status, headers);
    res.end();
  } else {
    const text = typeof body === "string" ? body : JSON.stringify(body);
    res.writeHead(status, { "Content-Type": "application/json", ...headers });
    res.end(text);
  }
}

// The page: a fixed list of files, read once.
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".json": "application/manifest+json" };
const PAGES = new Map(
  [
    ["/", "index.html"],
    ["/app.js", "app.js"],
    ["/canonical.js", "canonical.js"],
    ["/sw.js", "sw.js"],
    ["/style.css", "style.css"],
    ["/manifest.json", "manifest.json"],
    ["/register/", "register/index.html"],
    ["/register/register.js", "register/register.js"],
    ["/register/style.css", "register/style.css"],
  ].map(([url, file]) => [url, { body: fs.readFileSync(path.join(PAGE_DIR, file)), type: TYPES[path.extname(file)] }]),
);
// What a <meta> CSP can't say: no framing, no opener, HTTPS only.
const PAGE_HEADERS = {
  "Content-Security-Policy": "frame-ancestors 'none'",
  "X-Frame-Options": "DENY",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Strict-Transport-Security": "max-age=63072000",
  "Cache-Control": "no-cache",
};

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) {
        reject(new Error("too large"));
        req.destroy();
      } else chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function rateLimited(host) {
  const now = Date.now();
  const times = (recent.get(host) || []).filter((t) => now - t < 3600_000);
  recent.set(host, times);
  const live = [...pending.values()].filter((p) => p.host === host && p.expires > now / 1000).length;
  if (live >= MAX_PENDING_PER_HOST || times.length >= MAX_PER_HOST_PER_HOUR) return true;
  times.push(now);
  return false;
}

async function notify(entry, id) {
  let argv = "";
  try {
    argv = JSON.parse(entry.raw).argv.join(" ");
  } catch {}
  const snapshot = subscriptions.slice();
  const payload = JSON.stringify({
    title: `sudo on ${entry.host}`,
    body: argv.length > 120 ? argv.slice(0, 117) + "..." : argv,
    url: `${ORIGIN}/#${id}`,
    tag: id,
  });
  // All at once, each with a time limit; drop only endpoints the push
  // service says are gone, and never overwrite subscriptions added meanwhile.
  const results = await Promise.allSettled(
    snapshot.map((sub) => webpush.sendNotification(sub, payload, { TTL: MAX_LIFETIME, urgency: "high", timeout: 10_000 }).then(() => sub)),
  );
  const dead = new Set();
  results.forEach((r, i) => {
    if (r.status === "rejected") {
      const code = r.reason?.statusCode;
      console.error("push failed:", code ?? r.reason?.message);
      if (code === 404 || code === 410) dead.add(snapshot[i].endpoint);
    }
  });
  if (dead.size) {
    subscriptions = subscriptions.filter((x) => !dead.has(x.endpoint));
    saveSubscriptions();
  }
}

function expireOld() {
  const now = Date.now() / 1000;
  for (const [id, p] of pending) {
    if (now > p.expires + 60) {
      for (const w of p.waiters) w();
      pending.delete(id);
    }
  }
}
setInterval(expireOld, 10_000).unref();

const routes = [
  // Machine: a new request.
  ["POST", /^\/v1\/requests$/, async (req, res) => {
    const host = hostFor(req);
    if (!host) return send(res, 401, { error: "unauthorised" });
    let raw;
    try {
      raw = await readBody(req, MAX_REQUEST);
    } catch {
      return send(res, 413, { error: "too large" });
    }
    let r;
    try {
      r = JSON.parse(raw);
    } catch {
      return send(res, 400, { error: "not JSON" });
    }
    const now = Date.now() / 1000;
    if (!ID.test(r?.id) || r.host !== host || !Array.isArray(r.argv) ||
        typeof r.expires !== "number" || r.expires > now + MAX_LIFETIME || r.expires < now) {
      return send(res, 400, { error: "invalid request" });
    }
    if (pending.has(r.id)) return send(res, 409, { error: "duplicate id" });
    if (rateLimited(host)) return send(res, 429, { error: "too many requests" });
    const entry = { raw, host, expires: r.expires, assertions: [], waiters: new Set() };
    pending.set(r.id, entry);
    send(res, 201);
    notify(entry, r.id).catch((e) => console.error("notify:", e));
  }],

  // Machine: wait for assertions.
  ["GET", /^\/v1\/requests\/([A-Za-z0-9_-]{22})\/assertions$/, async (req, res, m, url) => {
    const host = hostFor(req);
    const p = pending.get(m[1]);
    if (!host || !p || p.host !== host) return send(res, 404, { error: "not found" });
    const from = Math.max(0, Math.min(MAX_ASSERTIONS, Number(url.searchParams.get("from")) || 0));
    const wait = Math.max(0, Math.min(30, Number(url.searchParams.get("wait")) || 0));
    const reply = () => send(res, 200, { assertions: p.assertions.slice(from), next: p.assertions.length });
    if (p.assertions.length > from || wait === 0) return reply();
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      clearTimeout(t);
      p.waiters.delete(finish);
      reply();
    };
    const t = setTimeout(finish, wait * 1000);
    p.waiters.add(finish);
    req.on("close", () => {
      done = true;
      clearTimeout(t);
      p.waiters.delete(finish);
    });
  }],

  // Machine: the request is decided (approved, denied or given up on).
  ["DELETE", /^\/v1\/requests\/([A-Za-z0-9_-]{22})$/, async (req, res, m) => {
    const host = hostFor(req);
    const p = pending.get(m[1]);
    if (!host || !p || p.host !== host) return send(res, 404, { error: "not found" });
    for (const w of [...p.waiters]) w();
    pending.delete(m[1]);
    send(res, 204);
  }],

  // Page: the request text, exactly as the machine sent it.
  ["GET", /^\/v1\/requests\/([A-Za-z0-9_-]{22})$/, async (req, res, m) => {
    const p = pending.get(m[1]);
    if (!p) return send(res, 404, { error: "not found" });
    send(res, 200, p.raw);
  }],

  // Page: an assertion. Unauthenticated: the machine checks it.
  ["POST", /^\/v1\/requests\/([A-Za-z0-9_-]{22})\/assertions$/, async (req, res, m) => {
    const p = pending.get(m[1]);
    if (!p) return send(res, 404, { error: "not found" });
    if (p.assertions.length >= MAX_ASSERTIONS) return send(res, 429, { error: "too many" });
    let a;
    try {
      a = JSON.parse(await readBody(req, MAX_ASSERTION));
    } catch {
      return send(res, 400, { error: "bad assertion" });
    }
    const fields = ["id", "authenticatorData", "clientDataJSON", "signature"];
    if (!fields.every((f) => typeof a?.[f] === "string" && /^[A-Za-z0-9_-]{1,8192}$/.test(a[f]))) {
      return send(res, 400, { error: "bad assertion" });
    }
    p.assertions.push(Object.fromEntries(fields.map((f) => [f, a[f]])));
    for (const w of [...p.waiters]) w();
    send(res, 202, undefined);
  }],

  ["GET", /^\/v1\/vapid-public-key$/, async (req, res) => send(res, 200, { key: VAPID_PUBLIC_KEY })],

  // Page: subscribe this device to pushes (needs the setup token).
  ["POST", /^\/v1\/subscriptions$/, async (req, res) => {
    const m = /^Bearer (\S{20,200})$/.exec(req.headers.authorization || "");
    if (!m || !sameHex(sha256(m[1]), SETUP_TOKEN_SHA256)) return send(res, 401, { error: "unauthorised" });
    let s;
    try {
      s = JSON.parse(await readBody(req, 4096));
    } catch {
      return send(res, 400, { error: "bad subscription" });
    }
    // Only real push services: the relay POSTs to this URL.
    let pushHost = "";
    try {
      const u = new URL(s?.endpoint);
      if (u.protocol === "https:" && !u.port && !u.username) pushHost = u.hostname;
    } catch {}
    if (!PUSH_HOSTS.some((re) => re.test(pushHost))) return send(res, 400, { error: "not a push service" });
    if (typeof s?.endpoint !== "string" ||
        typeof s?.keys?.p256dh !== "string" || typeof s?.keys?.auth !== "string") {
      return send(res, 400, { error: "bad subscription" });
    }
    const sub = { endpoint: s.endpoint, keys: { p256dh: s.keys.p256dh, auth: s.keys.auth } };
    subscriptions = subscriptions.filter((x) => x.endpoint !== sub.endpoint).concat([sub]).slice(-10);
    saveSubscriptions();
    send(res, 201, undefined);
  }],
];

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://relay");
    const page = PAGES.get(url.pathname);
    if (page && !url.search) {
      if (req.method !== "GET" && req.method !== "HEAD") return send(res, 405, { error: "method" });
      res.writeHead(200, { "Content-Type": page.type, "Content-Length": page.body.length, ...PAGE_HEADERS });
      return res.end(req.method === "HEAD" ? undefined : page.body);
    }
    for (const [method, re, handler] of routes) {
      const m = re.exec(url.pathname);
      if (m && req.method === method) return await handler(req, res, m, url);
    }
    send(res, 404, { error: "not found" });
  } catch (e) {
    console.error(e);
    if (!res.headersSent) send(res, 500, { error: "error" });
  }
});
server.requestTimeout = 60_000;
server.listen(PORT, () => console.log(`remote-sudo-approve server on :${PORT}`));

// As PID 1 in a container nothing handles these for us.
for (const sig of ["SIGTERM", "SIGINT"]) process.on(sig, () => process.exit(0));
