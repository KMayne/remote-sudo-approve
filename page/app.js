// The approval page. Trusted (DESIGN.md): it shows a request and asks the
// passkey to sign exactly what it shows. Rules it must keep:
//  - the challenge is SHA-256 of the bytes received, and only after they
//    parse into the canonical form (canonical.js);
//  - nothing from the request is ever inserted as HTML: textContent only;
//  - it never takes a challenge, RP ID or origin from the relay.

import { canonical, escape, parse } from "./canonical.js";

// No names built in: the API is on the server this page came from, and the
// passkey's RP ID is this page's own host name. (The machines check the
// origin and RP ID they were configured with, so a page served from the
// wrong place can't produce a signature they accept.)
const RELAY = "";
const RP_ID = location.hostname;

const $ = (id) => document.getElementById(id);
const el = (tag, text, cls) => {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
};
const b64url = (buf) => {
  let s = "";
  for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
function status(text, cls = "") {
  const s = $("status");
  s.textContent = text;
  s.className = cls;
}

async function load(id) {
  const resp = await fetch(`${RELAY}/v1/requests/${id}`, { cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer" });
  if (resp.status === 404) throw new Error("This request has expired or doesn't exist.");
  if (!resp.ok) throw new Error(`The relay said ${resp.status}.`);
  const bytes = new Uint8Array(await resp.arrayBuffer());
  // ignoreBOM keeps a leading BOM in the text, so it fails the ASCII check
  // instead of being hashed but not shown.
  const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  const req = parse(text);
  if (req.id !== id) throw new Error("The relay returned a different request.");
  // Belt and braces: what we hash is exactly what we re-serialised.
  if (canonical(req) !== text) throw new Error("Not canonical.");
  return { req, bytes };
}

function row(label, value, cls) {
  const tr = el("tr");
  tr.append(el("th", label), el("td", value, cls));
  return tr;
}

// Every string from the request is shown through one of these, so nothing
// invisible or misleading reaches the screen: plain text only if it is
// printable ASCII with no odd spacing, otherwise as an escaped literal.
const PLAIN = /^[\x21-\x7e]+( [\x21-\x7e]+)*$/;
const show = (s) => (PLAIN.test(s) ? s : escape(s));
// Multi-line text (diffs): each line on its own, escaped the same way.
const showLines = (s) => s.split("\n").map((l) => (l === "" || PLAIN.test(l) ? l : escape(l))).join("\n");

function render(req) {
  const d = $("request");
  d.replaceChildren();
  d.append(el("h1", `sudo on ${show(req.host)}`));

  // Warnings first: they decide how carefully to read the rest.
  if (req.warnings.length) {
    const w = el("ul", undefined, "warnings");
    for (const x of req.warnings) w.append(el("li", show(x)));
    const box = el("div", undefined, "warnbox");
    box.append(el("h2", "Warnings"), w);
    d.append(box);
  }

  d.append(el("p", `${show(req.user)} wants to run, as ${show(req.runas)}:`, "lead"));

  // Every argument on its own line, numbered from 0 like argv[N] in the
  // warnings, always as an escaped literal so spaces, control and non-ASCII
  // characters are visible.
  const args = el("ol", undefined, "argv");
  args.start = 0;
  for (const a of req.argv) args.append(el("li", escape(a)));
  d.append(args);

  const t = el("table");
  t.append(row("program", show(req.command), "mono"));
  t.append(row("directory", show(req.cwd), "mono"));
  t.append(row("stdin", req.stdin === "null" ? "/dev/null (no input)" : show(req.stdin), req.stdin === "null" ? "" : "warn"));
  t.append(row("expires", new Date(req.expires * 1000).toLocaleTimeString()));
  d.append(t);

  if (req.change) {
    d.append(el("h2", "Deploy", req.change.diffs.length ? "warn" : ""));
    d.append(el("p", show(req.change.system), "mono"));
    if (req.change.diffs.length === 0) {
      d.append(el("p", "No security changes."));
    } else {
      d.append(el("p", "This changes sudo security:", "warn"));
      for (const [path, diff] of req.change.diffs) {
        d.append(el("h3", show(path), "mono"), el("pre", showLines(diff), "diff"));
      }
    }
  }

  const env = el("details");
  env.append(el("summary", `environment (${req.env.length})`));
  const et = el("table");
  for (const [k, v] of req.env) et.append(row(show(k), escape(v), "mono"));
  env.append(et);
  d.append(env);
}

async function approve(req, bytes) {
  const challenge = await crypto.subtle.digest("SHA-256", bytes);
  const cred = await navigator.credentials.get({
    publicKey: { challenge, rpId: RP_ID, userVerification: "required", timeout: 120_000, allowCredentials: [] },
  });
  const r = cred.response;
  const body = {
    id: b64url(cred.rawId),
    authenticatorData: b64url(r.authenticatorData),
    clientDataJSON: b64url(r.clientDataJSON),
    signature: b64url(r.signature),
  };
  const resp = await fetch(`${RELAY}/v1/requests/${req.id}/assertions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    credentials: "omit",
    referrerPolicy: "no-referrer",
  });
  if (resp.status !== 202) throw new Error(`The relay said ${resp.status}.`);
}

async function main() {
  // Never inside a frame, and never under the control of a page that opened
  // us: either could change what's shown just before the tap.
  if (window.top !== window || window.opener) {
    status("Open this page directly, not from inside another page.", "error");
    return;
  }
  const id = location.hash.slice(1);
  if (!/^[A-Za-z0-9_-]{22}$/.test(id)) {
    status("No request here. Open this page from a sudo notification.");
    return;
  }
  let loaded;
  try {
    loaded = await load(id);
  } catch (e) {
    status(String(e.message || e), "error");
    return;
  }
  const { req, bytes } = loaded;
  render(req);

  const button = $("approve");
  button.hidden = false;
  // A moment to read before the button works, so a request can't be
  // swapped in under a finger already on its way down.
  button.disabled = true;
  let armed = false;
  setTimeout(() => {
    armed = true;
    if (tick()) button.disabled = false;
  }, 1500);
  const tick = () => {
    if (Date.now() / 1000 >= req.expires) {
      button.disabled = true;
      status("Expired.", "error");
      return false;
    }
    return true;
  };
  setInterval(tick, 1000);
  tick();
  button.addEventListener("click", async () => {
    if (!armed || !tick()) return;
    button.disabled = true;
    status("Waiting for your passkey...");
    try {
      await approve(req, bytes);
      status("Approved. The machine checks the signature and runs the command.", "ok");
    } catch (e) {
      button.disabled = false;
      status(`Not approved: ${e.message || e}`, "error");
    }
  });
}

// Setup: subscribe this device to approval notifications.
// Trusted Types are enforced where supported (index.html), so the worker
// URL goes through a policy that allows exactly this one script. Created
// once: a second createPolicy with the same name throws.
const swUrl = window.trustedTypes
  ? trustedTypes.createPolicy("sw", {
      createScriptURL: (u) => {
        if (u !== "./sw.js") throw new Error("unexpected script URL");
        return u;
      },
    }).createScriptURL("./sw.js")
  : "./sw.js";

async function subscribe() {
  try {
    // Ask while the tap still counts as a user gesture (iOS).
    if ((await Notification.requestPermission()) !== "granted") throw new Error("notifications not allowed");
    const token = prompt("Setup token");
    if (!token) return;
    const reg = await navigator.serviceWorker.register(swUrl, { scope: "./" });
    await navigator.serviceWorker.ready;
    const { key } = await (await fetch(`${RELAY}/v1/vapid-public-key`, { credentials: "omit" })).json();
    const raw = Uint8Array.from(atob(key.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
    const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: raw });
    const resp = await fetch(`${RELAY}/v1/subscriptions`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify(sub.toJSON()),
      credentials: "omit",
    });
    if (resp.status !== 201) throw new Error(`relay said ${resp.status}`);
    status("This device will get approval notifications.", "ok");
  } catch (e) {
    status(`Couldn't subscribe: ${e.message || e}`, "error");
  }
}

$("subscribe").addEventListener("click", subscribe);
// A changed request id never loads by itself: blank the page and make the
// person ask for it.
window.addEventListener("hashchange", () => {
  $("request").replaceChildren();
  $("approve").hidden = true;
  status("The request changed. Reload to see the new one.", "error");
});
main();
