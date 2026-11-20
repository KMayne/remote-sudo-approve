// End to end: the real server, the real verifier (debug build) and a
// simulated passkey that does what the page does: fetch the request bytes
// from the relay, hash them, sign.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import webpush from "web-push";

const ROOT = new URL("..", import.meta.url).pathname;
const RP_ID = "approve.example.ts.net";
const ORIGIN = `https://${RP_ID}`;
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "spk-"));
const PORT = 18000 + Math.floor(Math.random() * 1000);
const RELAY = `http://127.0.0.1:${PORT}`;
const HOST_TOKEN = crypto.randomBytes(24).toString("base64url");
const sha256 = (b) => crypto.createHash("sha256").update(b).digest();
const b64url = (b) => Buffer.from(b).toString("base64url");

const passkey = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const intruder = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const CRED_ID = b64url(Buffer.from("phone-credential"));
let relay;
let verifier;

before(async () => {
  execFileSync("cargo", ["build", "-q", "--bin", "remote-sudo-approve-verify"], { cwd: ROOT });
  verifier = path.join(ROOT, "target/debug/remote-sudo-approve-verify");
  fs.writeFileSync(path.join(dir, "tokens.json"), JSON.stringify({ "test-host": sha256(HOST_TOKEN).toString("hex") }));
  fs.writeFileSync(path.join(dir, "token"), HOST_TOKEN);
  const v = webpush.generateVAPIDKeys();
  // The page directory as packaged: page/ with register/ inside it.
  const pageDir = path.join(dir, "page");
  fs.cpSync(path.join(ROOT, "page"), pageDir, { recursive: true });
  fs.cpSync(path.join(ROOT, "register"), path.join(pageDir, "register"), { recursive: true });
  relay = spawn("node", ["server.mjs"], {
    cwd: path.join(ROOT, "server"),
    env: {
      ...process.env, PORT: String(PORT), ORIGIN, PAGE_DIR: pageDir,
      VAPID_PUBLIC_KEY: v.publicKey, VAPID_PRIVATE_KEY: v.privateKey,
      HOST_TOKENS_FILE: path.join(dir, "tokens.json"), SETUP_TOKEN_SHA256: sha256("x".repeat(32)).toString("hex"),
      SUBSCRIPTIONS_FILE: path.join(dir, "subs.json"),
    },
    stdio: ["ignore", "pipe", "inherit"],
  });
  await new Promise((ok) => relay.stdout.once("data", ok));
});

after(() => {
  relay?.kill();
  fs.rmSync(dir, { recursive: true, force: true });
});

function config(expiry = 20) {
  const spki = passkey.publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const p = path.join(dir, `config-${expiry}.json`);
  fs.writeFileSync(p, JSON.stringify({
    host: "test-host", rp_id: RP_ID, origin: ORIGIN, relay: RELAY, token_file: path.join(dir, "token"),
    credentials: [{ name: "phone", id: CRED_ID, public_key: spki }],
    trusted: { root_owned_under: ["/usr/bin"] },
    env: { HOME: { exact: "/root" }, TERM: "term" },
    expiry_seconds: expiry,
  }));
  return p;
}

function frame(commandInfo, argv, envp, tty = true) {
  const userInfo = ["user=claude", `uid=${process.getuid()}`, `gid=${process.getgid()}`];
  const parts = [Buffer.from("SPK1")];
  for (const s of [userInfo, commandInfo, argv, envp]) {
    const n = Buffer.alloc(4); n.writeUInt32LE(s.length); parts.push(n);
    for (const item of s) {
      const b = Buffer.from(item); const l = Buffer.alloc(4); l.writeUInt32LE(b.length); parts.push(l, b);
    }
  }
  parts.push(Buffer.from([tty ? 1 : 0]));
  return Buffer.concat(parts);
}

const COMMAND = ["command=/usr/bin/true", "runas_uid=0", "runas_gid=0", "cwd=/"];
const ENV = ["HOME=/root", "TERM=xterm"];

/** Start the verifier. `id` resolves to the request id once it's waiting;
 * `done` to {code, err}. */
function start(msg, cfg = config()) {
  const child = spawn(verifier, [], { env: { REMOTE_SUDO_APPROVE_TEST_CONFIG: cfg }, stdio: ["pipe", "ignore", "pipe"] });
  let err = "";
  let gotId;
  const id = new Promise((ok) => (gotId = ok));
  child.stderr.on("data", (d) => {
    err += d;
    const m = /#([A-Za-z0-9_-]{22})/.exec(err);
    if (m) gotId(m[1]);
  });
  child.stdin.end(msg);
  const done = new Promise((ok) => child.on("exit", (code) => { gotId(null); ok({ code, err }); }));
  return { id, done };
}

/** The page + passkey: fetch the bytes, hash, sign, post. */
async function approve(id, key = passkey.privateKey, { origin = ORIGIN, flags = 0x05, alter } = {}) {
  const bytes = Buffer.from(await (await fetch(`${RELAY}/v1/requests/${id}`)).arrayBuffer());
  const challenge = sha256(alter ? alter(bytes) : bytes);
  const clientData = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: b64url(challenge), origin, crossOrigin: false }));
  const authData = Buffer.concat([sha256(RP_ID), Buffer.from([flags, 0, 0, 0, 0])]);
  const sig = crypto.sign("sha256", Buffer.concat([authData, sha256(clientData)]), key);
  const r = await fetch(`${RELAY}/v1/requests/${id}/assertions`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id: CRED_ID, authenticatorData: b64url(authData), clientDataJSON: b64url(clientData), signature: b64url(sig) }),
  });
  assert.equal(r.status, 202);
}

test("a genuine approval lets the command through", async () => {
  const v = start(frame(COMMAND, ["true"], ENV));
  await approve(await v.id);
  const { code, err } = await v.done;
  assert.equal(code, 0, err);
  assert.match(err, /approved by phone/);
});

test("junk and forgeries are ignored; the genuine one still works", async () => {
  const v = start(frame(COMMAND, ["true"], ENV));
  const id = await v.id;
  await approve(id, intruder.privateKey);                       // someone else's key
  await approve(id, passkey.privateKey, { origin: "https://other.example.ts.net" });
  await approve(id, passkey.privateKey, { flags: 0x01 });       // no user verification
  await approve(id, passkey.privateKey, { alter: (b) => Buffer.from(b.toString().replace("true", "sh")) });
  await approve(id);                                            // genuine, last
  const { code, err } = await v.done;
  assert.equal(code, 0, err);
  assert.equal((err.match(/ignoring/g) || []).length, 4, err);
});

test("an approval for another request doesn't carry over", async () => {
  const a = start(frame(COMMAND, ["true"], ENV), config(4));
  const b = start(frame(COMMAND, ["true", "other"], ENV), config(4));
  const [ida, idb] = [await a.id, await b.id];
  // Sign b's bytes, post to a.
  const bytes = Buffer.from(await (await fetch(`${RELAY}/v1/requests/${idb}`)).arrayBuffer());
  await approve(ida, passkey.privateKey, { alter: () => bytes });
  assert.equal((await a.done).code, 1);
  assert.equal((await b.done).code, 1);
});

test("no approval: denied when it expires", async () => {
  const v = start(frame(COMMAND, ["true"], ENV), config(2));
  await v.id;
  const { code, err } = await v.done;
  assert.equal(code, 1);
  assert.match(err, /timed out/);
});

test("refused before anything is sent", async () => {
  for (const msg of [
    frame(["command=/usr/bin/bash", "runas_uid=0", "runas_gid=0", "cwd=/"], ["bash"], ENV),
    frame(COMMAND, ["true"], [...ENV, "LD_PRELOAD=/tmp/x.so"]),
    frame([...COMMAND, "sudoedit=true"], ["true"], ENV),
    frame(COMMAND.filter((k) => !k.startsWith("cwd=")), ["true"], ENV),
    Buffer.from("garbage"),
  ]) {
    const v = start(msg);
    const { code, err } = await v.done;
    assert.equal(code, 1, err);
    assert.doesNotMatch(err, /waiting/);
  }
});

test("the relay won't take requests without this host's token", async () => {
  const r = await fetch(`${RELAY}/v1/requests`, { method: "POST", body: "{}", headers: { Authorization: "Bearer " + "y".repeat(30) } });
  assert.equal(r.status, 401);
});

test("the API never serves a page, whatever the path or content", async () => {
  for (const p of ["/v1/", "/v1/requests/<script>", "/v1/requests/AAAAAAAAAAAAAAAAAAAAAA", "/nope", "/index.html", "/app.js/", "/register", "/../etc/passwd", "/?x=1"]) {
    const r = await fetch(RELAY + p);
    assert.equal(r.headers.get("x-content-type-options"), "nosniff", p);
    assert.match(r.headers.get("content-security-policy"), /default-src 'none'/, p);
    assert.equal(r.headers.get("content-type"), "application/json", p);
    assert.equal(r.status, 404, p);
  }
});

test("the page is served at its exact paths, with the headers a meta tag can't set", async () => {
  for (const [p, type] of [["/", "text/html"], ["/app.js", "text/javascript"], ["/canonical.js", "text/javascript"], ["/sw.js", "text/javascript"],
    ["/style.css", "text/css"], ["/manifest.json", "application/manifest+json"], ["/register/", "text/html"], ["/register/register.js", "text/javascript"]]) {
    const r = await fetch(RELAY + p);
    assert.equal(r.status, 200, p);
    assert.ok(r.headers.get("content-type").startsWith(type), p);
    assert.equal(r.headers.get("content-security-policy"), "frame-ancestors 'none'", p);
    assert.equal(r.headers.get("x-frame-options"), "DENY", p);
    assert.equal(r.headers.get("cross-origin-opener-policy"), "same-origin", p);
    assert.equal(r.headers.get("x-content-type-options"), "nosniff", p);
    assert.ok(r.headers.get("strict-transport-security"), p);
  }
  // What's served is exactly the file in the repo.
  const served = Buffer.from(await (await fetch(RELAY + "/app.js")).arrayBuffer());
  assert.deepEqual(served, fs.readFileSync(path.join(ROOT, "page/app.js")));
  assert.equal((await fetch(RELAY + "/", { method: "POST" })).status, 405);
});
