#!/usr/bin/env node
// remote-sudo-approve-setup: make the server's secrets. Nothing is stored; copy
// the output to where it belongs.
//
//   remote-sudo-approve-setup init
//       stdout: an env file for the server (web-push keys, setup token hash)
//       stderr: the setup token, shown once: it lets a device subscribe to
//               approval notifications on the page
//   remote-sudo-approve-setup host <name>
//       stdout: the JSON line to add to the server's tokens file
//       stderr: the machine's relay token, for its `tokenFile`
import crypto from "node:crypto";
import webpush from "web-push";

const token = (bytes) => crypto.randomBytes(bytes).toString("base64url");
const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");
const [cmd, arg] = process.argv.slice(2);

if (cmd === "init") {
  const keys = webpush.generateVAPIDKeys();
  const setup = token(18);
  console.log(`VAPID_PUBLIC_KEY=${keys.publicKey}`);
  console.log(`VAPID_PRIVATE_KEY=${keys.privateKey}`);
  console.log(`SETUP_TOKEN_SHA256=${sha256(setup)}`);
  console.error(`Setup token (type it on the page under "Get notifications on this device"): ${setup}`);
} else if (cmd === "host" && /^[A-Za-z0-9._-]{1,64}$/.test(arg || "")) {
  const t = token(32);
  console.log(JSON.stringify({ [arg]: sha256(t) }));
  console.error(`Relay token for ${arg} (goes in that machine's tokenFile): ${t}`);
} else {
  console.error("usage: remote-sudo-approve-setup init | host <name>");
  process.exit(2);
}
