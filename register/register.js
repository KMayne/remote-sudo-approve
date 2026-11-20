// Registration page: creates a discoverable P-256 passkey for the approval
// page's RP ID and shows what to pin in the NixOS config. It sends nothing
// anywhere (connect-src 'none'); the person copies the result.

const RP_ID = location.hostname;
const $ = (id) => document.getElementById(id);
const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));

$("create").addEventListener("click", async () => {
  const name = $("name").value.trim().replace(/[^A-Za-z0-9 _-]/g, "") || "passkey";
  $("status").textContent = "Follow your passkey provider's prompts...";
  try {
    const cred = await navigator.credentials.create({
      publicKey: {
        rp: { id: RP_ID, name: "sudo approval" },
        user: { id: crypto.getRandomValues(new Uint8Array(16)), name: `sudo-${name}`, displayName: `sudo approval (${name})` },
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: { residentKey: "required", userVerification: "required" },
        attestation: "none",
        timeout: 120_000,
      },
    });
    const r = cred.response;
    if (r.getPublicKeyAlgorithm() !== -7) throw new Error("the passkey isn't P-256 (ES256)");
    const auth = new Uint8Array(r.getAuthenticatorData());
    const flags = auth[32];
    const entry = { name, id: b64url(cred.rawId), public_key: b64(r.getPublicKey()), device_bound: false };
    // The same fingerprint the machines print on every approval
    // (verify/src/webauthn.rs): check it after the first test approval.
    const fp = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${entry.id}.${entry.public_key}`)));
    const fingerprint = Array.from(fp.slice(0, 8), (b) => b.toString(16).padStart(2, "0")).join("");
    $("out").textContent = JSON.stringify(entry, null, 2) + `\n\nkey fingerprint: ${fingerprint}` +
      `\n\nflags: user verified=${!!(flags & 4)}, backup eligible (synced)=${!!(flags & 8)}, backed up=${!!(flags & 16)}`;
    $("status").textContent = "Done. Add this entry to the config, check it in, and deploy.";
  } catch (e) {
    $("status").textContent = `Failed: ${e.message || e}`;
  }
});
