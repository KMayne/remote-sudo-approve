//! Checking a WebAuthn assertion (W3C WebAuthn Level 3, §7.2), for one
//! relying party, one expected challenge and a fixed set of pinned P-256
//! credentials. Nothing here trusts the relay: every input comes from it.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Authenticator data flags.
const UP: u8 = 0x01;
const UV: u8 = 0x04;
const BE: u8 = 0x08;

/// A passkey that may approve, as pinned in the config.
#[derive(Debug, Clone, Deserialize)]
pub struct Credential {
    pub name: String,
    /// Credential id, base64url without padding (as the browser reports it).
    pub id: String,
    /// SubjectPublicKeyInfo DER, standard base64 (from
    /// `AuthenticatorAttestationResponse.getPublicKey()`).
    pub public_key: String,
    /// If true, assertions that say the key is backup-eligible (synced) are
    /// refused.
    #[serde(default)]
    pub device_bound: bool,
}

/// What the browser sends back, base64url-encoded fields as in
/// `PublicKeyCredential.toJSON()`.
#[derive(Debug, Clone, Deserialize)]
pub struct Assertion {
    pub id: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub signature: String,
}

impl Credential {
    /// A short fingerprint of the pinned key, shown at registration and on
    /// every approval: the first 8 bytes of SHA-256(id || "." || public_key)
    /// over the two strings as configured, in hex.
    pub fn fingerprint(&self) -> String {
        let d = Sha256::digest(format!("{}.{}", self.id, self.public_key).as_bytes());
        d[..8].iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join("")
    }
}

pub struct RelyingParty<'a> {
    /// e.g. "approve.example.ts.net"
    pub rp_id: &'a str,
    /// e.g. "https://approve.example.ts.net"
    pub origin: &'a str,
    pub credentials: &'a [Credential],
}

#[derive(Debug, PartialEq, Eq)]
pub enum Reject {
    UnknownCredential,
    BadEncoding(&'static str),
    BadPublicKey,
    ClientData(&'static str),
    WrongType,
    WrongChallenge,
    WrongOrigin,
    CrossOrigin,
    AuthDataTooShort,
    WrongRpId,
    NotUserPresent,
    NotUserVerified,
    SyncedKeyNotAllowed,
    BadSignature,
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin")]
    cross_origin: Option<bool>,
    #[serde(rename = "topOrigin")]
    top_origin: Option<serde_json::Value>,
}

impl RelyingParty<'_> {
    /// Verify `a` against `challenge`. Ok carries the approving credential.
    pub fn verify(&self, a: &Assertion, challenge: &[u8; 32]) -> Result<&Credential, Reject> {
        // The pinned credential, compared on decoded bytes.
        let id = URL_SAFE_NO_PAD.decode(&a.id).map_err(|_| Reject::BadEncoding("id"))?;
        let cred = self
            .credentials
            .iter()
            .find(|c| URL_SAFE_NO_PAD.decode(&c.id).map(|b| b == id).unwrap_or(false))
            .ok_or(Reject::UnknownCredential)?;
        let key_der = STANDARD.decode(&cred.public_key).map_err(|_| Reject::BadPublicKey)?;
        let key = VerifyingKey::from_public_key_der(&key_der).map_err(|_| Reject::BadPublicKey)?;

        let cdj = URL_SAFE_NO_PAD
            .decode(&a.client_data_json)
            .map_err(|_| Reject::BadEncoding("clientDataJSON"))?;
        let auth = URL_SAFE_NO_PAD
            .decode(&a.authenticator_data)
            .map_err(|_| Reject::BadEncoding("authenticatorData"))?;
        let sig = URL_SAFE_NO_PAD.decode(&a.signature).map_err(|_| Reject::BadEncoding("signature"))?;

        // §7.2 steps 10-13: client data.
        let cd: ClientData = serde_json::from_slice(&cdj).map_err(|_| Reject::ClientData("not JSON"))?;
        if cd.kind != "webauthn.get" {
            return Err(Reject::WrongType);
        }
        if cd.challenge != URL_SAFE_NO_PAD.encode(challenge) {
            return Err(Reject::WrongChallenge);
        }
        if cd.origin != self.origin {
            return Err(Reject::WrongOrigin);
        }
        if cd.cross_origin == Some(true) || cd.top_origin.is_some() {
            return Err(Reject::CrossOrigin);
        }

        // Steps 15-17: authenticator data.
        if auth.len() < 37 {
            return Err(Reject::AuthDataTooShort);
        }
        let rp_hash: [u8; 32] = Sha256::digest(self.rp_id.as_bytes()).into();
        if auth[..32] != rp_hash {
            return Err(Reject::WrongRpId);
        }
        let flags = auth[32];
        if flags & UP == 0 {
            return Err(Reject::NotUserPresent);
        }
        if flags & UV == 0 {
            return Err(Reject::NotUserVerified);
        }
        if cred.device_bound && flags & BE != 0 {
            return Err(Reject::SyncedKeyNotAllowed);
        }

        // Steps 19-20: the signature over authData || SHA-256(clientDataJSON).
        let sig = Signature::from_der(&sig).map_err(|_| Reject::BadSignature)?;
        let mut signed = auth.clone();
        signed.extend_from_slice(&Sha256::digest(&cdj));
        key.verify(&signed, &sig).map_err(|_| Reject::BadSignature)?;
        Ok(cred)
    }
}
