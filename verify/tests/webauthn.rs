//! A simulated passkey signs; every forged or altered assertion must fail.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::EncodePublicKey;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use remote_sudo_approve::webauthn::{Assertion, Credential, Reject, RelyingParty};

const RP: &str = "approve.example.ts.net";
const ORIGIN: &str = "https://approve.example.ts.net";
const CRED_ID: &[u8] = b"credential-one";

struct Authenticator {
    key: SigningKey,
}

/// What a browser + passkey would produce; each knob lets a test break one
/// thing.
struct Ceremony<'a> {
    challenge: &'a [u8],
    kind: &'a str,
    origin: &'a str,
    rp_id: &'a str,
    flags: u8,
    extra_client: &'a str,
    cred_id: &'a [u8],
}

impl Default for Ceremony<'_> {
    fn default() -> Self {
        Ceremony { challenge: &[7; 32], kind: "webauthn.get", origin: ORIGIN, rp_id: RP, flags: 0x05, extra_client: "", cred_id: CRED_ID }
    }
}

impl Authenticator {
    fn new() -> Self {
        Authenticator { key: SigningKey::random(&mut OsRng) }
    }

    fn credential(&self, device_bound: bool) -> Credential {
        let der = self.key.verifying_key().to_public_key_der().unwrap();
        Credential { name: "phone".into(), id: URL_SAFE_NO_PAD.encode(CRED_ID), public_key: STANDARD.encode(der.as_bytes()), device_bound }
    }

    fn sign(&self, c: &Ceremony) -> Assertion {
        let client = format!(
            r#"{{"type":"{}","challenge":"{}","origin":"{}"{}}}"#,
            c.kind,
            URL_SAFE_NO_PAD.encode(c.challenge),
            c.origin,
            c.extra_client
        );
        let mut auth = Sha256::digest(c.rp_id.as_bytes()).to_vec();
        auth.push(c.flags);
        auth.extend_from_slice(&[0, 0, 0, 0]); // sign count
        let mut signed = auth.clone();
        signed.extend_from_slice(&Sha256::digest(client.as_bytes()));
        let sig: Signature = self.key.sign(&signed);
        Assertion {
            id: URL_SAFE_NO_PAD.encode(c.cred_id),
            authenticator_data: URL_SAFE_NO_PAD.encode(&auth),
            client_data_json: URL_SAFE_NO_PAD.encode(client.as_bytes()),
            signature: URL_SAFE_NO_PAD.encode(sig.to_der().as_bytes()),
        }
    }
}

fn rp(creds: &[Credential]) -> RelyingParty<'_> {
    RelyingParty { rp_id: RP, origin: ORIGIN, credentials: creds }
}

const C: [u8; 32] = [7; 32];

#[test]
fn a_genuine_assertion_verifies() {
    let a = Authenticator::new();
    let creds = [a.credential(false)];
    assert_eq!(rp(&creds).verify(&a.sign(&Ceremony::default()), &C).map(|c| c.name.as_str()), Ok("phone"));
    assert_eq!(creds[0].fingerprint().len(), 16);
}

#[test]
fn an_approval_for_another_request_is_rejected() {
    let a = Authenticator::new();
    let creds = [a.credential(false)];
    let other = [8u8; 32];
    let s = a.sign(&Ceremony { challenge: &other, ..Default::default() });
    assert_eq!(rp(&creds).verify(&s, &C).err(), Some(Reject::WrongChallenge));
}

#[test]
fn an_unknown_key_is_rejected_even_if_its_signature_is_valid() {
    let ours = Authenticator::new();
    let attacker = Authenticator::new();
    let creds = [ours.credential(false)];
    // The attacker's own key, presented under our credential id.
    assert_eq!(rp(&creds).verify(&attacker.sign(&Ceremony::default()), &C).err(), Some(Reject::BadSignature));
    // Under its own id.
    let s = attacker.sign(&Ceremony { cred_id: b"attacker", ..Default::default() });
    assert_eq!(rp(&creds).verify(&s, &C).err(), Some(Reject::UnknownCredential));
}

#[test]
fn a_tampered_client_data_or_authenticator_data_breaks_the_signature() {
    let a = Authenticator::new();
    let creds = [a.credential(false)];
    let good = a.sign(&Ceremony::default());

    // Set the UV flag after signing.
    let weak = a.sign(&Ceremony { flags: 0x01, ..Default::default() });
    let mut auth = URL_SAFE_NO_PAD.decode(&weak.authenticator_data).unwrap();
    auth[32] |= 0x04;
    let forged = Assertion { authenticator_data: URL_SAFE_NO_PAD.encode(&auth), ..weak };
    assert_eq!(rp(&creds).verify(&forged, &C).err(), Some(Reject::BadSignature));

    // Swap in other client data.
    let other = a.sign(&Ceremony { challenge: &[9; 32], ..Default::default() });
    let mixed = Assertion { client_data_json: other.client_data_json.clone(), ..good.clone() };
    assert!(rp(&creds).verify(&mixed, &C).is_err());
}

#[test]
fn wrong_origin_rp_or_type_are_rejected() {
    let a = Authenticator::new();
    let creds = [a.credential(false)];
    let s = a.sign(&Ceremony { origin: "https://other.example.ts.net", ..Default::default() });
    assert_eq!(rp(&creds).verify(&s, &C).err(), Some(Reject::WrongOrigin));
    let s = a.sign(&Ceremony { origin: "https://approve.example.ts.net.evil.example", ..Default::default() });
    assert_eq!(rp(&creds).verify(&s, &C).err(), Some(Reject::WrongOrigin));
    let s = a.sign(&Ceremony { rp_id: "example.ts.net", ..Default::default() });
    assert_eq!(rp(&creds).verify(&s, &C).err(), Some(Reject::WrongRpId));
    let s = a.sign(&Ceremony { kind: "webauthn.create", ..Default::default() });
    assert_eq!(rp(&creds).verify(&s, &C).err(), Some(Reject::WrongType));
}

#[test]
fn framed_or_cross_origin_ceremonies_are_rejected() {
    let a = Authenticator::new();
    let creds = [a.credential(false)];
    let s = a.sign(&Ceremony { extra_client: r#","crossOrigin":true"#, ..Default::default() });
    assert_eq!(rp(&creds).verify(&s, &C).err(), Some(Reject::CrossOrigin));
    let s = a.sign(&Ceremony { extra_client: r#","crossOrigin":false,"topOrigin":"https://evil.example""#, ..Default::default() });
    assert_eq!(rp(&creds).verify(&s, &C).err(), Some(Reject::CrossOrigin));
    let s = a.sign(&Ceremony { extra_client: r#","crossOrigin":false"#, ..Default::default() });
    assert!(rp(&creds).verify(&s, &C).is_ok());
}

#[test]
fn user_presence_and_verification_are_required() {
    let a = Authenticator::new();
    let creds = [a.credential(false)];
    let s = a.sign(&Ceremony { flags: 0x04, ..Default::default() });
    assert_eq!(rp(&creds).verify(&s, &C).err(), Some(Reject::NotUserPresent));
    let s = a.sign(&Ceremony { flags: 0x01, ..Default::default() });
    assert_eq!(rp(&creds).verify(&s, &C).err(), Some(Reject::NotUserVerified));
}

#[test]
fn synced_keys_only_where_allowed() {
    let a = Authenticator::new();
    let synced = a.sign(&Ceremony { flags: 0x05 | 0x08 | 0x10, ..Default::default() });
    assert!(rp(&[a.credential(false)]).verify(&synced, &C).is_ok());
    assert_eq!(rp(&[a.credential(true)]).verify(&synced, &C).err(), Some(Reject::SyncedKeyNotAllowed));
}

#[test]
fn garbage_is_rejected_not_panicked_on() {
    let a = Authenticator::new();
    let creds = [a.credential(false)];
    let good = a.sign(&Ceremony::default());
    for bad in [
        Assertion { signature: "!!".into(), ..good.clone() },
        Assertion { signature: URL_SAFE_NO_PAD.encode([0u8; 3]), ..good.clone() },
        Assertion { authenticator_data: URL_SAFE_NO_PAD.encode([0u8; 10]), ..good.clone() },
        Assertion { client_data_json: URL_SAFE_NO_PAD.encode(b"not json"), ..good.clone() },
        Assertion { client_data_json: URL_SAFE_NO_PAD.encode(b"{}"), ..good.clone() },
        Assertion { id: "".into(), ..good.clone() },
    ] {
        assert!(rp(&creds).verify(&bad, &C).is_err());
    }
}
