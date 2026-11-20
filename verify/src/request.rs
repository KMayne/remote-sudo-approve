//! The request the passkey signs, and its canonical bytes.
//!
//! The challenge is SHA-256 of these exact bytes, built here from sudo's own
//! record of the command. The approval page re-serialises the request with
//! the same rules (page/canonical.js) and refuses to sign unless it gets the
//! same bytes, so what is shown is what is signed.
//!
//! Canonical form: a JSON object with the fields in the order below, no
//! whitespace, integers only, and every string escaped by [`escape`]: `"` and
//! `\` backslash-escaped, everything outside printable ASCII (0x20-0x7e) as
//! `\uXXXX` (UTF-16, so surrogate pairs above the BMP). The output is pure
//! ASCII.

use sha2::{Digest, Sha256};

/// Protocol version, part of the signed bytes.
pub const VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// 128 random bits, base64url without padding.
    pub id: String,
    pub host: String,
    /// The invoking user.
    pub user: String,
    pub runas: String,
    /// The real path of the program sudo will run.
    pub command: String,
    pub argv: Vec<String>,
    /// The environment the command will get, in sudo's order.
    pub env: Vec<(String, String)>,
    pub cwd: String,
    /// "tty" or "not-tty": whether the command's stdin is a terminal.
    pub stdin: String,
    pub created: u64,
    pub expires: u64,
    /// For a deploy: the target system and its security diff; else None.
    pub change: Option<Change>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The system store path being switched to.
    pub system: String,
    /// One entry per security-critical file that differs (unified diff
    /// text), empty if none.
    pub diffs: Vec<(String, String)>,
}

impl Request {
    /// The canonical bytes (ASCII).
    pub fn canonical(&self) -> String {
        let mut o = String::with_capacity(512);
        o.push_str("{\"v\":");
        o.push_str(&VERSION.to_string());
        field_str(&mut o, "id", &self.id);
        field_str(&mut o, "host", &self.host);
        field_str(&mut o, "user", &self.user);
        field_str(&mut o, "runas", &self.runas);
        field_str(&mut o, "command", &self.command);
        o.push_str(",\"argv\":");
        str_array(&mut o, self.argv.iter().map(String::as_str));
        o.push_str(",\"env\":[");
        for (i, (k, v)) in self.env.iter().enumerate() {
            if i > 0 {
                o.push(',');
            }
            str_array(&mut o, [k.as_str(), v.as_str()].into_iter());
        }
        o.push(']');
        field_str(&mut o, "cwd", &self.cwd);
        field_str(&mut o, "stdin", &self.stdin);
        o.push_str(",\"created\":");
        o.push_str(&self.created.to_string());
        o.push_str(",\"expires\":");
        o.push_str(&self.expires.to_string());
        o.push_str(",\"change\":");
        match &self.change {
            None => o.push_str("null"),
            Some(c) => {
                o.push_str("{\"system\":");
                escape_into(&mut o, &c.system);
                o.push_str(",\"diffs\":[");
                for (i, (path, diff)) in c.diffs.iter().enumerate() {
                    if i > 0 {
                        o.push(',');
                    }
                    str_array(&mut o, [path.as_str(), diff.as_str()].into_iter());
                }
                o.push_str("]}");
            }
        }
        o.push_str(",\"warnings\":");
        str_array(&mut o, self.warnings.iter().map(String::as_str));
        o.push('}');
        o
    }

    /// The WebAuthn challenge: SHA-256 of the canonical bytes.
    pub fn challenge(&self) -> [u8; 32] {
        Sha256::digest(self.canonical().as_bytes()).into()
    }
}

/// A fresh request id: 128 bits from the OS, base64url without padding.
pub fn new_id() -> Result<String, getrandom::Error> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b)?;
    use base64::Engine;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b))
}

fn field_str(o: &mut String, name: &str, value: &str) {
    o.push_str(",\"");
    o.push_str(name);
    o.push_str("\":");
    escape_into(o, value);
}

fn str_array<'a>(o: &mut String, items: impl Iterator<Item = &'a str>) {
    o.push('[');
    for (i, s) in items.enumerate() {
        if i > 0 {
            o.push(',');
        }
        escape_into(o, s);
    }
    o.push(']');
}

/// A JSON string literal, ASCII only.
pub fn escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    escape_into(&mut o, s);
    o
}

fn escape_into(o: &mut String, s: &str) {
    o.push('"');
    for ch in s.chars() {
        match ch {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            ' '..='~' => o.push(ch),
            _ => {
                let mut units = [0u16; 2];
                for u in ch.encode_utf16(&mut units) {
                    o.push_str(&format!("\\u{:04x}", u));
                }
            }
        }
    }
    o.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Request {
        Request {
            id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            host: "office-pi".into(),
            user: "claude".into(),
            runas: "root".into(),
            command: "/nix/store/x-systemd/bin/systemctl".into(),
            argv: vec!["systemctl".into(), "restart".into(), "nginx".into()],
            env: vec![("HOME".into(), "/root".into())],
            cwd: "/".into(),
            stdin: "tty".into(),
            created: 10,
            expires: 130,
            change: None,
            warnings: vec![],
        }
    }

    #[test]
    fn canonical_form() {
        assert_eq!(
            sample().canonical(),
            r#"{"v":2,"id":"AAAAAAAAAAAAAAAAAAAAAA","host":"office-pi","user":"claude","runas":"root","command":"/nix/store/x-systemd/bin/systemctl","argv":["systemctl","restart","nginx"],"env":[["HOME","/root"]],"cwd":"/","stdin":"tty","created":10,"expires":130,"change":null,"warnings":[]}"#
        );
    }

    #[test]
    fn escaping_makes_hidden_characters_visible() {
        assert_eq!(escape("a b"), r#""a b""#);
        assert_eq!(escape("q\"\\"), r#""q\"\\""#);
        assert_eq!(escape("\n\t\x7f"), r#""\u000a\u0009\u007f""#);
        // Right-to-left override and zero-width space can't hide in the text.
        assert_eq!(escape("\u{202e}\u{200b}"), "\"\\u202e\\u200b\"");
        // Above the BMP: a surrogate pair, as JavaScript sees it.
        assert_eq!(escape("\u{1f600}"), "\"\\ud83d\\ude00\"");
        assert!(sample().canonical().is_ascii());
    }

    #[test]
    fn canonical_is_valid_json_that_round_trips() {
        let mut r = sample();
        r.argv.push("weird \"arg\"\n\u{202e}\u{e9}\u{1f600}".into());
        r.change = Some(Change { system: "/nix/store/s".into(), diffs: vec![("etc/sudoers".into(), "-a\n+b".into())] });
        r.warnings.push("w".into());
        let v: serde_json::Value = serde_json::from_str(&r.canonical()).unwrap();
        assert_eq!(v["argv"][3], "weird \"arg\"\n\u{202e}\u{e9}\u{1f600}");
        assert_eq!(v["change"]["diffs"][0][1], "-a\n+b");
    }

    #[test]
    fn every_field_changes_the_challenge() {
        let base = sample().challenge();
        let mut r = sample();
        r.argv[2] = "nginx2".into();
        assert_ne!(r.challenge(), base);
        let mut r = sample();
        r.env[0].1 = "/tmp".into();
        assert_ne!(r.challenge(), base);
        let mut r = sample();
        r.expires += 1;
        assert_ne!(r.challenge(), base);
        let mut r = sample();
        r.host = "kitchen-pi".into();
        assert_ne!(r.challenge(), base);
    }

    #[test]
    fn ids_are_fresh() {
        let a = new_id().unwrap();
        assert_eq!(a.len(), 22);
        assert_ne!(a, new_id().unwrap());
    }
}
