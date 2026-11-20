//! Deploys: what a switch to another NixOS system would change in the files
//! that decide who gets root. Shown in red on the approval page (the
//! request's `change`), and used by automatic updates to refuse such
//! changes outright.
//!
//! Compared between two system paths (the running one and the target):
//! sudo's own configuration, this tool's, PAM for sudo, sshd and authorized
//! keys, Nix's settings, polkit rules, and a summary of users, groups and
//! setuid wrappers that the NixOS module writes (etc/remote-sudo-approve/summary).

use std::collections::BTreeSet;
use std::path::Path;

use similar::{ChangeTag, TextDiff};

/// Files, relative to a system path.
const FILES: &[&str] = &[
    "etc/sudoers",
    "etc/sudo.conf",
    "etc/remote-sudo-approve/config.json",
    "etc/remote-sudo-approve/agent.env",
    "etc/remote-sudo-approve/programs",
    "etc/remote-sudo-approve/allowed",
    "etc/remote-sudo-approve/summary",
    "etc/pam.d/sudo",
    "etc/ssh/sshd_config",
    "etc/nix/nix.conf",
    "etc/doas.conf",
];

/// Directories whose every file is compared.
const DIRS: &[&str] = &["etc/sudoers.d", "etc/ssh/authorized_keys.d", "etc/polkit-1/rules.d", "etc/ssh/sshd_config.d"];

const MAX_FILE: u64 = 512 * 1024;
/// Per file and in total, so a request stays small enough to read.
const MAX_DIFF: usize = 3000;
const MAX_TOTAL: usize = 24_000;

/// A NixOS system store path: `/nix/store/<32 chars>-<name>`, no more.
pub fn is_system_path(p: &str) -> bool {
    let Some(rest) = p.strip_prefix("/nix/store/") else { return false };
    let Some((hash, name)) = rest.split_once('-') else { return false };
    hash.len() == 32
        && hash.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && !name.is_empty()
        && name.len() <= 200
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
}

/// The security-relevant differences between two systems: (file, diff)
/// pairs, empty if there are none.
pub fn security_diff(current: &Path, target: &Path) -> Vec<(String, String)> {
    let mut names: BTreeSet<String> = FILES.iter().map(|s| s.to_string()).collect();
    for d in DIRS {
        for sys in [current, target] {
            if let Ok(rd) = std::fs::read_dir(sys.join(d)) {
                for e in rd.flatten() {
                    if let Some(n) = e.file_name().to_str() {
                        names.insert(format!("{d}/{n}"));
                    }
                }
            }
        }
    }
    let mut out = Vec::new();
    let mut total = 0;
    for name in names {
        let old = read(current, &name);
        let new = read(target, &name);
        if old == new {
            continue;
        }
        let mut d = diff(old.as_deref(), new.as_deref());
        if total + d.len() > MAX_TOTAL {
            d = "(changed; too many changes to show)".to_owned();
        }
        total += d.len();
        out.push((name, d));
    }
    out
}

/// A file's contents, normalised; None if it doesn't exist.
fn read(system: &Path, rel: &str) -> Option<String> {
    use std::io::Read;
    let f = std::fs::File::open(system.join(rel)).ok()?;
    let mut bytes = Vec::new();
    f.take(MAX_FILE).read_to_end(&mut bytes).ok()?;
    Some(normalise(rel, &String::from_utf8_lossy(&bytes)))
}

/// Store hashes change with every build; what matters is the names.
fn normalise(rel: &str, text: &str) -> String {
    match rel {
        // One real path per line: keep the program names.
        "etc/remote-sudo-approve/programs" => {
            let names: BTreeSet<&str> = text.lines().filter_map(|l| l.rsplit('/').next()).filter(|n| !n.is_empty()).collect();
            names.into_iter().collect::<Vec<_>>().join("\n")
        }
        // name<TAB>real path: keep the names.
        "etc/remote-sudo-approve/allowed" => {
            let names: BTreeSet<&str> = text.lines().filter_map(|l| l.split('\t').next()).filter(|n| !n.is_empty()).collect();
            names.into_iter().collect::<Vec<_>>().join("\n")
        }
        _ => strip_store_hashes(text),
    }
}

/// `/nix/store/<hash>-name-1.2/…` becomes `/nix/store/name/…`: the hash and
/// a trailing version go, so an ordinary update isn't a "change".
fn strip_store_hashes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("/nix/store/") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 11..];
        let item_len = after.find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))).unwrap_or(after.len());
        let item = &after[..item_len];
        let name = match item.split_once('-') {
            Some((h, n)) if h.len() == 32 => n,
            _ => item,
        };
        // Drop a trailing version: the last "-<digit>…" part.
        let name = match name.rfind('-') {
            Some(j) if name[j + 1..].starts_with(|c: char| c.is_ascii_digit()) => &name[..j],
            _ => name,
        };
        out.push_str("/nix/store/");
        out.push_str(name);
        rest = &after[item_len..];
    }
    out.push_str(rest);
    out
}

/// Changed lines only, `-` old and `+` new, capped.
fn diff(old: Option<&str>, new: Option<&str>) -> String {
    let (old, new) = match (old, new) {
        (None, Some(n)) => return cap(format!("(new file)\n{}", prefix_lines('+', n))),
        (Some(o), None) => return cap(format!("(file removed)\n{}", prefix_lines('-', o))),
        (o, n) => (o.unwrap_or(""), n.unwrap_or("")),
    };
    let mut out = String::new();
    for ch in TextDiff::from_lines(old, new).iter_all_changes() {
        let sign = match ch.tag() {
            ChangeTag::Delete => '-',
            ChangeTag::Insert => '+',
            ChangeTag::Equal => continue,
        };
        out.push(sign);
        out.push_str(ch.value().trim_end_matches('\n'));
        out.push('\n');
    }
    cap(out)
}

fn prefix_lines(sign: char, text: &str) -> String {
    text.lines().map(|l| format!("{sign}{l}\n")).collect()
}

fn cap(mut s: String) -> String {
    if s.len() > MAX_DIFF {
        let mut end = MAX_DIFF;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
        s.push_str("\n(more changes not shown)");
    }
    s.trim_end().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn system(files: &[(&str, &str)]) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for (rel, text) in files {
            let p = d.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        d
    }

    const H1: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const H2: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn an_ordinary_update_is_not_a_security_change() {
        let a = system(&[
            ("etc/sudoers", "claude ALL=(root) NOPASSWD: NOSETENV: ALL, !sudoedit\n"),
            ("etc/sudo.conf", &format!("Plugin remote_sudo_approve /nix/store/{H1}-remote-sudo-approve-0.1.0/lib/x.so verifier=/nix/store/{H1}-remote-sudo-approve-0.1.0/bin/v\n")),
            ("etc/remote-sudo-approve/programs", &format!("/nix/store/{H1}-systemd-258/bin/systemctl\n/nix/store/{H1}-coreutils-9.7/bin/coreutils\n")),
            ("etc/remote-sudo-approve/allowed", &format!("systemctl\t/nix/store/{H1}-systemd-258/bin/systemctl\n")),
            ("etc/ssh/authorized_keys.d/alice", "ssh-ed25519 AAAA alice\n"),
        ]);
        let b = system(&[
            ("etc/sudoers", "claude ALL=(root) NOPASSWD: NOSETENV: ALL, !sudoedit\n"),
            ("etc/sudo.conf", &format!("Plugin remote_sudo_approve /nix/store/{H2}-remote-sudo-approve-0.1.1/lib/x.so verifier=/nix/store/{H2}-remote-sudo-approve-0.1.1/bin/v\n")),
            ("etc/remote-sudo-approve/programs", &format!("/nix/store/{H2}-coreutils-9.8/bin/coreutils\n/nix/store/{H2}-systemd-259/bin/systemctl\n")),
            ("etc/remote-sudo-approve/allowed", &format!("systemctl\t/nix/store/{H2}-systemd-259/bin/systemctl\n")),
            ("etc/ssh/authorized_keys.d/alice", "ssh-ed25519 AAAA alice\n"),
        ]);
        assert_eq!(security_diff(a.path(), b.path()), vec![]);
    }

    #[test]
    fn changes_that_matter_show_up() {
        let a = system(&[
            ("etc/sudoers", "root ALL=(ALL) ALL\nclaude ALL=(root) NOPASSWD: NOSETENV: ALL, !sudoedit\n"),
            ("etc/sudo.conf", "Plugin sudoers_policy sudoers.so\nPlugin remote_sudo_approve /nix/store/x/lib/x.so\n"),
            ("etc/remote-sudo-approve/programs", "/nix/store/x/bin/systemctl\n"),
            ("etc/ssh/authorized_keys.d/alice", "ssh-ed25519 AAAA alice\n"),
        ]);
        let b = system(&[
            ("etc/sudoers", "root ALL=(ALL) ALL\nclaude ALL=(root) NOPASSWD: ALL\n"),
            ("etc/remote-sudo-approve/programs", "/nix/store/x/bin/systemctl\n/nix/store/y/bin/newtool\n"),
            ("etc/ssh/authorized_keys.d/alice", "ssh-ed25519 AAAA alice\n"),
            ("etc/ssh/authorized_keys.d/claude", "ssh-ed25519 BBBB evil\n"),
        ]);
        let d = security_diff(a.path(), b.path());
        let get = |n: &str| d.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str());
        assert_eq!(get("etc/sudoers"), Some("-claude ALL=(root) NOPASSWD: NOSETENV: ALL, !sudoedit\n+claude ALL=(root) NOPASSWD: ALL"));
        assert!(get("etc/sudo.conf").unwrap().starts_with("(file removed)"));
        assert_eq!(get("etc/remote-sudo-approve/programs"), Some("+newtool"));
        assert_eq!(get("etc/ssh/authorized_keys.d/claude"), Some("(new file)\n+ssh-ed25519 BBBB evil"));
        assert_eq!(d.len(), 4);
    }

    #[test]
    fn huge_diffs_are_capped() {
        let big: String = (0..5000).map(|i| format!("line {i}\n")).collect();
        let a = system(&[("etc/sudoers", "x\n")]);
        let b = system(&[("etc/sudoers", &big)]);
        let d = security_diff(a.path(), b.path());
        assert!(d[0].1.len() < MAX_DIFF + 40);
        assert!(d[0].1.ends_with("(more changes not shown)"));
    }

    #[test]
    fn system_paths() {
        assert!(is_system_path(&format!("/nix/store/{H1}-nixos-system-office-pi-26.05.20261108.ac588ef")));
        assert!(!is_system_path(&format!("/nix/store/{H1}-x/../../etc")));
        assert!(!is_system_path(&format!("/nix/store/{H1}-x/bin")));
        assert!(!is_system_path("/nix/store/short-x"));
        assert!(!is_system_path("/tmp/x"));
        assert!(!is_system_path(&format!("/nix/store/{H1}-")));
    }
}
