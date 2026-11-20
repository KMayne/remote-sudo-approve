//! Prints canonical requests with awkward contents, one per line, for the
//! page's cross-check (page/canonical.test.mjs).
use remote_sudo_approve::request::{Change, Request};

fn main() {
    let base = Request {
        id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
        host: "office-pi".into(),
        user: "claude".into(),
        runas: "root".into(),
        command: "/nix/store/x/bin/systemctl".into(),
        argv: vec!["systemctl".into(), "restart".into(), "nginx".into()],
        env: vec![("HOME".into(), "/root".into()), ("TERM".into(), "xterm".into())],
        cwd: "/".into(),
        stdin: "tty".into(),
        created: 1795100000,
        expires: 1795100120,
        change: None,
        warnings: vec![],
    };
    let mut v = vec![base.clone()];
    let mut r = base.clone();
    r.argv = vec![
        "x".into(),
        "spaces  and\ttabs".into(),
        "quote\" back\\slash".into(),
        "newline\nnull\u{0}del\u{7f}".into(),
        "bidi \u{202e}evil\u{202c} zero\u{200b}width".into(),
        "accent \u{e9} emoji \u{1f600} cjk \u{4e2d}".into(),
        "".into(),
    ];
    r.warnings = vec!["argument 1: \"/tmp/x\" is writable".into()];
    r.stdin = "not-tty".into();
    v.push(r);
    let mut r = base.clone();
    r.change = Some(Change { system: "/nix/store/abc-nixos-system".into(), diffs: vec![("etc/sudoers".into(), "-a\n+b \u{2028}".into())] });
    v.push(r);
    let mut r = base;
    r.change = Some(Change { system: "/nix/store/abc".into(), diffs: vec![] });
    v.push(r);
    for r in v {
        println!("{}", r.canonical());
    }
}
