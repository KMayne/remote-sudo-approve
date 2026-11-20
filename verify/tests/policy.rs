//! The rules, against real files on the test machine (root-owned /usr/bin)
//! and files the test user owns (standing in for the agent's).

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use remote_sudo_approve::policy::{check, warnings, EnvRule, Refusal, Rules, Trusted};

fn me() -> (u32, Vec<u32>) {
    let m = std::fs::metadata(std::env::temp_dir()).unwrap();
    let home = std::fs::metadata(std::env::var("HOME").unwrap()).unwrap();
    let _ = m;
    (home.uid(), vec![home.gid()])
}

fn rules() -> Rules {
    let (uid, gids) = me();
    let mut env = HashMap::new();
    env.insert("HOME".into(), EnvRule::Exact("/root".into()));
    env.insert("PATH".into(), EnvRule::Exact("/usr/bin:/usr/sbin".into()));
    env.insert("TERM".into(), EnvRule::Term);
    env.insert("LANG".into(), EnvRule::Locale);
    env.insert("SUDO_COMMAND".into(), EnvRule::PrintableAscii);
    env.insert("PAGER".into(), EnvRule::Exact("cat".into()));
    env.insert("SUDO_TTY".into(), EnvRule::Tty);
    let mut required_info = HashMap::new();
    required_info.insert("umask".to_owned(), "022".to_owned());
    Rules {
        trusted: Trusted::RootOwnedUnder(vec![PathBuf::from("/usr/bin"), PathBuf::from("/usr/sbin")]),
        env,
        allowed: vec![("true".into(), std::fs::canonicalize("/usr/bin/true").unwrap().to_str().unwrap().to_owned())],
        required_info,
        runas_uid: 0,
        user_uid: uid,
        user_gids: gids,
    }
}

fn info(command: &str, extra: &[&str]) -> Vec<String> {
    let mut v = vec![format!("command={command}"), "runas_uid=0".into(), "runas_gid=0".into(), "cwd=/".into(), "umask=022".into()];
    v.extend(extra.iter().map(|s| s.to_string()));
    v
}

fn argv(a: &[&str]) -> Vec<Vec<u8>> {
    a.iter().map(|s| s.as_bytes().to_vec()).collect()
}

fn good_env() -> Vec<Vec<u8>> {
    argv(&["HOME=/root", "PATH=/usr/bin:/usr/sbin", "TERM=xterm-256color", "LANG=en_GB.UTF-8", "SUDO_COMMAND=/usr/bin/true x", "PAGER=cat"])
}

fn exists(p: &str) -> bool {
    Path::new(p).exists()
}

#[test]
fn an_ordinary_command_passes() {
    let c = check(&rules(), &info("/usr/bin/true", &["use_pty=true", "closefrom=3"]), &argv(&["true", "x"]), &good_env()).unwrap();
    assert_eq!(c.command, std::fs::canonicalize("/usr/bin/true").unwrap().to_str().unwrap());
    assert_eq!(c.argv, vec!["true", "x"]);
    assert_eq!(c.cwd, "/");
}

#[test]
fn the_program_must_be_absolute_and_out_of_the_agents_reach() {
    let r = rules();
    let e = good_env();
    assert_eq!(check(&r, &info("true", &[]), &argv(&["true"]), &e), Err(Refusal::RelativeCommand));
    assert_eq!(check(&r, &info("tmp/x", &[]), &argv(&["x"]), &e), Err(Refusal::RelativeCommand));

    // A copy of a system program in a directory the agent owns.
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("true");
    std::fs::copy("/usr/bin/true", &copy).unwrap();
    assert!(matches!(check(&r, &info(copy.to_str().unwrap(), &[]), &argv(&["true"]), &e), Err(Refusal::UntrustedProgram(_))));

    // A symlink the agent owns, pointing at a trusted program: it could be
    // repointed after approval.
    let link = dir.path().join("link");
    std::os::unix::fs::symlink("/usr/bin/true", &link).unwrap();
    assert!(matches!(check(&r, &info(link.to_str().unwrap(), &[]), &argv(&["true"]), &e), Err(Refusal::UntrustedProgram(_))));

    // ".." can't climb out of /usr/bin into somewhere untrusted.
    assert!(matches!(
        check(&r, &info("/usr/bin/../../tmp", &[]), &argv(&["x"]), &e),
        Err(Refusal::UntrustedProgram(_)) | Err(Refusal::CommandUnresolvable(_))
    ));
}

#[test]
fn shells_interpreters_and_launchers_are_refused() {
    let r = rules();
    let e = good_env();
    for p in ["/usr/bin/bash", "/usr/bin/sh", "/usr/bin/env", "/usr/bin/find", "/usr/bin/sed", "/usr/bin/awk", "/usr/bin/git",
        "/usr/bin/python3", "/usr/bin/perl", "/usr/bin/less", "/usr/bin/vi", "/usr/bin/nano", "/usr/bin/xargs", "/usr/bin/sudo", "/usr/bin/su"]
    {
        if !exists(p) {
            continue;
        }
        assert!(matches!(check(&r, &info(p, &[]), &argv(&["x"]), &e), Err(Refusal::DeniedProgram(_))), "{p} should be refused");
    }
}

#[test]
fn every_name_a_program_is_run_as_is_checked() {
    let r = rules();
    let e = good_env();
    // A multi-call binary picks its behaviour from argv[0].
    assert!(matches!(check(&r, &info("/usr/bin/true", &[]), &argv(&["env", "id"]), &e), Err(Refusal::DeniedProgram(_))));
    assert!(matches!(check(&r, &info("/usr/bin/true", &[]), &argv(&["/x/bash"]), &e), Err(Refusal::DeniedProgram(_))));
    assert!(matches!(
        check(&r, &info("/usr/bin/true", &[]), &argv(&["true", "--coreutils-prog=env", "id"]), &e),
        Err(Refusal::DeniedProgram(_))
    ));
    // A symlink named like a denied program, even if it resolves to an
    // allowed one (/usr/bin/sh -> bash is denied either way; check the
    // link name path is walked).
    if exists("/usr/bin/sh") {
        assert!(matches!(check(&r, &info("/usr/bin/sh", &[]), &argv(&["sh"]), &e), Err(Refusal::DeniedProgram(_))));
    }
}

#[test]
fn execution_settings_must_be_the_expected_ones() {
    let r = rules();
    let e = good_env();
    let a = argv(&["true"]);
    let t = "/usr/bin/true";
    assert_eq!(check(&r, &info(t, &["sudoedit=true"]), &a, &e), Err(Refusal::Sudoedit));
    assert_eq!(check(&r, &info(t, &["chroot=/tmp/x"]), &a, &e), Err(Refusal::UnexpectedKey("chroot".into())));
    assert_eq!(check(&r, &info(t, &["preserve_groups=true"]), &a, &e), Err(Refusal::UnexpectedKey("preserve_groups".into())));
    assert_eq!(check(&r, &info(t, &["execfd=3"]), &a, &e), Err(Refusal::UnexpectedKey("execfd".into())));
    assert_eq!(check(&r, &info(t, &["cwd_optional=true"]), &a, &e), Err(Refusal::UnexpectedKey("cwd_optional".into())));
    assert_eq!(check(&r, &info(t, &["some_future_key=1"]), &a, &e), Err(Refusal::UnexpectedKey("some_future_key".into())));
    assert!(matches!(check(&r, &info(t, &["rlimit_core=user"]), &a, &e), Err(Refusal::BadValue(_))));
    // Required settings: exactly the configured value, and present.
    let mut i = info(t, &[]);
    i[4] = "umask=0777".into();
    assert!(matches!(check(&r, &i, &a, &e), Err(Refusal::BadValue(_))));
    i.remove(4);
    assert!(matches!(check(&r, &i, &a, &e), Err(Refusal::BadValue(_))));
    let mut need = rules();
    need.required_info.insert("rlimit_fsize".into(), "infinity".into());
    assert!(matches!(check(&need, &info(t, &[]), &a, &e), Err(Refusal::BadValue(_))));
    assert!(check(&need, &info(t, &["rlimit_fsize=infinity"]), &a, &e).is_ok());
    assert!(matches!(check(&need, &info(t, &["rlimit_fsize=1,1"]), &a, &e), Err(Refusal::BadValue(_))));
    assert!(matches!(check(&r, &info(t, &["closefrom=10"]), &a, &e), Err(Refusal::BadValue(_))));
    // A second command= can't smuggle in another program.
    assert!(matches!(check(&r, &info(t, &["command=/usr/bin/bash"]), &a, &e), Err(Refusal::BadValue(_))));

    let mut i = info(t, &[]);
    i.retain(|k| !k.starts_with("cwd="));
    assert_eq!(check(&r, &i, &a, &e), Err(Refusal::MissingKey("cwd")));
    let mut i = info(t, &[]);
    i.retain(|k| !k.starts_with("cwd="));
    i.push("cwd=/home/claude".into());
    assert!(matches!(check(&r, &i, &a, &e), Err(Refusal::BadValue(_))));
    let mut i = info(t, &[]);
    i[1] = "runas_uid=1000".into();
    assert!(matches!(check(&r, &i, &a, &e), Err(Refusal::BadValue(_))));
}

#[test]
fn the_environment_is_an_exact_allowlist() {
    let r = rules();
    let a = argv(&["true"]);
    let t = info("/usr/bin/true", &[]);
    let with = |extra: &str| {
        let mut e = good_env();
        e.push(extra.as_bytes().to_vec());
        e
    };
    assert_eq!(check(&r, &t, &a, &with("LD_PRELOAD=/tmp/x.so")), Err(Refusal::EnvNotAllowed("LD_PRELOAD".into())));
    assert_eq!(check(&r, &t, &a, &with("GIT_CONFIG_COUNT=1")), Err(Refusal::EnvNotAllowed("GIT_CONFIG_COUNT".into())));
    let mut e = good_env();
    e[1] = b"PATH=/home/claude/bin:/usr/bin".to_vec();
    assert!(matches!(check(&r, &t, &a, &e), Err(Refusal::EnvBadValue(_))));
    let mut e = good_env();
    e[3] = b"LANG=../../tmp/evil".to_vec();
    assert!(matches!(check(&r, &t, &a, &e), Err(Refusal::EnvBadValue(_))));
    let mut e = good_env();
    e[2] = b"TERM=../x".to_vec();
    assert!(matches!(check(&r, &t, &a, &e), Err(Refusal::EnvBadValue(_))));
    let mut e = good_env();
    e[5] = b"PAGER=sh -c x".to_vec();
    assert!(matches!(check(&r, &t, &a, &e), Err(Refusal::EnvBadValue(_))));
    let mut e = good_env();
    e[4] = b"SUDO_COMMAND=a\nb".to_vec();
    assert!(matches!(check(&r, &t, &a, &e), Err(Refusal::EnvBadValue(_))));
}

#[test]
fn limits_and_encoding() {
    let r = rules();
    let t = info("/usr/bin/true", &[]);
    let many: Vec<Vec<u8>> = (0..65).map(|_| b"x".to_vec()).collect();
    assert_eq!(check(&r, &t, &many, &good_env()), Err(Refusal::TooManyArgs));
    let long = vec![b"true".to_vec(), vec![b'x'; 5000]];
    assert_eq!(check(&r, &t, &long, &good_env()), Err(Refusal::ArgsTooLong));
    let bad = vec![b"true".to_vec(), vec![0xff, 0xfe]];
    assert_eq!(check(&r, &t, &bad, &good_env()), Err(Refusal::NotUtf8));
    assert_eq!(check(&r, &t, &[], &good_env()), Err(Refusal::EmptyArgv));
}

#[test]
fn warnings_flag_inputs_the_agent_can_change() {
    let r = rules();
    let mine = tempfile::tempdir_in(std::env::var("HOME").unwrap()).unwrap();
    let f = mine.path().join("payload");
    std::fs::write(&f, "x").unwrap();
    let f = f.to_str().unwrap().to_owned();
    let rel = f.trim_start_matches('/').to_owned();
    let run = |args: &[&str]| {
        let c = check(&r, &info("/usr/bin/true", &[]), &argv(args), &good_env()).unwrap();
        warnings(&r, &c)
    };

    assert!(run(&["true", "/etc/hosts"]).is_empty());
    assert!(run(&["true", "restart", "nginx", "--now", "-v"]).is_empty());
    for spelling in [
        f.clone(),
        rel.clone(),
        format!("--config={f}"),
        format!("--config={rel}"),
        format!("if={f}"),
        format!("-f{f}"),
        format!("--a=b={f}"),
        format!("@{f}"),
        format!("/etc/hosts:{f}"),
        format!("file://{f}"),
        format!("{}/new", mine.path().display()),
        "/tmp/whatever".to_owned(),
        "/dev/stdin".to_owned(),
        "/proc/self/fd/0".to_owned(),
    ] {
        assert!(!run(&["true", &spelling]).is_empty(), "no warning for {spelling}");
    }
}

#[test]
fn off_the_allowlist_is_flagged_and_names_matter() {
    use remote_sudo_approve::policy::NOT_ALLOWLISTED;
    let r = rules();
    let e = good_env();
    let c = check(&r, &info("/usr/bin/true", &[]), &argv(&["true"]), &e).unwrap();
    assert!(c.allowlisted);
    assert!(warnings(&r, &c).is_empty());
    // Another installed program: allowed to ask, but flagged.
    let c = check(&r, &info("/usr/bin/false", &[]), &argv(&["false"]), &e).unwrap();
    assert!(!c.allowlisted);
    assert_eq!(warnings(&r, &c)[0], NOT_ALLOWLISTED);
    // The allowlisted file under another argv[0] isn't the allowlisted program.
    let c = check(&r, &info("/usr/bin/true", &[]), &argv(&["other"]), &e).unwrap();
    assert!(!c.allowlisted);
}

#[test]
fn hidden_shells_and_deploy_tools_are_refused_by_name() {
    let r = rules();
    let e = good_env();
    for name in ["newgrp", "sg", "login", "sulogin", "setarch", "linux64", "visudo", "dc", "prlimit", "setsid", "passwd",
        "nixos-rebuild", "switch-to-configuration", "nixos-enter", "python3.12", "lua5.4", "rbash", "ld-musl-x86_64.so.1"]
    {
        assert!(matches!(check(&r, &info("/usr/bin/true", &[]), &argv(&[name]), &e), Err(Refusal::DeniedProgram(_))), "{name}");
    }
    // Not a false positive any more.
    assert!(check(&r, &info("/usr/bin/true", &[]), &argv(&["node_exporter"]), &e).is_ok());
}

#[test]
fn sudo_tty_values() {
    let r = rules();
    let t = info("/usr/bin/true", &[]);
    let with = |v: &str| {
        let mut e = good_env();
        e.push(format!("SUDO_TTY={v}").into_bytes());
        check(&r, &t, &argv(&["true"]), &e)
    };
    assert!(with("/dev/pts/3").is_ok());
    assert!(with("/dev/tty1").is_ok());
    assert!(with("/dev/ttyS0").is_ok());
    assert!(with("/dev/pts/../../tmp/x").is_err());
    assert!(with("/tmp/x").is_err());
    assert!(with("/dev/pts/").is_err());
}
