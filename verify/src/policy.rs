//! What must hold before a command is even sent for approval, and the
//! warnings shown with it. Inputs are sudo's `command_info`, `run_argv` and
//! `run_envp` for the execution (sudo_plugin(5)), never anything the user
//! typed or set in its own environment.
//!
//! Everything here refuses by default: an unknown `command_info` key, an
//! environment variable not on the list, a program outside the trusted set.

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

/// Limits on what can be approved at all.
pub const MAX_ARGS: usize = 64;
pub const MAX_ARG_BYTES: usize = 4096;

/// How to decide that a program file is part of the trusted system.
#[derive(Debug, Clone)]
pub enum Trusted {
    /// NixOS: the real path must be exactly one of these files: the real
    /// targets of the installed programs (/run/current-system/sw/{bin,sbin}),
    /// listed at build time. Not their dependencies.
    Files(std::collections::HashSet<String>),
    /// Elsewhere: the real path must be under one of these directories, and
    /// it and every directory above it must be root-owned and not writable
    /// by group or others.
    RootOwnedUnder(Vec<PathBuf>),
}

/// Environment rules: for each allowed name, the allowed values.
#[derive(Debug, Clone)]
pub enum EnvRule {
    /// Exactly this value.
    Exact(String),
    /// Any of these values.
    OneOf(Vec<String>),
    /// A locale name: letters, digits, `_`, `.`, `-` and one optional `@`
    /// modifier; never a path.
    Locale,
    /// A terminal type: [a-z0-9.+-], at most 32 characters.
    Term,
    /// Any value made only of printable ASCII (SUDO_COMMAND and the like,
    /// which sudo sets itself and the program sees as data).
    PrintableAscii,
    /// A terminal device: /dev/pts/N, /dev/ttyN or /dev/ttySN (SUDO_TTY).
    Tty,
}

#[derive(Debug, Clone)]
pub struct Rules {
    pub trusted: Trusted,
    pub env: HashMap<String, EnvRule>,
    /// The allowlist: (name, real path) of programs approved for routine
    /// use. Anything else trusted can still be requested, with a warning.
    pub allowed: Vec<(String, String)>,
    /// `command_info` keys that must be present with exactly this value
    /// (umask and every rlimit, which would otherwise be the invoker's).
    pub required_info: HashMap<String, String>,
    /// Who the command may run as; only root for now.
    pub runas_uid: u32,
    /// The uid and gids of the gated user, for the "writable by" warnings.
    pub user_uid: u32,
    pub user_gids: Vec<u32>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    MissingKey(&'static str),
    UnexpectedKey(String),
    BadValue(String),
    Sudoedit,
    RelativeCommand,
    CommandUnresolvable(String),
    UntrustedProgram(String),
    DeniedProgram(String),
    EnvNotAllowed(String),
    EnvBadValue(String),
    TooManyArgs,
    ArgsTooLong,
    NotUtf8,
    EmptyArgv,
}

/// The parts of an execution that are approved, once checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    /// The real path of the program.
    pub command: String,
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: String,
    /// The target user's uid (always `rules.runas_uid`).
    pub runas_uid: u32,
    /// Whether the program, under the name it is run as, is on the allowlist.
    pub allowlisted: bool,
}

/// Programs that are refused whatever the arguments: shells, interpreters,
/// launchers, and interactive programs that can run commands. Matched on the
/// file name of the real path, after stripping a NixOS `.<name>-wrapped`.
const DENIED: &[&str] = &[
    "sh", "bash", "dash", "zsh", "fish", "ksh", "mksh", "tcsh", "csh", "nu", "elvish", "xonsh",
    "python", "perl", "ruby", "node", "deno", "bun", "lua", "luajit", "php", "tclsh", "wish",
    "guile", "racket", "ghci", "irb", "awk", "gawk", "mawk", "nawk", "sed", "env", "nice",
    "nohup", "timeout", "xargs", "find", "parallel", "watch", "sudo", "sudoedit", "su", "doas",
    "pkexec", "run0", "systemd-run", "machinectl", "nsenter", "unshare", "chroot", "setpriv",
    "capsh", "runuser", "busybox", "toybox", "script", "expect", "screen", "tmux", "gdb", "lldb",
    "strace", "ltrace", "valgrind", "vi", "vim", "nvim", "view", "vimdiff", "nano", "pico",
    "emacs", "ed", "ex", "joe", "mcedit", "micro", "less", "more", "most", "pg", "man", "info",
    "mc", "ranger", "nix", "make", "ssh", "scp", "sftp", "rsync", "socat", "nc", "ncat",
    "openssl", "dbus-send", "busctl", "flock", "stdbuf", "taskset", "ionice", "chrt", "time",
    "ld.so", "ld-linux-aarch64.so.1", "ld-linux-x86-64.so.2", "ld-linux-armhf.so.3", "ld-linux.so.2",
    "pip", "pip3", "git", "rbash", "ash", "pypy",
    // Start a shell or a login with no command in sight (security review).
    "newgrp", "sg", "login", "sulogin", "agetty", "getty", "systemd-sulogin-shell", "openvt",
    "setsid", "setarch", "linux32", "linux64", "i386", "x86_64", "uname26", "aarch64", "arch",
    "visudo", "vipw", "vigr", "dc", "bc", "prlimit", "scriptlive", "scriptreplay", "ldd", "sotruss",
    "coredumpctl", "ssh-agent", "sqlite3", "m4", "psql", "fakeroot", "choom", "uclampset",
    "coresched", "runcon", "systemd-inhibit", "systemd-cat", "systemd-socket-activate",
    "systemd-nspawn", "dbus-run-session", "dbus-launch", "npx", "npm",
    // Change root's credentials, after which su needs no approval.
    "passwd", "chpasswd", "chsh", "usermod", "useradd", "gpasswd",
    // Deploys: only through the guarded deploy command (DESIGN.md).
    "switch-to-configuration",
];

/// Prefixes that are refused (`nix-shell`, `nixos-rebuild`, `ld-musl-…`).
/// Versioned interpreters (`python3.12`, `lua5.4`) are caught by stripping
/// trailing digits and dots instead, so `node_exporter` isn't.
const DENIED_PREFIXES: &[&str] = &["nix-", "nixos-", "ld-musl-"];

/// `command_info` keys that may appear, and what's allowed in each. Anything
/// else refuses the command.
fn check_info_key(key: &str, value: &str, runas_uid: u32) -> Result<(), Refusal> {
    let uid = runas_uid.to_string();
    let ok = match key {
        // Checked separately.
        "command" | "cwd" => true,
        "runas_uid" | "runas_euid" => value == uid,
        "runas_gid" | "runas_egid" => value == "0",
        // Root's supplementary groups, from the group database.
        "runas_groups" => value.split(',').all(|g| g.parse::<u32>().is_ok()),
        "runas_user" => value == "root",
        // sudo prints it as "0%o": 022, 077, 0...
        "umask" => (2..=4).contains(&value.len()) && value.starts_with('0') && value.chars().all(|c| ('0'..='7').contains(&c)),
        "closefrom" => value.parse::<u32>().map(|n| n <= 3).unwrap_or(false),
        // Restrictions and logging; none of them changes what runs.
        "umask_override" | "noexec" | "use_pty" | "set_utmp" | "exec_background" | "intercept" | "intercept_verify"
        | "use_ptrace" | "log_subcmds" | "ignore_iolog_errors" | "iolog_compress" | "iolog_flush"
        | "iolog_stdin" | "iolog_stdout" | "iolog_stderr" | "iolog_ttyin" | "iolog_ttyout"
        | "log_passwords" | "log_server_keepalive" | "log_server_verify" => value == "true" || value == "false",
        "utmp_user" | "iolog_user" | "iolog_group" | "iolog_mode" | "iolog_path" | "maxseq"
        | "log_server_timeout" | "log_server_cabundle" | "log_server_peer_cert"
        | "log_server_peer_key" | "debug_flags" | "plugin_path" | "source" => true,
        // Resource limits: allowed if set by sudoers, never "user".
        k if k.starts_with("rlimit_") => !value.split(',').any(|v| v == "user"),
        // Refused: they change how or where the program runs.
        "sudoedit" => return Err(Refusal::Sudoedit),
        _ => return Err(Refusal::UnexpectedKey(key.to_owned())),
    };
    if ok {
        Ok(())
    } else {
        Err(Refusal::BadValue(format!("{key}={value}")))
    }
}

pub fn check(
    rules: &Rules,
    command_info: &[String],
    run_argv: &[Vec<u8>],
    run_envp: &[Vec<u8>],
) -> Result<Checked, Refusal> {
    // command_info: every key known and acceptable.
    let mut command = None;
    let mut cwd = None;
    let mut runas = None;
    let mut seen = std::collections::HashSet::new();
    for kv in command_info {
        let (k, v) = kv.split_once('=').ok_or_else(|| Refusal::BadValue(kv.clone()))?;
        if !seen.insert(k) {
            return Err(Refusal::BadValue(format!("{k} given twice")));
        }
        check_info_key(k, v, rules.runas_uid)?;
        match k {
            "command" => command = Some(v),
            "cwd" => cwd = Some(v),
            "runas_uid" => runas = Some(v),
            _ => {}
        }
    }
    for (k, want) in &rules.required_info {
        let have = command_info.iter().find_map(|kv| kv.strip_prefix(k.as_str()).and_then(|r| r.strip_prefix('=')));
        if have != Some(want.as_str()) {
            return Err(Refusal::BadValue(format!("{k} must be {want}, is {}", have.unwrap_or("absent"))));
        }
    }
    let command = command.ok_or(Refusal::MissingKey("command"))?;
    // sudoers sets cwd from runcwd; without it the command would run in the
    // caller's directory.
    let cwd = cwd.ok_or(Refusal::MissingKey("cwd"))?;
    if cwd != "/" {
        return Err(Refusal::BadValue(format!("cwd={cwd}")));
    }
    runas.ok_or(Refusal::MissingKey("runas_uid"))?;

    // The program: an absolute path whose real path is trusted and allowed.
    if !command.starts_with('/') {
        return Err(Refusal::RelativeCommand);
    }
    // sudo execs `command` as given, so every hop from it to the real file
    // must be out of the agent's reach, or a symlink could be repointed
    // between approval and exec.
    let (real, names) = resolve_with_names(Path::new(command))?;
    trusted(&rules.trusted, &real)?;
    let real_shown = real.display().to_string();
    let real = real.to_str().ok_or(Refusal::NotUtf8)?.to_owned();

    // Arguments.
    if run_argv.is_empty() {
        return Err(Refusal::EmptyArgv);
    }
    if run_argv.len() > MAX_ARGS {
        return Err(Refusal::TooManyArgs);
    }
    if run_argv.iter().map(Vec::len).sum::<usize>() > MAX_ARG_BYTES {
        return Err(Refusal::ArgsTooLong);
    }
    let argv = run_argv
        .iter()
        .map(|a| String::from_utf8(a.clone()).map_err(|_| Refusal::NotUtf8))
        .collect::<Result<Vec<_>, _>>()?;

    // The deny list, on every name the program is known by: each symlink
    // followed, the real file, and argv[0] (which multi-call binaries use to
    // pick what to be). coreutils can also be told by an option.
    let argv0 = Path::new(&argv[0]).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    for n in names.iter().chain(std::iter::once(&argv0)) {
        if denied_name(n) {
            return Err(Refusal::DeniedProgram(format!("{real_shown} (as {n})")));
        }
    }
    if argv.iter().skip(1).any(|a| a.starts_with("--coreutils-prog")) {
        return Err(Refusal::DeniedProgram(format!("{real_shown} --coreutils-prog")));
    }

    // Environment: every variable allowed by name and value.
    let mut env = Vec::with_capacity(run_envp.len());
    for e in run_envp {
        let e = std::str::from_utf8(e).map_err(|_| Refusal::NotUtf8)?;
        let (k, v) = e.split_once('=').ok_or_else(|| Refusal::EnvBadValue(e.to_owned()))?;
        let rule = rules.env.get(k).ok_or_else(|| Refusal::EnvNotAllowed(k.to_owned()))?;
        if !env_ok(rule, v) {
            return Err(Refusal::EnvBadValue(format!("{k}={v}")));
        }
        env.push((k.to_owned(), v.to_owned()));
    }

    // On the allowlist only under the allowed name: a multi-call binary
    // shares one real file between many programs.
    let run_as = Path::new(command).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let allowlisted = rules.allowed.iter().any(|(name, path)| *path == real && *name == run_as && *name == argv0);

    Ok(Checked { command: real, argv, env, cwd: cwd.to_owned(), runas_uid: rules.runas_uid, allowlisted })
}

fn env_ok(rule: &EnvRule, v: &str) -> bool {
    match rule {
        EnvRule::Exact(x) => v == x,
        EnvRule::OneOf(xs) => xs.iter().any(|x| x == v),
        EnvRule::Locale => {
            !v.is_empty()
                && v.len() <= 64
                && v.matches('@').count() <= 1
                && v.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '@'))
                && !v.contains("..")
        }
        EnvRule::Term => {
            !v.is_empty()
                && v.len() <= 32
                && v.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '+' | '-'))
        }
        EnvRule::PrintableAscii => v.bytes().all(|b| (0x20..0x7f).contains(&b)),
        EnvRule::Tty => ["/dev/pts/", "/dev/ttyS", "/dev/tty"]
            .iter()
            .any(|p| v.strip_prefix(p).is_some_and(|n| !n.is_empty() && n.len() <= 5 && n.bytes().all(|b| b.is_ascii_digit()))),
    }
}

fn trusted(t: &Trusted, real: &Path) -> Result<(), Refusal> {
    let shown = || real.display().to_string();
    match t {
        Trusted::Files(files) => match real.to_str() {
            Some(r) if files.contains(r) => Ok(()),
            _ => Err(Refusal::UntrustedProgram(shown())),
        },
        Trusted::RootOwnedUnder(dirs) => {
            if !dirs.iter().any(|d| real.starts_with(d)) {
                return Err(Refusal::UntrustedProgram(shown()));
            }
            // The file and every directory above it.
            for p in real.ancestors() {
                let m = std::fs::metadata(p).map_err(|_| Refusal::UntrustedProgram(shown()))?;
                if m.uid() != 0 || m.mode() & 0o022 != 0 {
                    return Err(Refusal::UntrustedProgram(shown()));
                }
            }
            Ok(())
        }
    }
}

/// Resolve an absolute path one component at a time, following symlinks,
/// and require that nothing on the way can be changed by anyone but root:
/// every directory looked in is root-owned and not group- or
/// world-writable, and every symlink followed is root-owned. Returns the
/// real path. (The final file's own mode is checked by `trusted`.)
pub fn resolve_root_owned(path: &Path) -> Result<PathBuf, Refusal> {
    resolve_with_names(path).map(|(p, _)| p)
}

/// As `resolve_root_owned`, also returning the name of every symlink
/// followed and of the final file: a multi-call binary (coreutils) picks
/// its behaviour by the name it was run as, so all of them are checked.
pub fn resolve_with_names(path: &Path) -> Result<(PathBuf, Vec<String>), Refusal> {
    let mut names = Vec::new();
    let shown = || path.display().to_string();
    let untrusted = |why: String| Refusal::UntrustedProgram(format!("{}: {why}", path.display()));
    let mut hops = 0;
    // Components still to walk, front first.
    let mut todo: Vec<std::ffi::OsString> = Vec::new();
    push_components(&mut todo, path).ok_or_else(|| Refusal::CommandUnresolvable(shown()))?;
    let mut cur = PathBuf::from("/");
    while let Some(name) = todo.pop() {
        if name == ".." {
            cur.pop();
            continue;
        }
        // The directory we're looking in decides who can change this entry.
        let dir = std::fs::metadata(&cur).map_err(|e| untrusted(format!("{}: {e}", cur.display())))?;
        let next = cur.join(&name);
        let m = std::fs::symlink_metadata(&next).map_err(|e| Refusal::CommandUnresolvable(format!("{}: {e}", next.display())))?;
        // A group-writable directory is acceptable only if it's sticky and
        // the entry is root's (only an entry's owner can replace it there):
        // that is /nix/store, writable by the nixbld build users.
        let group_ok = dir.mode() & 0o020 == 0 || (dir.mode() & 0o1000 != 0 && m.uid() == 0);
        if dir.uid() != 0 || dir.mode() & 0o002 != 0 || !group_ok {
            return Err(untrusted(format!("{} is not root-only", cur.display())));
        }
        if m.file_type().is_symlink() {
            names.push(name.to_string_lossy().into_owned());
            if m.uid() != 0 {
                return Err(untrusted(format!("symlink {} is not root's", next.display())));
            }
            hops += 1;
            if hops > 40 {
                return Err(Refusal::CommandUnresolvable(shown()));
            }
            let target = std::fs::read_link(&next).map_err(|e| Refusal::CommandUnresolvable(format!("{}: {e}", next.display())))?;
            if target.is_absolute() {
                cur = PathBuf::from("/");
            }
            push_components(&mut todo, &target).ok_or_else(|| Refusal::CommandUnresolvable(shown()))?;
        } else {
            cur = next;
        }
    }
    if let Some(n) = cur.file_name() {
        names.push(n.to_string_lossy().into_owned());
    }
    Ok((cur, names))
}

/// Push a path's normal components onto `todo` so they pop in order. None
/// for anything unexpected (prefixes).
fn push_components(todo: &mut Vec<std::ffi::OsString>, p: &Path) -> Option<()> {
    let mut parts = Vec::new();
    for c in p.components() {
        match c {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => parts.push(std::ffi::OsString::from("..")),
            Component::Normal(n) => parts.push(n.to_owned()),
            Component::Prefix(_) => return None,
        }
    }
    todo.extend(parts.into_iter().rev());
    Some(())
}

fn denied_name(name: &str) -> bool {
    // NixOS wraps programs as `.foo-wrapped`, possibly twice.
    let mut base = name;
    while let Some(inner) = base.strip_prefix('.').and_then(|s| s.strip_suffix("-wrapped")) {
        base = inner;
    }
    let lower = base.to_ascii_lowercase();
    // Versioned names: python3.12, perl5.38.2, lua5.4 ...
    let stem = lower.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    DENIED.contains(&lower.as_str()) || DENIED.contains(&stem) || DENIED_PREFIXES.iter().any(|p| lower.starts_with(p))
}

/// Shown first when the program isn't on the machine's allowlist.
pub const NOT_ALLOWLISTED: &str =
    "NOT ON THE ALLOWLIST: this program may give a root shell or do far more than its arguments show";

/// Warnings for things the approver must know: a program off the allowlist,
/// and arguments naming files the gated user can write (their content can
/// change after approval). stdin is always /dev/null for gated users (the
/// plugin sees to it), so it needs no warning.
pub fn warnings(rules: &Rules, c: &Checked) -> Vec<String> {
    let mut w = Vec::new();
    if !c.allowlisted {
        w.push(NOT_ALLOWLISTED.to_owned());
    }
    for (i, arg) in c.argv.iter().enumerate().skip(1) {
        for p in paths_in(arg) {
            if let Some(why) = risky_path(rules, &p) {
                w.push(format!("argv[{i}]: {} {why}", crate::request::escape(&p)));
            }
        }
    }
    w
}

/// Every path an argument might name, as an absolute path (the command runs
/// in /). The argument is cut at `=`, `:`, `,` and `@`; `file://` and a
/// short option letter (`-f/tmp/x`) are stripped; what's left is taken as a
/// path, relative to / if it doesn't start with one. Over-inclusive on
/// purpose: a candidate that names nothing the agent can write is silent.
fn paths_in(arg: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |cand: &str| {
        let cand = cand.strip_prefix("file://").unwrap_or(cand);
        if cand.is_empty() || cand.starts_with('-') || cand.contains('\0') {
            return;
        }
        let abs = if cand.starts_with('/') { cand.to_owned() } else { format!("/{cand}") };
        if !out.contains(&abs) {
            out.push(abs);
        }
    };
    let body = arg.trim_start_matches('-');
    for whole in [arg, body] {
        add(whole);
    }
    // -f/tmp/x, -fvalue
    if arg.starts_with('-') && !arg.starts_with("--") && arg.len() > 2 {
        add(&arg[2..]);
    }
    for piece in body.split(['=', ':', ',', '@']) {
        add(piece);
    }
    // Everything after each separator, so "a=b=/x" and "h:/x:/y" are seen whole too.
    for (i, ch) in body.char_indices() {
        if matches!(ch, '=' | ':' | ',' | '@') {
            add(&body[i + 1..]);
        }
    }
    out
}

fn risky_path(rules: &Rules, p: &str) -> Option<String> {
    for special in ["/dev/fd", "/dev/stdin", "/dev/stdout", "/dev/stderr", "/proc", "/run/user"] {
        if p == special || p.starts_with(&format!("{special}/")) {
            return Some("names a file descriptor, process or user runtime path".to_owned());
        }
    }
    // The longest prefix that exists. Only "not found" means it doesn't
    // exist: any other error (the verifier isn't root) means we can't tell.
    let path = Path::new(p);
    let mut existing = None;
    for a in path.ancestors() {
        match std::fs::symlink_metadata(a) {
            Ok(_) => {
                existing = Some(a);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                // Not ours to look into. If what stops us is a directory
                // only root can enter, the agent can't get in either.
                let blocked_by_root_only = a.ancestors().skip(1).find_map(|d| std::fs::symlink_metadata(d).ok()).is_some_and(|m| m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0);
                return if blocked_by_root_only { None } else { Some("can't be inspected".to_owned()) };
            }
        }
    }
    let existing = existing?;
    let real = match std::fs::canonicalize(existing) {
        Ok(r) => r,
        Err(_) => return Some("can't be inspected".to_owned()),
    };
    // If the agent can write the file, where it would be created, or any
    // directory above it, the content can change after approval.
    for a in real.ancestors() {
        match std::fs::symlink_metadata(a) {
            Ok(m) => {
                if writable_by(&m, rules.user_uid, &rules.user_gids) || has_acl(a) {
                    return Some(format!("is writable by the agent (via {})", crate::request::escape(&a.display().to_string())));
                }
            }
            Err(_) => return Some("can't be inspected".to_owned()),
        }
    }
    None
}

fn writable_by(m: &std::fs::Metadata, uid: u32, gids: &[u32]) -> bool {
    let mode = m.mode();
    (m.uid() == uid && mode & 0o200 != 0)
        || (gids.contains(&m.gid()) && mode & 0o020 != 0)
        || mode & 0o002 != 0
        // The owner can always chmod it.
        || m.uid() == uid
}

/// A POSIX ACL could grant write access the mode doesn't show; treat any as
/// risky rather than parse it.
fn has_acl(p: &Path) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = CString::new(p.as_os_str().as_bytes()) else { return true };
    let name = c"system.posix_acl_access";
    // SAFETY: valid C strings; a null buffer of size 0 asks only for the size.
    let r = unsafe { libc_lgetxattr(c.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    r >= 0
}

extern "C" {
    #[link_name = "lgetxattr"]
    fn libc_lgetxattr(path: *const std::ffi::c_char, name: *const std::ffi::c_char, value: *mut std::ffi::c_void, size: usize) -> isize;
}
