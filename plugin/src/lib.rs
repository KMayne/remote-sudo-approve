//! sudo approval plugin: every command of a gated user needs the verifier's
//! OK (sudo_plugin(5), "Approval plugin API"; sudo >= 1.9).
//!
//! sudo.conf:
//!
//! ```text
//! Plugin sudoers_policy sudoers.so
//! Plugin remote_sudo_approve /nix/store/…/lib/libremote_sudo_approve_plugin.so \
//!     verifier=/nix/store/…/bin/remote-sudo-approve-verify run_as=remote-sudo-approve \
//!     ungated_uids=0,1000
//! ```
//!
//! Security notes (see DESIGN.md):
//!
//! - sudo calls `open` inside its per-command approval check and skips the
//!   plugin unless `open` returns exactly 1 (0 means "disable me"). So `open`
//!   returns 0 only for an ungated uid, decided with no allocation, and 1 for
//!   everyone else whatever happens; errors surface as `check` returning 0.
//! - `check` approves (1) only if the verifier exits 0 before the deadline.
//!   Everything else, including any error here, is 0.
//! - Nothing here may panic: the crate is built with panic=abort, so a panic
//!   would kill sudo. The ungated path is index- and allocation-free.

use std::ffi::{c_char, c_int, c_uint, CStr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const SUDO_APPROVAL_PLUGIN: c_uint = 4;
const SUDO_API_VERSION: c_uint = (1 << 16) | 22;
/// Approval must complete within this, measured on the monotonic clock
/// from the start of `check` (the verifier's own expiry is 120 s).
const DEADLINE: Duration = Duration::from_secs(125);
/// At most this many uids may be listed as ungated.
const MAX_UNGATED: usize = 8;

type ConvT = *const std::ffi::c_void;
type PrintfT = *const std::ffi::c_void;

type OpenFn = unsafe extern "C" fn(
    c_uint,
    ConvT,
    PrintfT,
    *const *const c_char,
    *const *const c_char,
    c_int,
    *const *const c_char,
    *const *const c_char,
    *const *const c_char,
    *mut *const c_char,
) -> c_int;
type CheckFn = unsafe extern "C" fn(*const *const c_char, *const *const c_char, *const *const c_char, *mut *const c_char) -> c_int;

/// `struct approval_plugin` from sudo_plugin.h (API 1.22).
#[repr(C)]
pub struct ApprovalPlugin {
    type_: c_uint,
    version: c_uint,
    open: OpenFn,
    close: unsafe extern "C" fn(),
    check: CheckFn,
    show_version: unsafe extern "C" fn(c_int) -> c_int,
}

// SAFETY: the struct holds only function pointers and integers.
unsafe impl Sync for ApprovalPlugin {}

/// The symbol sudo looks up: the name given in sudo.conf.
#[no_mangle]
pub static remote_sudo_approve: ApprovalPlugin = ApprovalPlugin {
    type_: SUDO_APPROVAL_PLUGIN,
    version: SUDO_API_VERSION,
    open: plugin_open,
    close: plugin_close,
    check: plugin_check,
    show_version: plugin_show_version,
};

/// What `open` saw, for `check`.
struct Session {
    user_info: Vec<Vec<u8>>,
    options: Vec<Vec<u8>>,
}

static SESSION: Mutex<Option<Session>> = Mutex::new(None);

static DENIED: &CStr = c"not approved by passkey";
static ERROR: &CStr = c"passkey approval failed";

unsafe extern "C" fn plugin_open(
    _version: c_uint,
    _conv: ConvT,
    _printf: PrintfT,
    _settings: *const *const c_char,
    user_info: *const *const c_char,
    _submit_optind: c_int,
    _submit_argv: *const *const c_char,
    _submit_envp: *const *const c_char,
    options: *const *const c_char,
    _errstr: *mut *const c_char,
) -> c_int {
    // Fast path, no allocation: an ungated user disables the plugin for
    // this command. Any doubt (no uid, unparsable) means gated.
    if let Some(uid) = find_uint(user_info, b"uid=") {
        if is_ungated(options, uid) {
            return 0;
        }
    }
    // Gated: remember the inputs for check. If anything fails here we still
    // return 1; check then finds no session and denies.
    let s = Session { user_info: copy_array(user_info), options: copy_array(options) };
    if let Ok(mut g) = SESSION.lock() {
        *g = Some(s);
    }
    1
}

unsafe extern "C" fn plugin_close() {
    if let Ok(mut g) = SESSION.lock() {
        *g = None;
    }
}

unsafe extern "C" fn plugin_show_version(_verbose: c_int) -> c_int {
    1
}

unsafe extern "C" fn plugin_check(
    command_info: *const *const c_char,
    run_argv: *const *const c_char,
    run_envp: *const *const c_char,
    errstr: *mut *const c_char,
) -> c_int {
    let start = Instant::now();
    let session = match SESSION.lock() {
        Ok(mut g) => g.take(),
        Err(_) => None,
    };
    let result = match session {
        Some(s) => run_verifier(&s, command_info, run_argv, run_envp, start),
        None => Err(()),
    };
    match result {
        // Approved: the command must not read input the agent controls, so
        // its stdin becomes /dev/null (the request says so). If that can't
        // be done, deny.
        Ok(true) if start.elapsed() < DEADLINE => {
            if null_stdin() {
                1
            } else {
                set_err(errstr, ERROR);
                0
            }
        }
        Ok(_) => {
            set_err(errstr, DENIED);
            0
        }
        Err(()) => {
            set_err(errstr, ERROR);
            0
        }
    }
}

/// Replace fd 0 with /dev/null (checked to be the real null device).
unsafe fn null_stdin() -> bool {
    let fd = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
    if fd < 0 {
        return false;
    }
    let mut st: libc::stat = std::mem::zeroed();
    let ok = libc::fstat(fd, &mut st) == 0
        && (st.st_mode & libc::S_IFMT) == libc::S_IFCHR
        && st.st_rdev == libc::makedev(1, 3)
        && libc::dup2(fd, 0) == 0;
    if fd != 0 {
        libc::close(fd);
    }
    ok
}

unsafe fn set_err(errstr: *mut *const c_char, msg: &'static CStr) {
    if !errstr.is_null() {
        *errstr = msg.as_ptr();
    }
}

/// A NULL-terminated C string array as byte vectors.
unsafe fn copy_array(a: *const *const c_char) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if a.is_null() {
        return out;
    }
    let mut i = 0;
    loop {
        let p = *a.add(i);
        if p.is_null() {
            break;
        }
        if i >= 65536 {
            // Never pass on a shortened list: an entry that can't be a valid
            // setting or variable makes the verifier refuse.
            out.push(b"\xff(truncated)".to_vec());
            break;
        }
        out.push(CStr::from_ptr(p).to_bytes().to_vec());
        i += 1;
    }
    out
}

/// `key<digits>` in a C string array, parsed without allocating.
unsafe fn find_uint(a: *const *const c_char, key: &[u8]) -> Option<u32> {
    if a.is_null() {
        return None;
    }
    let mut i = 0;
    while i < 4096 {
        let p = *a.add(i);
        if p.is_null() {
            return None;
        }
        let s = CStr::from_ptr(p).to_bytes();
        if let Some(rest) = s.strip_prefix(key) {
            return parse_u32(rest);
        }
        i += 1;
    }
    None
}

fn parse_u32(s: &[u8]) -> Option<u32> {
    if s.is_empty() || s.len() > 10 {
        return None;
    }
    let mut n: u64 = 0;
    for &c in s {
        if !c.is_ascii_digit() {
            return None;
        }
        n = n * 10 + u64::from(c - b'0');
    }
    u32::try_from(n).ok()
}

/// Whether `uid` is in the `ungated_uids=` option (only root if absent).
unsafe fn is_ungated(options: *const *const c_char, uid: u32) -> bool {
    let mut list: &[u8] = b"0";
    if !options.is_null() {
        let mut i = 0;
        while i < 256 {
            let p = *options.add(i);
            if p.is_null() {
                break;
            }
            let s = CStr::from_ptr(p).to_bytes();
            if let Some(v) = s.strip_prefix(b"ungated_uids=") {
                list = v;
                break;
            }
            i += 1;
        }
    }
    let mut count = 0;
    for part in list.split(|&c| c == b',') {
        count += 1;
        if count > MAX_UNGATED {
            return false;
        }
        if parse_u32(part) == Some(uid) {
            return true;
        }
    }
    false
}

fn option<'a>(s: &'a Session, key: &[u8]) -> Option<&'a [u8]> {
    s.options.iter().find_map(|o| o.strip_prefix(key))
}

/// The framed message (verify/src/frame.rs).
fn encode(user_info: &[Vec<u8>], command_info: &[Vec<u8>], argv: &[Vec<u8>], envp: &[Vec<u8>], tty: bool) -> Vec<u8> {
    let mut o = b"SPK1".to_vec();
    for s in [user_info, command_info, argv, envp] {
        o.extend_from_slice(&(s.len() as u32).to_le_bytes());
        for item in s {
            o.extend_from_slice(&(item.len() as u32).to_le_bytes());
            o.extend_from_slice(item);
        }
    }
    o.push(tty as u8);
    o
}

unsafe fn run_verifier(
    s: &Session,
    command_info: *const *const c_char,
    run_argv: *const *const c_char,
    run_envp: *const *const c_char,
    start: Instant,
) -> Result<bool, ()> {
    let verifier = option(s, b"verifier=").ok_or(())?;
    let run_as = option(s, b"run_as=").ok_or(())?;
    if !verifier.starts_with(b"/") {
        return Err(());
    }
    let verifier = std::ffi::CString::new(verifier).map_err(|_| ())?;
    let run_as = std::ffi::CString::new(run_as).map_err(|_| ())?;

    // The verifier's account, looked up before forking.
    let pw = libc::getpwnam(run_as.as_ptr());
    if pw.is_null() {
        return Err(());
    }
    let (uid, gid) = ((*pw).pw_uid, (*pw).pw_gid);
    if uid == 0 || gid == 0 {
        return Err(());
    }

    let tty = libc::isatty(0) == 1;
    let msg = encode(&s.user_info, &copy_array(command_info), &copy_array(run_argv), &copy_array(run_envp), tty);

    let mut fds = [0 as c_int; 2];
    if libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
        return Err(());
    }
    let (rd, wr) = (fds[0], fds[1]);

    let path = verifier.as_ptr();
    let argv: [*const c_char; 2] = [path, std::ptr::null()];
    let envp: [*const c_char; 1] = [std::ptr::null()];

    let pid = libc::fork();
    if pid < 0 {
        libc::close(rd);
        libc::close(wr);
        return Err(());
    }
    if pid == 0 {
        child(rd, uid, gid, path, argv.as_ptr(), envp.as_ptr());
    }

    libc::close(rd);
    let written = write_all(wr, &msg);
    libc::close(wr);

    let status = wait_until(pid, start + DEADLINE);
    if !written {
        return Ok(false);
    }
    Ok(matches!(status, Some(st) if libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0))
}

/// In the forked child: only async-signal-safe calls; any failure exits.
unsafe fn child(rd: c_int, uid: libc::uid_t, gid: libc::gid_t, path: *const c_char, argv: *const *const c_char, envp: *const *const c_char) -> ! {
    // Default signal dispositions and an empty mask.
    let mut set: libc::sigset_t = std::mem::zeroed();
    libc::sigemptyset(&mut set);
    libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
    for sig in 1..65 {
        if sig != libc::SIGKILL && sig != libc::SIGSTOP {
            libc::signal(sig, libc::SIG_DFL);
        }
    }
    // stdin from the pipe; stdout to /dev/null; stderr stays (messages for
    // the person at the terminal).
    if libc::dup2(rd, 0) != 0 {
        libc::_exit(126);
    }
    let null = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
    if null < 0 || libc::dup2(null, 1) != 1 {
        libc::_exit(126);
    }
    // Everything else closed.
    if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) != 0 {
        libc::_exit(126);
    }
    if libc::chdir(c"/".as_ptr()) != 0 {
        libc::_exit(126);
    }
    libc::umask(0o077);
    // Limits of our own, not the invoking shell's.
    let lim = |soft: u64, hard: u64| libc::rlimit { rlim_cur: soft, rlim_max: hard };
    for (res, l) in [
        (libc::RLIMIT_CORE, lim(0, 0)),
        (libc::RLIMIT_NOFILE, lim(256, 256)),
        (libc::RLIMIT_FSIZE, lim(libc::RLIM_INFINITY, libc::RLIM_INFINITY)),
        (libc::RLIMIT_AS, lim(libc::RLIM_INFINITY, libc::RLIM_INFINITY)),
        (libc::RLIMIT_DATA, lim(libc::RLIM_INFINITY, libc::RLIM_INFINITY)),
        (libc::RLIMIT_STACK, lim(8 << 20, libc::RLIM_INFINITY)),
        (libc::RLIMIT_CPU, lim(libc::RLIM_INFINITY, libc::RLIM_INFINITY)),
    ] {
        if libc::setrlimit(res, &l) != 0 {
            libc::_exit(126);
        }
    }
    // Become the verifier's account entirely, so the agent's uid can't
    // signal or trace it.
    let groups = [gid];
    if libc::setgroups(1, groups.as_ptr()) != 0
        || libc::setresgid(gid, gid, gid) != 0
        || libc::setresuid(uid, uid, uid) != 0
        || libc::getuid() != uid
        || libc::geteuid() != uid
    {
        libc::_exit(126);
    }
    libc::execve(path, argv, envp);
    libc::_exit(127);
}

unsafe fn write_all(fd: c_int, mut b: &[u8]) -> bool {
    while !b.is_empty() {
        let n = libc::write(fd, b.as_ptr().cast(), b.len());
        if n < 0 {
            if *libc::__errno_location() == libc::EINTR {
                continue;
            }
            return false;
        }
        b = &b[n as usize..];
    }
    true
}

/// Wait for `pid` until `deadline`, killing it if it's still running then.
unsafe fn wait_until(pid: libc::pid_t, deadline: Instant) -> Option<c_int> {
    loop {
        let mut st: c_int = 0;
        let r = libc::waitpid(pid, &mut st, libc::WNOHANG);
        if r == pid {
            return Some(st);
        }
        if r < 0 && *libc::__errno_location() != libc::EINTR {
            return None;
        }
        if Instant::now() >= deadline {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, &mut st, 0);
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn arr(items: &[&str]) -> (Vec<CString>, Vec<*const c_char>) {
        let owned: Vec<CString> = items.iter().map(|s| CString::new(*s).unwrap()).collect();
        let mut ptrs: Vec<*const c_char> = owned.iter().map(|c| c.as_ptr()).collect();
        ptrs.push(std::ptr::null());
        (owned, ptrs)
    }

    unsafe fn open_with(user: &[&str], opts: Option<&[&str]>) -> c_int {
        let ui = arr(user);
        let o = opts.map(arr);
        let op = o.as_ref().map(|o| o.1.as_ptr()).unwrap_or(std::ptr::null());
        plugin_open(0, std::ptr::null(), std::ptr::null(), std::ptr::null(), ui.1.as_ptr(), 0, std::ptr::null(), std::ptr::null(), op, std::ptr::null_mut())
    }

    #[test]
    fn open_disables_only_for_ungated_uids() {
        let opts: &[&str] = &["verifier=/x", "run_as=remote-sudo-approve", "ungated_uids=0,1000"];
        unsafe {
            assert_eq!(open_with(&["user=alice", "uid=1000"], Some(opts)), 0);
            assert_eq!(open_with(&["uid=0"], Some(opts)), 0);
            assert_eq!(open_with(&["user=claude", "uid=1001"], Some(opts)), 1);
            // No uid, or a malformed one: gated.
            assert_eq!(open_with(&["user=x"], Some(opts)), 1);
            assert_eq!(open_with(&["uid=1000x"], Some(opts)), 1);
            assert_eq!(open_with(&["uid="], Some(opts)), 1);
            assert_eq!(open_with(&["uid=99999999999"], Some(opts)), 1);
            // Without the option only root is ungated.
            assert_eq!(open_with(&["uid=1000"], None), 1);
            assert_eq!(open_with(&["uid=0"], None), 0);
        }
    }

    #[test]
    fn check_without_a_session_denies() {
        unsafe { plugin_close() };
        let ci = arr(&["command=/bin/true"]);
        let r = unsafe { plugin_check(ci.1.as_ptr(), ci.1.as_ptr(), ci.1.as_ptr(), std::ptr::null_mut()) };
        assert_eq!(r, 0);
    }

    #[test]
    fn missing_or_bad_options_deny() {
        let cases: [&[&str]; 4] = [
            &[],
            &["verifier=relative", "run_as=nobody"],
            &["verifier=/bin/true", "run_as=root"],
            &["verifier=/bin/true", "run_as=no-such-user-here"],
        ];
        for opts in cases {
            let s = Session { user_info: vec![b"uid=1001".to_vec()], options: opts.iter().map(|o| o.as_bytes().to_vec()).collect() };
            let ci = arr(&["command=/bin/true"]);
            let r = unsafe { run_verifier(&s, ci.1.as_ptr(), ci.1.as_ptr(), ci.1.as_ptr(), Instant::now()) };
            assert_ne!(r, Ok(true), "{opts:?}");
        }
    }

    #[test]
    fn the_frame_matches_the_verifiers_decoder_layout() {
        let m = encode(&[b"uid=1".to_vec()], &[b"command=/x".to_vec()], &[b"x".to_vec()], &[], true);
        assert_eq!(&m[..4], b"SPK1");
        assert_eq!(*m.last().unwrap(), 1);
    }
}
