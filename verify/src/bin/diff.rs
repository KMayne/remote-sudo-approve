//! remote-sudo-approve-diff <target system> [<current system>]: print what a switch
//! would change in the security-relevant files. Exit 0 if nothing, 1 if
//! something, 2 on a usage error. Automatic updates use it to refuse
//! security changes, which need a passkey-approved deploy instead.

use std::path::Path;
use std::process::ExitCode;

use remote_sudo_approve::change;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (target, current) = match args.as_slice() {
        [t] => (t.as_str(), "/run/current-system"),
        [t, c] => (t.as_str(), c.as_str()),
        _ => {
            eprintln!("usage: remote-sudo-approve-diff <target system> [<current system>]");
            return ExitCode::from(2);
        }
    };
    if !Path::new(target).join("etc").is_dir() || !Path::new(current).join("etc").is_dir() {
        eprintln!("remote-sudo-approve-diff: not a NixOS system: {target} or {current}");
        return ExitCode::from(2);
    }
    let diffs = change::security_diff(Path::new(current), Path::new(target));
    if diffs.is_empty() {
        println!("no security changes");
        return ExitCode::SUCCESS;
    }
    for (file, d) in diffs {
        println!("== {file}\n{d}\n");
    }
    ExitCode::from(1)
}
