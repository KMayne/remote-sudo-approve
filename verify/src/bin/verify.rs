//! remote-sudo-approve-verify: run by the sudo plugin for each command of a gated
//! user, as the `remote-sudo-approve` account. Reads the framed message on stdin,
//! applies the rules, asks for approval through the relay and checks the
//! passkey's signature. Exit 0 means approved; anything else denies.
//!
//! Messages for the person at the terminal go to stderr.

use std::io::Read;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use remote_sudo_approve::config::Config;
use remote_sudo_approve::policy::{self, Rules};
use remote_sudo_approve::request::{self, Change, Request};
use remote_sudo_approve::webauthn::{Assertion, RelyingParty};
use remote_sudo_approve::{change, frame, relay};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("remote-sudo-approve: denied: {why}");
            ExitCode::from(1)
        }
    }
}

fn now() -> Result<u64, String> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| "clock before 1970")?.as_secs())
}

fn run() -> Result<(), String> {
    let mut input = Vec::new();
    std::io::stdin()
        .take(frame::MAX_TOTAL as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|e| format!("reading request: {e}"))?;
    let msg = frame::decode(&input).map_err(|e| format!("bad message from plugin: {}", e.0))?;

    let cfg = Config::load()?;
    let user_info = strings(&msg.user_info)?;
    let get = |k: &str| user_info.iter().find_map(|s| s.strip_prefix(k)).map(str::to_owned);
    let user = get("user=").ok_or("no user in user_info")?;
    let uid: u32 = get("uid=").and_then(|s| s.parse().ok()).ok_or("no uid in user_info")?;
    let mut gids: Vec<u32> = get("groups=").unwrap_or_default().split(',').filter_map(|g| g.parse().ok()).collect();
    if let Some(g) = get("gid=").and_then(|s| s.parse().ok()) {
        gids.push(g);
    }

    let rules = Rules {
        trusted: cfg.trusted()?,
        env: cfg.env_rules(),
        allowed: cfg.allowed()?,
        required_info: cfg.required_info.clone(),
        runas_uid: 0,
        user_uid: uid,
        user_gids: gids,
    };
    let command_info = strings(&msg.command_info)?;
    let checked = policy::check(&rules, &command_info, &msg.run_argv, &msg.run_envp).map_err(|r| format!("{r:?}"))?;
    let warnings = policy::warnings(&rules, &checked);

    // A deploy: say what it changes in the files that decide who gets root.
    let change = if cfg.switch_program.as_deref() == Some(checked.command.as_str()) {
        let [_, target] = checked.argv.as_slice() else { return Err("the deploy command takes exactly one system path".into()) };
        if !change::is_system_path(target) {
            return Err("not a system store path".into());
        }
        let t = std::path::Path::new(target);
        if !t.join("bin/switch-to-configuration").is_file() {
            return Err(format!("{target} isn't a NixOS system on this machine (fetch it first)"));
        }
        Some(Change { system: target.clone(), diffs: change::security_diff(std::path::Path::new("/run/current-system"), t) })
    } else {
        None
    };

    let created = now()?;
    let req = Request {
        id: request::new_id().map_err(|e| format!("random: {e}"))?,
        host: cfg.host.clone(),
        user,
        runas: "root".into(),
        command: checked.command.clone(),
        argv: checked.argv.clone(),
        env: checked.env.clone(),
        cwd: checked.cwd.clone(),
        // The plugin replaces a gated user's stdin with /dev/null.
        stdin: "null".into(),
        created,
        expires: created + cfg.expiry_seconds,
        change,
        warnings,
    };
    let challenge = req.challenge();

    let token = std::fs::read_to_string(&cfg.token_file).map_err(|e| format!("{}: {e}", cfg.token_file.display()))?;
    let client = relay::Client::new(&cfg.relay, token.trim());
    client.submit(&req.id, &req.canonical())?;
    eprintln!("remote-sudo-approve: waiting up to {} s for approval: {}/#{}", cfg.expiry_seconds, cfg.origin, req.id);

    let result = wait_for_approval(&cfg, &client, &req, &challenge);
    client.withdraw(&req.id);
    result
}

fn wait_for_approval(cfg: &Config, client: &relay::Client, req: &Request, challenge: &[u8; 32]) -> Result<(), String> {
    let rp = RelyingParty { rp_id: &cfg.rp_id, origin: &cfg.origin, credentials: &cfg.credentials };
    let mut from = 0;
    loop {
        let t = now()?;
        if t >= req.expires {
            return Err("timed out".into());
        }
        let batch = client.poll(&req.id, from, Duration::from_secs((req.expires - t).min(25)))?;
        from = batch.next;
        if batch.assertions.is_empty() {
            // A relay that answers at once with nothing must not spin us.
            std::thread::sleep(Duration::from_millis(500));
        }
        for raw in batch.assertions {
            // Anyone can post an assertion; each is checked on its own.
            let Ok(a) = serde_json::from_value::<Assertion>(raw) else { continue };
            match rp.verify(&a, challenge) {
                Ok(cred) => {
                    if now()? >= req.expires {
                        return Err("approved too late".into());
                    }
                    eprintln!("remote-sudo-approve: approved by {} (key {})", cred.name, cred.fingerprint());
                    return Ok(());
                }
                Err(r) => eprintln!("remote-sudo-approve: ignoring an assertion that doesn't verify ({r:?})"),
            }
        }
    }
}

fn strings(items: &[Vec<u8>]) -> Result<Vec<String>, String> {
    items.iter().map(|b| String::from_utf8(b.clone()).map_err(|_| "non-UTF-8 input".to_owned())).collect()
}
