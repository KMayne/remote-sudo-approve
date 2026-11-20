//! The verifier's configuration: a root-owned JSON file at a fixed path,
//! written by the NixOS module. Nothing here comes from the gated user.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use serde::Deserialize;

use crate::policy::{EnvRule, Trusted};
use crate::webauthn::Credential;

pub const PATH: &str = "/etc/remote-sudo-approve/config.json";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// This machine's name, as shown on the approval page.
    pub host: String,
    pub rp_id: String,
    pub origin: String,
    /// The relay API base URL, e.g. https://approve.example.ts.net
    pub relay: String,
    /// File holding this host's bearer token for the relay (readable only
    /// by the verifier's account).
    pub token_file: PathBuf,
    pub credentials: Vec<Credential>,
    pub trusted: TrustedConfig,
    pub env: HashMap<String, EnvConfig>,
    /// File of "name<TAB>real path" lines: the allowlist.
    pub allowed_file: Option<PathBuf>,
    /// command_info keys that must have exactly these values.
    #[serde(default)]
    pub required_info: HashMap<String, String>,
    /// The deploy command's real path. A request to run it carries the
    /// security diff between the running system and its argument.
    pub switch_program: Option<String>,
    #[serde(default = "default_expiry")]
    pub expiry_seconds: u64,
}

fn default_expiry() -> u64 {
    120
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TrustedConfig {
    /// A file listing the installed programs' real paths, one per line.
    ProgramsFile(PathBuf),
    RootOwnedUnder(Vec<PathBuf>),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum EnvConfig {
    Exact(String),
    OneOf(Vec<String>),
    Locale,
    Term,
    PrintableAscii,
    Tty,
}

impl Config {
    pub fn load() -> Result<Config, String> {
        // Tests point a debug build elsewhere; release builds always read
        // the fixed path (and the plugin gives the verifier no environment).
        #[cfg(debug_assertions)]
        let path = std::env::var("REMOTE_SUDO_APPROVE_TEST_CONFIG").unwrap_or_else(|_| PATH.to_owned());
        #[cfg(not(debug_assertions))]
        let path = PATH.to_owned();
        let text = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
        serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))
    }

    pub fn trusted(&self) -> Result<Trusted, String> {
        Ok(match &self.trusted {
            TrustedConfig::ProgramsFile(p) => {
                let text = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
                let set: HashSet<String> = text.lines().map(str::trim).filter(|l| l.starts_with('/')).map(str::to_owned).collect();
                if set.is_empty() {
                    return Err(format!("{}: no programs", p.display()));
                }
                Trusted::Files(set)
            }
            TrustedConfig::RootOwnedUnder(d) => Trusted::RootOwnedUnder(d.clone()),
        })
    }

    pub fn allowed(&self) -> Result<Vec<(String, String)>, String> {
        let Some(p) = &self.allowed_file else { return Ok(Vec::new()) };
        let text = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
        Ok(text.lines().filter_map(|l| l.split_once('\t')).map(|(n, r)| (n.to_owned(), r.to_owned())).collect())
    }

    pub fn env_rules(&self) -> HashMap<String, EnvRule> {
        self.env
            .iter()
            .map(|(k, v)| {
                let r = match v {
                    EnvConfig::Exact(x) => EnvRule::Exact(x.clone()),
                    EnvConfig::OneOf(x) => EnvRule::OneOf(x.clone()),
                    EnvConfig::Locale => EnvRule::Locale,
                    EnvConfig::Term => EnvRule::Term,
                    EnvConfig::PrintableAscii => EnvRule::PrintableAscii,
                    EnvConfig::Tty => EnvRule::Tty,
                };
                (k.clone(), r)
            })
            .collect()
    }
}
