//! The verifier's side of the relay API. The relay is untrusted: it can
//! refuse, delay or return garbage, all of which end in denial.
//!
//! ```text
//! POST /v1/requests                         body: the request (JSON), bearer
//! GET  /v1/requests/<id>/assertions?from=N  long-poll, bearer
//!      → {"assertions": [ ... ], "next": M}
//! ```

use std::io::Read;
use std::time::Duration;

use serde::Deserialize;

pub struct Client {
    base: String,
    auth: String,
    agent: ureq::Agent,
}

#[derive(Debug, Deserialize)]
pub struct Batch {
    pub assertions: Vec<serde_json::Value>,
    pub next: usize,
}

/// At most this many assertions are looked at per request id, so a flood
/// of junk can't keep the verifier busy.
const MAX_ASSERTIONS: usize = 64;
const MAX_REPLY: u64 = 1 << 20;

impl Client {
    pub fn new(base: &str, token: &str) -> Client {
        let agent = ureq::AgentBuilder::new().timeout_connect(Duration::from_secs(10)).redirects(0).build();
        Client { base: base.trim_end_matches('/').to_owned(), auth: format!("Bearer {token}"), agent }
    }

    pub fn submit(&self, id: &str, canonical: &str) -> Result<(), String> {
        let r = self
            .agent
            .post(&format!("{}/v1/requests", self.base))
            .timeout(Duration::from_secs(15))
            .set("Authorization", &self.auth)
            .set("Content-Type", "application/json")
            .send_string(canonical);
        let _ = id;
        match r {
            Ok(resp) if resp.status() == 201 => Ok(()),
            Ok(resp) => Err(format!("relay refused the request ({})", resp.status())),
            Err(e) => Err(format!("relay: {}", short(&e))),
        }
    }

    /// Withdraw a decided request (best effort).
    pub fn withdraw(&self, id: &str) {
        let _ = self
            .agent
            .delete(&format!("{}/v1/requests/{id}", self.base))
            .timeout(Duration::from_secs(5))
            .set("Authorization", &self.auth)
            .call();
    }

    /// Assertions the relay holds from index `from` on. `Batch::next` is
    /// always `from` plus the number returned, whatever the relay says.
    pub fn poll(&self, id: &str, from: usize, wait: Duration) -> Result<Batch, String> {
        if from >= MAX_ASSERTIONS {
            return Err("too many assertions".into());
        }
        let r = self
            .agent
            .get(&format!("{}/v1/requests/{id}/assertions", self.base))
            .query("from", &from.to_string())
            .query("wait", &wait.as_secs().to_string())
            .timeout(wait + Duration::from_secs(10))
            .set("Authorization", &self.auth)
            .call();
        let resp = r.map_err(|e| format!("relay: {}", short(&e)))?;
        let mut text = String::new();
        resp.into_reader().take(MAX_REPLY + 1).read_to_string(&mut text).map_err(|e| format!("relay: {e}"))?;
        if text.len() as u64 > MAX_REPLY {
            return Err("relay reply too long".into());
        }
        let mut b: Batch = serde_json::from_str(&text).map_err(|_| "relay reply isn't valid".to_owned())?;
        b.assertions.truncate(MAX_ASSERTIONS - from);
        b.next = from + b.assertions.len();
        Ok(b)
    }
}

fn short(e: &ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, _) => format!("status {code}"),
        ureq::Error::Transport(t) => t.kind().to_string(),
    }
}
