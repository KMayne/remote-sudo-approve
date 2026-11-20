//! remote-sudo-approve: approve each sudo command of a gated user with a passkey.
//! See DESIGN.md for the protocol and threat model.

pub mod change;
pub mod config;
pub mod frame;
pub mod policy;
pub mod relay;
pub mod request;
pub mod webauthn;
