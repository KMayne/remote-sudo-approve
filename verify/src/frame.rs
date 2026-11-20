//! The plugin → verifier message on the verifier's stdin. Length-prefixed,
//! so no argument or environment value can forge a field boundary.
//!
//! ```text
//! "SPK1"
//! 4 sections, in order: user_info, command_info, run_argv, run_envp
//!   u32 count, then count × (u32 length, bytes)
//! u8 stdin_is_tty (0 or 1)
//! ```
//! Integers are little-endian. The encoder lives in the plugin
//! (plugin/src/lib.rs); this is the decoder, with hard limits.

pub const MAGIC: &[u8; 4] = b"SPK1";
const MAX_ITEMS: u32 = 4096;
const MAX_ITEM: u32 = 1 << 20;
pub const MAX_TOTAL: usize = 4 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub user_info: Vec<Vec<u8>>,
    pub command_info: Vec<Vec<u8>>,
    pub run_argv: Vec<Vec<u8>>,
    pub run_envp: Vec<Vec<u8>>,
    pub stdin_is_tty: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Malformed(pub &'static str);

pub fn decode(mut b: &[u8]) -> Result<Message, Malformed> {
    if b.len() > MAX_TOTAL {
        return Err(Malformed("too long"));
    }
    if b.get(..4) != Some(MAGIC.as_slice()) {
        return Err(Malformed("magic"));
    }
    b = &b[4..];
    let mut sections = Vec::with_capacity(4);
    for _ in 0..4 {
        let n = take_u32(&mut b)?;
        if n > MAX_ITEMS {
            return Err(Malformed("too many items"));
        }
        let mut items = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let len = take_u32(&mut b)?;
            if len > MAX_ITEM {
                return Err(Malformed("item too long"));
            }
            let len = len as usize;
            if b.len() < len {
                return Err(Malformed("truncated"));
            }
            items.push(b[..len].to_vec());
            b = &b[len..];
        }
        sections.push(items);
    }
    let tty = match b {
        [0] => false,
        [1] => true,
        _ => return Err(Malformed("trailer")),
    };
    let run_envp = sections.pop().unwrap_or_default();
    let run_argv = sections.pop().unwrap_or_default();
    let command_info = sections.pop().unwrap_or_default();
    let user_info = sections.pop().unwrap_or_default();
    Ok(Message { user_info, command_info, run_argv, run_envp, stdin_is_tty: tty })
}

fn take_u32(b: &mut &[u8]) -> Result<u32, Malformed> {
    let (head, rest) = b.split_first_chunk::<4>().ok_or(Malformed("truncated"))?;
    *b = rest;
    Ok(u32::from_le_bytes(*head))
}

/// The encoder, for tests and tools; the plugin has its own copy that
/// writes straight from sudo's C arrays.
pub fn encode(m: &Message) -> Vec<u8> {
    let mut o = MAGIC.to_vec();
    for s in [&m.user_info, &m.command_info, &m.run_argv, &m.run_envp] {
        o.extend_from_slice(&(s.len() as u32).to_le_bytes());
        for item in s {
            o.extend_from_slice(&(item.len() as u32).to_le_bytes());
            o.extend_from_slice(item);
        }
    }
    o.push(m.stdin_is_tty as u8);
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg() -> Message {
        Message {
            user_info: vec![b"uid=1001".to_vec()],
            command_info: vec![b"command=/bin/true".to_vec(), b"cwd=/".to_vec()],
            // An argument that looks like a field can't become one.
            run_argv: vec![b"true".to_vec(), b"x\ncommand=/bin/sh\x00".to_vec()],
            run_envp: vec![],
            stdin_is_tty: true,
        }
    }

    #[test]
    fn round_trip() {
        assert_eq!(decode(&encode(&msg())), Ok(msg()));
    }

    #[test]
    fn malformed_input_is_rejected() {
        let good = encode(&msg());
        assert!(decode(&good[..good.len() - 1]).is_err());
        let mut extra = good.clone();
        extra.push(0);
        assert!(decode(&extra).is_err());
        let mut bad_tty = good.clone();
        *bad_tty.last_mut().unwrap() = 2;
        assert!(decode(&bad_tty).is_err());
        assert!(decode(b"SPK2").is_err());
        assert!(decode(b"").is_err());
        // A huge count doesn't allocate or loop forever.
        let mut huge = MAGIC.to_vec();
        huge.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode(&huge), Err(Malformed("too many items")));
        let mut long = MAGIC.to_vec();
        long.extend_from_slice(&1u32.to_le_bytes());
        long.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode(&long), Err(Malformed("item too long")));
    }
}
