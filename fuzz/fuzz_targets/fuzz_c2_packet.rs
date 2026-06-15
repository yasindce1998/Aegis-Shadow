#![no_main]
use libfuzzer_sys::fuzz_target;
use common::c2_parse::parse_c2_packet;

fuzz_target!(|data: &[u8]| {
    let _ = parse_c2_packet(data);
});
