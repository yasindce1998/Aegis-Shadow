#![no_main]
use libfuzzer_sys::fuzz_target;
use common::CommandPayload;

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }
    let cmd = unsafe { *(data.as_ptr() as *const CommandPayload) };
    // Exercise command dispatch logic
    match cmd.cmd_type {
        1 => { let _ = cmd.arg1; } // hide_pid
        2 => { let _ = cmd.arg1; } // unhide_pid
        3 => { let _ = cmd.arg1; } // obfuscate_file
        4 => { let _ = cmd.arg1; } // exfil
        5 => {} // kill_switch
        _ => {}
    }
});
