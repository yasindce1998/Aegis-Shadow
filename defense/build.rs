use std::path::PathBuf;

fn main() {
    let ebpf_dir = PathBuf::from("../target/bpfel-unknown-none/release");

    println!("cargo:rerun-if-changed=../defense-ebpf/src/main.rs");
    println!("cargo:rerun-if-changed={}", ebpf_dir.display());
}

// Made with Bob
