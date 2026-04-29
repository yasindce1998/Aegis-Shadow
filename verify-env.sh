#!/bin/bash
# save as verify-env.sh, run with: bash verify-env.sh
echo "=== Aegis-Shadow Environment Check ==="
echo -n "Kernel version: " && uname -r
echo -n "BTF support: " && (ls /sys/kernel/btf/vmlinux 2>/dev/null && echo "OK" || echo "MISSING")
echo -n "Rust: " && rustc --version 2>/dev/null || echo "MISSING"
echo -n "bpf-linker: " && bpf-linker --version 2>/dev/null || echo "MISSING"
echo -n "bpftool: " && which bpftool 2>/dev/null || echo "MISSING"
echo -n "clang: " && clang --version 2>/dev/null | head -1 || echo "MISSING"
echo -n "libelf: " && pkg-config --exists libelf && echo "OK" || echo "MISSING"
echo "=== All checks complete ==="

# Made with Bob
