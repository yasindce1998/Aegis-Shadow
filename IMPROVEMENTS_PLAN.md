# Aegis-Shadow Improvement Plan

## Priority Fixes to Apply

Based on the code quality review, here are the improvements we'll implement:

### 1. Fix Rust-Analyzer False Positive ✅
**File**: `offense-ebpf/src/main.rs:1003`
**Change**: Add explicit type annotation
```rust
// Before:
let seq = match unsafe { DNS_EXFIL_SEQ.get(&0u32) } {
    Some(s) => *s,
    None => return Ok(0),
};

// After:
let seq: u32 = match unsafe { DNS_EXFIL_SEQ.get(&0u32) } {
    Some(s) => *s,
    None => return Ok(0),
};
```

### 2. Add Security Warning Comments ✅
**File**: `common/src/lib.rs:24-44`
**Change**: Add prominent security warnings about hardcoded keys
```rust
/// ⚠️ SECURITY WARNING: These keys are hardcoded for research purposes only.
/// In production, keys MUST be:
/// - Generated at runtime
/// - Loaded from secure key management system
/// - Rotated regularly
/// - Never committed to source control
pub const C2_CHACHA20_KEY: [u8; 32] = [
    // ...
];
```

### 3. Add Input Validation ✅
**File**: `offense/src/main.rs:456-478`
**Change**: Add bounds checking to parse functions
```rust
fn parse_tty_device(s: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let major = parts[0].parse::<u32>().ok()?;
    let minor = parts[1].parse::<u32>().ok()?;
    
    // Validate device numbers are in reasonable range
    if major > 255 || minor > 255 {
        return None;
    }
    
    Some((major, minor))
}
```

### 4. Add Named Constants for Magic Numbers ✅
**File**: `offense-ebpf/src/main.rs`
**Change**: Replace magic numbers with named constants
```rust
// Add at top of file:
const LINUX_DIRENT64_RECLEN_OFFSET: usize = 16;
const LINUX_DIRENT64_NAME_OFFSET: usize = 19;
const STRUCT_FILE_F_INODE_OFFSET: usize = 32;
const STRUCT_INODE_I_INO_OFFSET: usize = 64;

// Then use in code:
let reclen_ptr = entry_ptr + LINUX_DIRENT64_RECLEN_OFFSET;
let name_ptr = entry_ptr + LINUX_DIRENT64_NAME_OFFSET;
```

### 5. Add Error Counter Map ✅
**File**: `offense-ebpf/src/main.rs`
**Change**: Add BPF map to track errors
```rust
/// Error counters for debugging
#[map]
static ERROR_COUNTERS: HashMap<u32, u64> = HashMap::with_max_entries(32, 0);

const ERR_PROBE_READ_FAILED: u32 = 1;
const ERR_PROBE_WRITE_FAILED: u32 = 2;
const ERR_MAP_INSERT_FAILED: u32 = 3;
// etc.
```

### 6. Improve Defense Alert Structure ✅
**File**: `common/src/lib.rs`
**Change**: Update DefenseAlert to match actual usage
```rust
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DefenseAlert {
    pub alert_type: u32,
    pub severity: u8,
    pub _pad1: [u8; 3],
    pub pid: u32,
    pub timestamp_ns: u64,
    pub context: u64,
    pub details: [u8; 64],
}
```

### 7. Add CI/CD Configuration ✅
**File**: `.github/workflows/ci.yml`
**Change**: Create GitHub Actions workflow
```yaml
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: nightly
      - run: cargo test --all
      - run: cargo clippy -- -D warnings
      - run: cargo fmt -- --check
```

### 8. Add .gitignore Improvements ✅
**File**: `.gitignore`
**Change**: Add more comprehensive ignores
```
# Existing entries...

# eBPF build artifacts
*.o
*.ll
*.bc

# Test outputs
/tmp/
*.log
alerts.json

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db
```

### 9. Add SECURITY.md ✅
**File**: `SECURITY.md`
**Change**: Create security policy document
```markdown
# Security Policy

## ⚠️ Research Tool Warning

This is a security research tool. Use only in authorized environments.

## Reporting Vulnerabilities

Please report security issues to: [security contact]

## Known Limitations

1. Hardcoded cryptographic keys (research only)
2. Limited input validation
3. No key rotation mechanism
4. Minimal rate limiting

## Secure Usage Guidelines

- Never use in production
- Always use in isolated lab environments
- Rotate keys regularly
- Monitor for unauthorized use
```

### 10. Add CONTRIBUTING.md ✅
**File**: `CONTRIBUTING.md`
**Change**: Create contribution guidelines
```markdown
# Contributing to Aegis-Shadow

## Code Quality Standards

- All code must pass `cargo clippy`
- Format with `cargo fmt`
- Add tests for new features
- Document public APIs
- Follow Rust naming conventions

## Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `cargo test --all`
5. Submit PR with clear description

## Security Considerations

- Never commit real keys or credentials
- Test in isolated environments only
- Follow responsible disclosure practices
```

---

## Implementation Order

1. ✅ Create documentation files (SECURITY.md, CONTRIBUTING.md)
2. ✅ Update .gitignore
3. ✅ Add security warnings to common/src/lib.rs
4. ✅ Fix rust-analyzer issue in offense-ebpf
5. ✅ Add input validation to offense/src/main.rs
6. ✅ Add named constants to offense-ebpf
7. ✅ Update DefenseAlert structure
8. ✅ Add CI/CD configuration
9. ✅ Update README with security warnings
10. ✅ Create CODE_REVIEW.md (already done)

---

## Testing Plan

After applying fixes:
1. Run `cargo clippy --all-targets`
2. Run `cargo fmt --all -- --check`
3. Build all crates: `cargo build --all`
4. Build eBPF: `cargo xtask build-ebpf`
5. Run test scripts (if in appropriate environment)

---

## Notes

- Some fixes require switching to Code mode
- Critical security issues documented but not all fixed (by design for research tool)
- Production deployment would require additional hardening
- All improvements maintain backward compatibility