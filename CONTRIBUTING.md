# Contributing to Aegis-Shadow

Thank you for your interest in contributing to Aegis-Shadow! This document provides guidelines for contributing to this security research project.

## 🎯 Project Goals

Aegis-Shadow is designed to:
1. Demonstrate eBPF-based rootkit techniques for security research
2. Provide detection mechanisms for eBPF-based threats
3. Educate security professionals about kernel-level threats
4. Advance defensive capabilities against advanced persistent threats

## 📋 Code of Conduct

### Research Ethics
- Use only for authorized security research
- Never deploy on systems without explicit permission
- Respect privacy and confidentiality
- Follow responsible disclosure practices
- Contribute to improving security, not harming it

### Community Standards
- Be respectful and professional
- Provide constructive feedback
- Help others learn
- Credit original authors
- Follow project guidelines

## 🚀 Getting Started

### Prerequisites
```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install nightly toolchain
rustup install nightly
rustup component add rust-src --toolchain nightly

# Install eBPF tools
cargo install bpf-linker

# Install system dependencies (Ubuntu/Debian)
sudo apt-get install clang llvm libelf-dev linux-headers-$(uname -r)
```

### Development Setup
```bash
# Clone repository
git clone https://github.com/your-org/aegis-shadow.git
cd aegis-shadow

# Verify environment
./verify-env.sh

# Build project
cargo xtask build-ebpf
cargo build --all

# Run tests
cargo test --all
```

## 💻 Development Workflow

### 1. Fork and Branch
```bash
# Fork on GitHub, then:
git clone https://github.com/YOUR_USERNAME/aegis-shadow.git
cd aegis-shadow
git remote add upstream https://github.com/original/aegis-shadow.git

# Create feature branch
git checkout -b feature/your-feature-name
```

### 2. Make Changes
- Write clear, documented code
- Follow Rust naming conventions
- Add tests for new features
- Update documentation
- Keep commits atomic and focused

### 3. Test Thoroughly
```bash
# Format code
cargo fmt --all

# Run linter
cargo clippy --all-targets -- -D warnings

# Run tests
cargo test --all

# Build eBPF programs
cargo xtask build-ebpf --release

# Test in isolated environment
sudo ./tests/test_offense.sh
sudo ./tests/test_defense.sh
```

### 4. Submit Pull Request
```bash
# Commit changes
git add .
git commit -m "feat: add new detection module"

# Push to your fork
git push origin feature/your-feature-name

# Create PR on GitHub
```

## 📝 Code Quality Standards

### Rust Style Guide
- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo fmt` for formatting
- Pass `cargo clippy` without warnings
- Maintain 80-100 character line length
- Use meaningful variable names

### Documentation Requirements
```rust
/// Brief description of function
///
/// # Arguments
/// * `param1` - Description of parameter
///
/// # Returns
/// Description of return value
///
/// # Safety
/// Explain any unsafe operations
///
/// # Examples
/// ```
/// let result = function(arg);
/// ```
pub fn function(param1: Type) -> Result<ReturnType, Error> {
    // Implementation
}
```

### Testing Standards
- Unit tests for all public functions
- Integration tests for features
- Test error handling paths
- Use descriptive test names
- Add comments explaining test purpose

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tty_device_valid() {
        let result = parse_tty_device("136:0");
        assert_eq!(result, Some((136, 0)));
    }

    #[test]
    fn test_parse_tty_device_invalid() {
        let result = parse_tty_device("invalid");
        assert_eq!(result, None);
    }
}
```

## 🔒 Security Considerations

### Code Review Checklist
- [ ] No hardcoded secrets or keys
- [ ] Input validation on all user inputs
- [ ] Proper error handling
- [ ] Bounds checking in loops
- [ ] Safe use of `unsafe` blocks
- [ ] No information leaks
- [ ] Proper resource cleanup
- [ ] Rate limiting where appropriate

### eBPF-Specific Guidelines
- [ ] Bounded loops (verifier requirement)
- [ ] No unbounded recursion
- [ ] Proper use of BPF helpers
- [ ] Correct map sizing
- [ ] Memory safety in kernel space
- [ ] No floating-point operations
- [ ] Stack size limits respected

## 📚 Documentation Guidelines

### Code Comments
```rust
// Single-line comment for simple explanations

/// Doc comment for public API
/// Use markdown formatting
/// Include examples when helpful

/* Multi-line comment for
   complex explanations or
   temporary notes */
```

### Commit Messages
Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new detection module for ghost maps
fix: correct bounds checking in getdents64 hook
docs: update USAGE.md with new CLI options
test: add integration tests for defense engine
refactor: simplify error handling in offense loader
perf: optimize syscall latency monitoring
chore: update dependencies to latest versions
```

### Pull Request Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No new warnings
- [ ] Tests added/updated
```

## 🐛 Bug Reports

### Issue Template
```markdown
**Describe the bug**
Clear description of the issue

**To Reproduce**
Steps to reproduce:
1. Run command '...'
2. Observe behavior '...'
3. See error

**Expected behavior**
What should happen

**Environment**
- OS: [e.g., Ubuntu 22.04]
- Kernel: [e.g., 5.15.0]
- Rust: [e.g., 1.75.0]

**Additional context**
Any other relevant information
```

## ✨ Feature Requests

### Proposal Template
```markdown
**Feature Description**
Clear description of proposed feature

**Use Case**
Why is this feature needed?

**Proposed Implementation**
High-level approach

**Alternatives Considered**
Other approaches evaluated

**Additional Context**
Any other relevant information
```

## 🔄 Review Process

### For Contributors
1. Submit PR with clear description
2. Respond to review comments
3. Update based on feedback
4. Ensure CI passes
5. Wait for maintainer approval

### For Reviewers
1. Review code quality
2. Check security implications
3. Verify tests pass
4. Test functionality
5. Provide constructive feedback

## 📊 Project Structure

```
aegis-shadow/
├── common/              # Shared data structures (#![no_std])
├── offense-ebpf/        # Offensive eBPF programs
├── offense/             # Offensive user-space loader
├── defense-ebpf/        # Defensive eBPF programs
├── defense/             # Defensive user-space engine
├── integration-tests/   # Adversarial offense-vs-defense tests
├── xtask/               # Build automation
├── tests/               # Shell-based test scripts
└── assets/              # Project assets (logo, etc.)
```

## 🎓 Learning Resources

### eBPF Resources
- [eBPF Documentation](https://ebpf.io/)
- [BPF and XDP Reference Guide](https://docs.cilium.io/en/latest/bpf/)
- [Linux Kernel BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)

### Rust Resources
- [The Rust Book](https://doc.rust-lang.org/book/)
- [Rust by Example](https://doc.rust-lang.org/rust-by-example/)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)

### Security Research
- [MITRE ATT&CK](https://attack.mitre.org/)
- [eBPF Security Research](https://www.blackhat.com/us-21/briefings/schedule/#ebpf-i-thought-we-were-friends-23619)

## 💬 Communication

### Channels
- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and ideas
- **Pull Requests**: Code contributions

### Response Times
- Issues: 48-72 hours
- Pull Requests: 3-5 business days
- Security Issues: 24-48 hours

## 🏆 Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Credited in release notes
- Acknowledged in documentation

## 📄 License

By contributing, you agree that your contributions will be licensed under the same license as the project (see LICENSE file).

## ❓ Questions?

If you have questions not covered here:
1. Check existing documentation
2. Search closed issues
3. Open a new discussion
4. Contact maintainers

---

Thank you for contributing to Aegis-Shadow and advancing security research! 🛡️