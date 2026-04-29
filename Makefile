.PHONY: setup build-ebpf build clean load-offense load-defense test

# Build all eBPF programs
build-ebpf:
	cargo xtask build-ebpf --release

# Build everything
build: build-ebpf
	cargo build --release --package offense --package defense

# Clean all build artifacts
clean:
	cargo clean

# Load the rootkit (requires root)
load-offense:
	@echo "Loading Shadow rootkit..."
	sudo ./target/release/offense $(ARGS)

# Load the defense guardian (requires root)
load-defense:
	@echo "Loading Aegis guardian..."
	sudo ./target/release/defense $(ARGS)

# Run the full test sequence
test:
	@echo "=== Aegis-Shadow Test Sequence ==="
	@echo "Step 1: Creating target process..."
	sleep 9999 &
	@echo "Step 2: Loading rootkit..."
	sudo ./target/release/offense hide-pid --pid $$(pgrep -f "sleep 9999")
	@echo "Step 3: Verifying process is hidden..."
	ps aux | grep -c "sleep 9999"
	@echo "Step 4: Running defense audit..."
	sudo ./target/release/defense audit
	@echo "Step 5: Cleanup..."
	sudo ./target/release/offense cleanup
	kill $$(pgrep -f "sleep 9999") 2>/dev/null || true
	@echo "=== Test complete ==="

# Environment verification
verify-env:
	bash verify-env.sh

# Setup: install all dependencies
setup:
	rustup toolchain install nightly
	rustup default nightly
	cargo install bpf-linker
	cargo install cargo-generate
	sudo apt install -y bpftool libelf-dev clang llvm