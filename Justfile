# Thurin Core - Build orchestration
# Run `just --list` to see all commands

# Default: show available commands
default:
    @just --list

# === Full builds ===

# Build everything in order
build: build-circuits build-contracts build-sdk

# Run all tests
test: test-circuits test-contracts test-sdk

# === Circuits ===

# Compile circuits
build-circuits:
    cd circuits && nargo compile

# Run circuit tests
test-circuits:
    cd circuits && nargo test

# Generate verification key (requires bb)
circuits-vk:
    cd circuits && bb write_vk -b target/thurin.json -o target/vk -t evm

# Generate Solidity verifier and copy to contracts
circuits-verifier: circuits-vk
    cd circuits && bb write_solidity_verifier -k target/vk/vk -o ../contracts/src/HonkVerifier.sol -t evm

# Full circuit pipeline: compile → vk → verifier
circuits-full: build-circuits circuits-verifier

# === Contracts ===

# Build contracts
build-contracts:
    cd contracts && forge build

# Run contract tests
test-contracts:
    cd contracts && forge test

# === SDK ===

# Build SDK
build-sdk:
    pnpm --filter sdk build

# Run SDK tests
test-sdk:
    pnpm --filter sdk test

# === Utilities ===

# Generate test vectors
gen-test-vectors:
    pnpm --filter test-vectors generate

# Run circuits-helper
circuits-hash *ARGS:
    cd circuits-helper && nargo execute {{ARGS}}

# Clean all build artifacts
clean:
    rm -rf circuits/target
    cd contracts && forge clean
    pnpm --filter sdk run clean 2>/dev/null || true
