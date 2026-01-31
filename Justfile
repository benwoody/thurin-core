# Thurin Core - Build orchestration
# Run `just --list` to see all commands

# Add nargo to PATH
export PATH := env_var("HOME") + "/.nargo/bin:" + env_var("PATH")

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

# === Deploy (Testnets) ===

# Deploy to Ethereum Sepolia
deploy-sepolia:
    cd contracts && forge script script/Deploy.s.sol --rpc-url sepolia --broadcast --verify

# Deploy to Base Sepolia
deploy-base-sepolia:
    cd contracts && forge script script/Deploy.s.sol --rpc-url base_sepolia --broadcast --verify

# Deploy to Scroll Sepolia
deploy-scroll-sepolia:
    cd contracts && forge script script/Deploy.s.sol --rpc-url scroll_sepolia --broadcast --verify

# Deploy to Linea Sepolia
deploy-linea-sepolia:
    cd contracts && forge script script/Deploy.s.sol --rpc-url linea_sepolia --broadcast --verify

# Deploy to Polygon zkEVM Cardona
deploy-polygon-zkevm-cardona:
    cd contracts && forge script script/Deploy.s.sol --rpc-url polygon_zkevm_cardona --broadcast --verify

# Deploy to zkSync Sepolia (requires foundry-zksync + Apple Silicon Mac)
# NOTE: No Intel Mac build available - run this from an M1/M2/M3/M4/M5 Mac
# Install: curl -L https://raw.githubusercontent.com/matter-labs/foundry-zksync/main/install-foundry-zksync | bash
deploy-zksync-sepolia:
    cd contracts && forge script script/Deploy.s.sol --rpc-url zksync_sepolia --broadcast --zksync

# Deploy to all testnets (except zkSync - run separately)
deploy-all-testnets: deploy-sepolia deploy-base-sepolia deploy-scroll-sepolia deploy-linea-sepolia deploy-polygon-zkevm-cardona
    @echo "Deployed to all EVM testnets. Run 'just deploy-zksync-sepolia' separately for zkSync."

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
