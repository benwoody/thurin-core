# Thurin Core

Monorepo for Thurin's core infrastructure: ZK circuits, smart contracts, and SDK.

## Overview

Thurin enables privacy-preserving identity verification using mobile driver's licenses (mDLs). Users can prove claims like "I'm over 21" without revealing any other personal information.

## Packages

| Package | Description |
|---------|-------------|
| [circuits](./circuits) | Noir ZK circuits for mDL verification |
| [contracts](./contracts) | Solidity smart contracts (ThurinSBT, ThurinVerifier, ThurinPoints) |
| [sdk](./sdk) | TypeScript SDK for proof generation and contract interaction |
| [circuits-helper](./circuits-helper) | Dev tool for computing Poseidon2 hashes |
| [test-vectors](./test-vectors) | Test data generation for circuits and SDK |

## Quick Start

```bash
# Install dependencies
pnpm install

# Run all tests
just test

# Build everything
just build
```

## Build Commands

```bash
just build              # Build all packages
just test               # Run all tests

# Circuits
just build-circuits     # Compile Noir circuits
just test-circuits      # Run circuit tests
just circuits-full      # Compile → generate verifier → copy to contracts

# Contracts
just build-contracts    # Build Solidity contracts
just test-contracts     # Run contract tests

# SDK
just build-sdk          # Build TypeScript SDK
just test-sdk           # Run SDK tests
```

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│    circuits     │────▶│    contracts    │────▶│       sdk       │
│  (Noir/ACIR)    │     │   (Solidity)    │     │  (TypeScript)   │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       │
        ▼                       ▼                       ▼
   HonkVerifier.sol        ABIs/Addresses         Browser WASM
```

**Dependency flow:**
1. Circuits compile to ACIR, generate `HonkVerifier.sol`
2. Contracts use HonkVerifier, export ABIs
3. SDK uses ABIs and circuit artifacts for browser proof generation

## Development Workflow

When changing circuits:

```bash
# 1. Edit circuits
vim circuits/src/main.nr

# 2. Test circuits
just test-circuits

# 3. Regenerate verifier and update contracts
just circuits-full

# 4. Test contracts
just test-contracts

# 5. Test SDK
just test-sdk
```

## Requirements

- [Noir](https://noir-lang.org/) (nargo) - Circuit compilation
- [Barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg) (bb) - Proof generation
- [Foundry](https://book.getfoundry.sh/) (forge) - Contract development
- [pnpm](https://pnpm.io/) - Package management
- [just](https://github.com/casey/just) - Task runner (optional, but recommended)

## License

Apache-2.0
