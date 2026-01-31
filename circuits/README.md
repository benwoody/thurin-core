# @thurinlabs/circuits

Zero-knowledge circuits for mDL (mobile driver's license) verification, written in Noir.

## Overview

This package contains the Noir circuits that enable privacy-preserving identity verification. Users can prove claims like "I'm over 21" without revealing any other personal information from their driver's license.

## Structure

```
src/
├── main.nr           # Main circuit entrypoint
├── cbor.nr           # CBOR extraction for mDL claims
├── mso.nr            # Mobile Security Object verification
├── nullifier.nr      # Nullifier and IACA root computation
└── utils.nr          # Utility functions (hashing, date conversion)
```

### Modules

| Module | Description |
|--------|-------------|
| `cbor.nr` | Extracts age_over_21, age_over_18, and state claims from CBOR bytes |
| `mso.nr` | Extracts digests and validity dates from MSO structures |
| `nullifier.nr` | Computes nullifiers and IACA roots using Poseidon2 |
| `utils.nr` | Byte comparison, timestamp conversion utilities |

## Development

```bash
# Check circuit compiles
nargo check

# Run tests
nargo test

# Compile to ACIR
nargo compile

# Generate witness
nargo execute

# Generate verification key (requires bb)
bb write_vk -b target/thurin.json -o target/vk -t evm

# Generate Solidity verifier
bb write_solidity_verifier -k target/vk/vk -o ../contracts/src/HonkVerifier.sol -t evm

# Generate and verify proof
bb prove -b target/thurin.json -w target/thurin.gz -k target/vk/vk -o target/proof -t evm
bb verify -k target/vk/vk -p target/proof/proof -i target/proof/public_inputs
```

**Important:** All `bb` commands need `-t evm` for EVM-compatible output.

## Circuit Flow

1. **Verify IACA root** - Check public key matches expected root
2. **Verify MSO signature** - ECDSA P-256 signature over MSO hash
3. **Verify claim digests** - Each claim hashes to its MSO digest
4. **Extract claims** - Parse age_over_21, age_over_18, state from CBOR
5. **Compute nullifier** - Deterministic but unlinkable identifier
6. **Check expiry** - MSO must not be expired

## Constraint Budget

| Operation | Constraints |
|-----------|-------------|
| ECDSA P-256 verify | ~100,000 |
| SHA-256 (3 blocks) | ~25,000 |
| Poseidon2 nullifier | ~300 |
| Date/bool logic | ~1,000 |
| **Total** | **~126,000** |

## License

Apache-2.0
