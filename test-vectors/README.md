# @thurin/test-vectors

Test data generation for Thurin mDL verification.

## Overview

This package generates valid mDL test data that can be used by both the Noir circuits and TypeScript SDK. It ensures both components are tested against identical inputs.

## What It Generates

| File | Description |
|------|-------------|
| `basic-california.json` | Complete test vector with all components |
| `age-claim.bin` | Raw CBOR bytes for age_over_21 IssuerSignedItem |
| `mso.bin` | Raw CBOR bytes for Mobile Security Object |
| `mso-signature.bin` | ECDSA P-256 signature (64 bytes, r \|\| s) |
| `iaca-pubkey-x.bin` | IACA public key X coordinate (32 bytes) |
| `iaca-pubkey-y.bin` | IACA public key Y coordinate (32 bytes) |

## Usage

```bash
# Generate test fixtures
pnpm generate

# Use in tests
import testVector from '@thurin/test-vectors/fixtures/basic-california.json';
```

## Structure

```
src/
├── index.ts      # Exports
├── types.ts      # Type definitions
├── cbor.ts       # CBOR encoding utilities
├── iaca.ts       # IACA key generation/signing
└── generate.ts   # Main generation script

fixtures/         # Generated test data (git-tracked)
├── basic-california.json
├── age-claim.bin
└── ...
```

## License

Apache-2.0
