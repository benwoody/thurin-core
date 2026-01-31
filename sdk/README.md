# @thurinlabs/sdk

TypeScript SDK for Thurin mDL zero-knowledge proofs.

## Overview

This SDK enables web applications to:

1. Request mDL credentials from users via the Digital Credentials API
2. Generate ZK proofs in the browser using WASM
3. Mint Soulbound Tokens (SBTs) as proof of verified identity
4. Interact with ThurinSBT, ThurinVerifier, and ThurinPoints contracts

## Installation

```bash
pnpm add @thurinlabs/sdk
```

## Dependencies

The SDK uses these key dependencies:
- `@aztec/bb.js` - Barretenberg WASM backend for proof generation
- `@noir-lang/noir_js` - Noir circuit execution
- `viem` - Ethereum interactions
- `cborg` - CBOR encoding/decoding

## Quick Start

```typescript
import { Thurin, initProver } from '@thurinlabs/sdk';
import circuit from './thurin.json'; // Compiled Noir circuit

// Initialize prover once on app load (loads WASM)
await initProver(circuit);

// Create Thurin client
const thurin = new Thurin({
  chainId: 8453, // Base
  addresses: {
    sbt: '0x...',
    verifier: '0x...',
    points: '0x...',
  },
  walletClient, // viem wallet client for transactions
});

// Request credential from wallet (requires Digital Credentials API)
const credential = await thurin.requestCredential({
  claims: ['age_over_21', 'age_over_18', 'issuing_jurisdiction'],
});

// Or use mock credential for testing
const credential = Thurin.createMockCredential({
  ageOver21: true,
  ageOver18: true,
  state: 'CA',
});

// Generate ZK proof
const proof = await thurin.generateProof(credential, {
  eventId: 'thurin-sbt',
  boundAddress: userAddress,
  proveAgeOver21: true,
  proveAgeOver18: true,
  proveState: true,
});

// Mint SBT
const txHash = await thurin.mint(proof, {
  referrerTokenId: 0n, // Optional: referrer's token ID
});

// Check SBT status
const status = await thurin.getSBTStatus(userAddress);
console.log(status.hasSBT, status.isValid, status.points);
```

## Architecture

Thurin uses a two-layer model:

### Layer 1: ThurinSBT (Identity Anchor)

A Soulbound Token proving "verified unique human with valid US mDL":
- Non-transferable ERC-721
- Stores nullifier (sybil resistance) and expiry (from mDL)
- One per person (enforced by nullifier)
- `isValid(address)` - single source of truth for verification status

### Layer 2: ThurinVerifier (Claim Verification)

Stateless proof verification for specific claims:
- Verifies ZK proofs of age, state, etc.
- Requires valid SBT
- dApps store their own verification results

### ThurinPoints (Incentives)

Points system for users and dApps:
- Users earn points for minting, referrals, verifications
- dApps earn points for verification volume

## API Reference

### Initialization

```typescript
import { initProver, isProverInitialized, destroyProver } from '@thurinlabs/sdk';

// Initialize prover (required before generateProof)
await initProver(circuit);

// Check if prover is ready
if (isProverInitialized()) { ... }

// Clean up WASM resources
await destroyProver();
```

### Thurin Client

```typescript
const thurin = new Thurin({
  chainId: number,              // 8453 (Base), 84532 (Base Sepolia), etc.
  addresses: ThurinAddresses,   // { sbt, verifier, points }
  rpcUrl?: string,              // Optional RPC URL
  publicClient?: PublicClient,  // Optional viem public client
  walletClient?: WalletClient,  // Optional viem wallet client
  circuit?: CompiledCircuit,    // Optional circuit for auto-init
});
```

### Credential Operations

```typescript
// Request credential from wallet
const credential = await thurin.requestCredential({
  claims: ['age_over_21', 'age_over_18', 'issuing_jurisdiction'],
  nonce?: string,
});

// Check if Digital Credentials API is supported
Thurin.isCredentialApiSupported();

// Create mock credential for testing
Thurin.createMockCredential({
  ageOver21?: boolean,
  ageOver18?: boolean,
  state?: string,        // e.g., 'CA', 'TX'
  documentNumber?: string,
  expiryDate?: Date,
});
```

### Proof Generation

```typescript
const proof = await thurin.generateProof(credential, {
  eventId: string,           // App-specific event ID for nullifier
  boundAddress: Address,     // Wallet address to bind proof to
  timestamp?: number,        // Proof timestamp (defaults to now)
  proveAgeOver21?: boolean,  // Include age 21+ in proof
  proveAgeOver18?: boolean,  // Include age 18+ in proof
  proveState?: boolean,      // Include state code in proof
});
```

### SBT Operations

```typescript
// Mint SBT with proof
const txHash = await thurin.mint(proof, {
  referrerTokenId?: bigint,  // Optional referrer
  gas?: bigint,              // Optional gas override
});

// Get mint price (tiered: $1 OG, $2 Early, $5 Standard)
const price = await thurin.getMintPrice();

// Get SBT status
const status = await thurin.getSBTStatus(userAddress);
// Returns: { hasSBT, isValid, tokenId, expiry, points }

// Check if user has valid (non-expired) SBT
const valid = await thurin.hasValidSBT(userAddress);

// Check nullifier
const used = await thurin.nullifierUsed(nullifier);

// Check IACA root
const trusted = await thurin.isTrustedIACARoot(root);
const stateName = await thurin.getIACAStateName(root);
```

### Points Operations

```typescript
// Get user points
const points = await thurin.getUserPoints(userAddress);

// Get dApp points
const dappPoints = await thurin.getDappPoints(dappAddress);

// Get leaderboard
const top10 = await thurin.getLeaderboard(10);
```

### Contract Wrappers

For direct contract access:

```typescript
const sbt = thurin.getSBT();        // ThurinSBT instance
const verifier = thurin.getVerifier(); // ThurinVerifier instance
const points = thurin.getPoints();   // ThurinPoints instance
```

## Contract Integration (Solidity)

dApps can check SBT status directly:

```solidity
import { IThurinSBT } from "@thurinlabs/contracts/interfaces/IThurinSBT.sol";

contract MyDapp {
    IThurinSBT public sbt;

    function doSomething() external {
        require(sbt.isValid(msg.sender), "Need valid Thurin SBT");
        // User is verified
    }
}
```

## Utilities

```typescript
import { hashEventId, NO_REFERRER } from '@thurinlabs/sdk';

// Hash event ID to bytes32
const eventIdHash = hashEventId('my-event');

// No referrer constant
const referrer = NO_REFERRER; // 0n
```

## Known Limitations

### Response Decryption (TODO)

The `requestCredential()` function calls the Digital Credentials API correctly, but response decryption is not yet implemented. The wallet encrypts its response using HPKE.

**What's missing:**
- HPKE decryption (ECDH key agreement + AES-GCM)
- DeviceResponse parsing (ISO 18013-7 structure)

This is blocked on having real mDL response data to test against. Use `createMockCredential()` for development and testing.

## Supported Chains

- Base (8453)
- Base Sepolia (84532)
- Ethereum Mainnet (1)
- Arbitrum (42161)
- Sepolia (11155111)

## License

Apache-2.0
