# @thurinlabs/contracts

Solidity smart contracts for Thurin identity verification.

**Deployed on Ethereum mainnet only.**

## Overview

Thurin uses a three-contract architecture:

| Contract | Purpose | State |
|----------|---------|-------|
| **ThurinSBT** | Soulbound token for verified humans | Stores nullifiers, expiry |
| **ThurinVerifier** | Stateless claim verification | Stores nothing (stateless) |
| **ThurinPoints** | Points tracking for users & dApps | Stores points balances |
| **HonkVerifier** | ZK proof verification (auto-generated) | Stores nothing |

## ThurinSBT

Non-transferable ERC-721 representing "verified unique human with valid US mDL".

```solidity
interface IThurinSBT {
    // Check if user has valid (non-expired) SBT
    function isValid(address user) external view returns (bool);

    // Get user's SBT expiry timestamp
    function expiry(address user) external view returns (uint256);

    // Check if nullifier has been used
    function nullifierUsed(bytes32 nullifier) external view returns (bool);

    // Get current mint price in ETH (from $5 USD via Chainlink)
    function getMintPrice() external view returns (uint256);

    // Mint SBT with ZK proof
    function mint(
        bytes calldata proof,
        bytes32 nullifier,
        uint256 proofTimestamp,
        bytes32 eventId,
        bytes32 iacaRoot,
        address boundAddress,
        bool proveAgeOver21,
        bool proveAgeOver18,
        bool proveState,
        bytes2 provenState,
        uint256 referrerTokenId
    ) external payable;
}
```

### Pricing

Flat **$5 USD** per mint, paid in ETH. Price calculated via Chainlink ETH/USD oracle.

### Referral System

- Pass a `referrerTokenId` when minting to credit the referrer
- Referrers earn 100 points per successful referral
- Can't self-refer (same nullifier = same person)

## ThurinVerifier

Stateless wrapper around HonkVerifier. Requires valid SBT.

```solidity
interface IThurinVerifier {
    // Check if user has valid SBT
    function hasValidSBT(address user) external view returns (bool);

    // Verify a ZK proof (stateless - returns result, stores nothing)
    function verify(
        bytes calldata proof,
        bytes32 nullifier,
        uint256 proofTimestamp,
        bytes32 eventId,
        bytes32 iacaRoot,
        address boundAddress,
        bool proveAgeOver21,
        bool proveAgeOver18,
        bool proveState,
        bytes2 provenState
    ) external view returns (bool);
}
```

## ThurinPoints

Points system for users and dApps.

```solidity
interface IThurinPoints {
    // User points
    function userPoints(address user) external view returns (uint256);

    // dApp verification count
    function dappVerificationCount(address dapp) external view returns (uint256);

    // Get top dApps by verification count
    function getTopDapps(uint256 limit) external view returns (DappInfo[] memory);
}
```

### Points Earning

**Users:**
- Mint SBT: 100 points (500 for OG, 250 for Early)
- Referral: 100 points per referred user

**dApps:**
- Earn points based on verification volume
- Permissionless - just call ThurinVerifier

## dApp Integration

### Simple: Just Check SBT

```solidity
import { IThurinSBT } from "@thurinlabs/contracts/interfaces/IThurinSBT.sol";

contract MyDapp {
    IThurinSBT public sbt;

    constructor(address _sbt) {
        sbt = IThurinSBT(_sbt);
    }

    function doSomething() external {
        require(sbt.isValid(msg.sender), "Need valid Thurin SBT");
        // User is a verified unique human
    }
}
```

### Advanced: Verify Specific Claims

```solidity
import { IThurinSBT } from "@thurinlabs/contracts/interfaces/IThurinSBT.sol";
import { IThurinVerifier } from "@thurinlabs/contracts/interfaces/IThurinVerifier.sol";

contract AcmeCasino {
    IThurinSBT public sbt;
    IThurinVerifier public verifier;
    mapping(address => bool) public ageVerified;

    function verifyAge(
        bytes calldata proof,
        bytes32 nullifier,
        uint256 proofTimestamp,
        bytes32 eventId,
        bytes32 iacaRoot,
        bytes2 provenState
    ) external {
        // Verify the ZK proof
        require(verifier.verify(
            proof,
            nullifier,
            proofTimestamp,
            eventId,
            iacaRoot,
            msg.sender,
            true,   // proveAgeOver21
            false,  // proveAgeOver18
            false,  // proveState
            0x0     // provenState (not used)
        ), "Invalid proof");

        ageVerified[msg.sender] = true;
    }

    function placeBet() external {
        require(sbt.isValid(msg.sender), "SBT expired");
        require(ageVerified[msg.sender], "Not age verified");
        // Proceed with betting
    }
}
```

## Development

```bash
# Install dependencies
forge install

# Build
forge build

# Run tests (19 tests including integration)
forge test

# Run with verbosity
forge test -vvv
```

## Local Testing (Anvil)

```bash
# Start Anvil (code-size-limit needed for HonkVerifier which is 24641 bytes)
anvil --code-size-limit 50000 --timestamp 1704067200

# Deploy contracts
forge script script/Deploy.s.sol \
  --rpc-url http://127.0.0.1:8545 \
  --broadcast \
  --code-size-limit 50000
```

**Notes:**
- HonkVerifier exceeds EIP-170 (24KB limit) at 24641 bytes
- `--timestamp` should match proof timestamp (proofs expire after 1 hour)

## Deployment

```bash
# Sepolia (testnet)
PRICE_FEED=0x694AA1769357215DE4FAC081bf1f309aDC325306 \
forge script script/Deploy.s.sol \
  --rpc-url $SEPOLIA_RPC \
  --broadcast \
  --verify

# Ethereum Mainnet (production)
forge script script/Deploy.s.sol \
  --rpc-url $MAINNET_RPC \
  --broadcast \
  --verify
```

## Regenerating HonkVerifier

When the circuit changes, from the monorepo root:

```bash
# Using just (recommended)
just circuits-full

# Or manually
cd circuits
nargo compile
bb write_vk -b target/thurin.json -o target/vk -t evm
bb write_solidity_verifier -k target/vk/vk -o ../contracts/src/HonkVerifier.sol -t evm
```

**Important:** Both commands need `-t evm` for EVM-compatible output.

## Regenerating Proof Fixture

The integration test uses `test/fixtures/proof.bin`:

```bash
cd circuits
nargo execute
bb prove -b target/thurin.json -w target/thurin.gz -k target/vk/vk -o target/proof -t evm
cp target/proof/proof ../contracts/test/fixtures/proof.bin
```

## Gas Estimates

| Operation | Gas |
|-----------|-----|
| `ThurinSBT.mint()` | ~2,700,000 |
| `ThurinVerifier.verify()` | ~2,600,000 |
| `ThurinSBT.isValid()` | ~3,000 |
| `addIACARoot()` | ~50,000 |

## Contract Addresses

### Sepolia (Testnet)

```
HonkVerifier:   0x65A8BEF0A58Ec557F77BE5Dd8A8dBE039159eD0d
ThurinSBT:      0x03812ef2AEF6666c14ce23EfDbF55bd4662BFbDf
ThurinVerifier: 0xee3312904bcf44ec69617c48118e530fEd0e5810
ThurinPoints:   0x8727531a2906b12474f67EC775E22741dEC188fd
```

### Ethereum Mainnet

```
TBD - not yet deployed
```

## License

Apache-2.0
