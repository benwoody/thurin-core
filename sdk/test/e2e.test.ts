/**
 * E2E Test - Full flow against local Anvil
 *
 * This test requires:
 * 1. Anvil running: anvil --code-size-limit 50000 --timestamp 1704067200
 * 2. Contracts deployed: cd packages/contracts && forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --broadcast --code-size-limit 50000
 *
 * Run with: pnpm test:e2e
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  createPublicClient,
  createWalletClient,
  http,
  type Address,
  type Hex,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';
import { ThurinSBT, ThurinVerifier, THURIN_SBT_ABI, hashEventId, NO_REFERRER } from '../src/index.js';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// Anvil default accounts
const ANVIL_PRIVATE_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as Hex;

// Proof fixture values from packages/circuits/Prover.toml
const PROOF_FIXTURE = {
  nullifier:
    '0x1ca63d2c7aa6f7fd4b51b6e0fad8d2c4aa37f5ed994521ada76c1d39fdee89df' as Hex,
  addressBinding:
    '0x0000000000000000000000000000000000000000000000000000000000000000' as Hex, // placeholder - compute with real fixture
  proofDate: 20240101, // Jan 1, 2024 in YYYYMMDD
  eventId: '0x0000000000000000000000000000000000000000000000000000000000000001' as Hex,
  iacaRoot:
    '0x2417f53cd9ead423f21f71a17726d2de8e1642521d5e8fa0bc4593240d7f2de6' as Hex,
  boundAddress: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045' as Address,
  proveAgeOver21: true,
  proveAgeOver18: true,
  proveState: true,
  provenState: '0x4341' as Hex, // "CA" in bytes2 (0x43='C', 0x41='A')
};

// Expected contract addresses from deterministic deployment
const EXPECTED_ADDRESSES = {
  honkVerifier: '0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512' as Address,
  sbt: '0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0' as Address,
  verifier: '0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9' as Address,
  points: '0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9' as Address,
};

// This test is skipped by default - run with: pnpm test:e2e
describe.skip('E2E: Anvil Integration', () => {
  let publicClient: ReturnType<typeof createPublicClient>;
  let walletClient: ReturnType<typeof createWalletClient>;
  let sbt: ThurinSBT;
  let verifier: ThurinVerifier;
  let proofBytes: Hex;

  beforeAll(async () => {
    // Check if Anvil is running
    publicClient = createPublicClient({
      chain: foundry,
      transport: http('http://127.0.0.1:8545'),
    });

    try {
      await publicClient.getChainId();
    } catch {
      throw new Error(
        'Anvil is not running. Start with:\n' +
        '  anvil --code-size-limit 50000 --timestamp 1704067200\n\n' +
        'Then deploy contracts with:\n' +
        '  cd packages/contracts && forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --broadcast --code-size-limit 50000'
      );
    }

    // Create wallet client with Anvil default account
    const account = privateKeyToAccount(ANVIL_PRIVATE_KEY);
    walletClient = createWalletClient({
      account,
      chain: foundry,
      transport: http('http://127.0.0.1:8545'),
    });

    // Verify contracts are deployed
    const sbtCode = await publicClient.getCode({ address: EXPECTED_ADDRESSES.sbt });
    if (!sbtCode || sbtCode === '0x') {
      throw new Error(
        'Contracts not deployed. Run:\n' +
        '  cd packages/contracts && forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --broadcast --code-size-limit 50000'
      );
    }

    // Initialize SDK wrappers
    sbt = new ThurinSBT(EXPECTED_ADDRESSES.sbt, publicClient, walletClient);
    verifier = new ThurinVerifier(EXPECTED_ADDRESSES.verifier, publicClient, walletClient);

    // Load proof from fixtures
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const proofPath = join(__dirname, '../../contracts/test/fixtures/proof.bin');
    try {
      const proofBuffer = readFileSync(proofPath);
      proofBytes = `0x${proofBuffer.toString('hex')}` as Hex;
    } catch {
      throw new Error(
        'Proof fixture not found. Generate with:\n' +
        '  cd packages/circuits && bb prove -b target/thurin.json -w target/thurin.gz -k target/vk/vk -o target/proof -t evm\n' +
        '  cp target/proof/proof ../contracts/test/fixtures/proof.bin'
      );
    }
  });

  it('should check IACA root is trusted', async () => {
    const isTrusted = await sbt.isTrustedIACARoot(PROOF_FIXTURE.iacaRoot);
    expect(isTrusted).toBe(true);
  });

  it('should check nullifier is not used initially', async () => {
    const isUsed = await sbt.nullifierUsed(PROOF_FIXTURE.nullifier);
    expect(isUsed).toBe(false);
  });

  it('should get mint price', async () => {
    const price = await sbt.getMintPrice();
    expect(price).toBeGreaterThan(0n);
    console.log('Mint price:', price, 'wei');
  });

  it('should mint SBT with valid proof', async () => {
    // Fund the bound address (vitalik.eth for test fixture)
    const fundTx = await walletClient.sendTransaction({
      to: PROOF_FIXTURE.boundAddress,
      value: 1000000000000000000n, // 1 ETH
    });
    await publicClient.waitForTransactionReceipt({ hash: fundTx });

    // Create wallet client for the bound address
    // Note: In real usage, this would be the user's wallet
    // For testing, we impersonate via Anvil
    const boundWalletClient = createWalletClient({
      account: PROOF_FIXTURE.boundAddress,
      chain: foundry,
      transport: http('http://127.0.0.1:8545'),
    });

    // Impersonate the bound address on Anvil
    await publicClient.request({
      method: 'anvil_impersonateAccount' as any,
      params: [PROOF_FIXTURE.boundAddress],
    });

    const sbtForBoundAddress = new ThurinSBT(
      EXPECTED_ADDRESSES.sbt,
      publicClient,
      boundWalletClient
    );

    // Get mint price
    const price = await sbt.getMintPrice();

    // Mint SBT
    const proof = {
      proof: proofBytes,
      publicInputs: {
        nullifier: PROOF_FIXTURE.nullifier,
        addressBinding: PROOF_FIXTURE.addressBinding,
        proofDate: PROOF_FIXTURE.proofDate,
        eventId: PROOF_FIXTURE.eventId,
        iacaRoot: PROOF_FIXTURE.iacaRoot,
        boundAddress: PROOF_FIXTURE.boundAddress,
        proveAgeOver21: PROOF_FIXTURE.proveAgeOver21,
        proveAgeOver18: PROOF_FIXTURE.proveAgeOver18,
        proveState: PROOF_FIXTURE.proveState,
        provenState: 'CA',
      },
    };

    const txHash = await sbtForBoundAddress.mint(proof, {
      referrerTokenId: NO_REFERRER,
    });
    console.log('Mint tx hash:', txHash);

    const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
    expect(receipt.status).toBe('success');

    // Stop impersonation
    await publicClient.request({
      method: 'anvil_stopImpersonatingAccount' as any,
      params: [PROOF_FIXTURE.boundAddress],
    });
  });

  it('should mark nullifier as used after mint', async () => {
    const isUsed = await sbt.nullifierUsed(PROOF_FIXTURE.nullifier);
    expect(isUsed).toBe(true);
  });

  it('should show user has valid SBT', async () => {
    const isValid = await sbt.isValid(PROOF_FIXTURE.boundAddress);
    expect(isValid).toBe(true);
  });

  it('should get user SBT status', async () => {
    const status = await sbt.getStatus(PROOF_FIXTURE.boundAddress);
    expect(status.hasSBT).toBe(true);
    expect(status.isValid).toBe(true);
    expect(status.tokenId).toBe(0n);
    expect(status.points).toBe(100n); // MINT_POINTS
    console.log('User SBT status:', status);
  });

  it('should verify user via ThurinVerifier', async () => {
    const hasValidSBT = await verifier.hasValidSBT(PROOF_FIXTURE.boundAddress);
    expect(hasValidSBT).toBe(true);
  });
});

// Standalone test that can run without Anvil - uses mocks
describe('E2E: SDK Integration (mocked)', () => {
  it('hashEventId produces consistent results', () => {
    const eventId1 = hashEventId('my-event');
    const eventId2 = hashEventId('my-event');
    expect(eventId1).toBe(eventId2);
  });

  it('hashEventId produces different results for different events', () => {
    const eventId1 = hashEventId('event-a');
    const eventId2 = hashEventId('event-b');
    expect(eventId1).not.toBe(eventId2);
  });

  it('ThurinSBT can be instantiated', () => {
    const mockClient = {} as any;
    const sbt = new ThurinSBT(
      '0x1234567890123456789012345678901234567890',
      mockClient
    );
    expect(sbt).toBeDefined();
  });
});
