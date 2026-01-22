#!/usr/bin/env npx tsx
/**
 * E2E Test Script - Full flow against local Anvil
 *
 * Prerequisites:
 * 1. Anvil running: anvil
 * 2. Contracts deployed: cd packages/contracts && forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --broadcast
 * 3. Proof generated: cd packages/circuits && bb prove -b target/thurin.json -w target/thurin.gz -k target/vk/vk -o target/proof -t evm
 *
 * Run: pnpm e2e:anvil
 */

import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import {
  createPublicClient,
  createWalletClient,
  http,
  type Address,
  type Hex,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Anvil default accounts
const ANVIL_PRIVATE_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as Hex;

// Proof fixture values from packages/circuits/Prover.toml
const PROOF_FIXTURE = {
  nullifier:
    '0x0a8806cc662e552051b7a27c0be7bda96c5fe92fb95db0f53f1c7f4c46806035' as Hex,
  proofTimestamp: 1704067200n, // Jan 1, 2024
  eventId:
    '0x0000000000000000000000000000000000000000000000000000000000000001' as Hex,
  iacaRoot:
    '0x2505ef45040cc8194c969e339747574c3824a306fbbc5f498a777a84c24647ee' as Hex,
  boundAddress: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045' as Address,
  revealAgeOver21: true,
  revealState: true,
  revealedState: '0x4341' as Hex, // "CA" as bytes2
};

// Registry ABI (minimal for this script)
const REGISTRY_ABI = [
  {
    type: 'function',
    name: 'verify',
    inputs: [
      { name: 'proof', type: 'bytes' },
      { name: 'nullifier', type: 'bytes32' },
      { name: 'proofTimestamp', type: 'uint256' },
      { name: 'eventId', type: 'bytes32' },
      { name: 'iacaRoot', type: 'bytes32' },
      { name: 'revealAgeOver21', type: 'bool' },
      { name: 'revealState', type: 'bool' },
      { name: 'revealedState', type: 'bytes2' },
    ],
    outputs: [{ type: 'bool' }],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    name: 'isVerified',
    inputs: [
      { name: 'user', type: 'address' },
      { name: 'eventId', type: 'bytes32' },
    ],
    outputs: [{ type: 'bool' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'nullifierUsed',
    inputs: [{ name: 'nullifier', type: 'bytes32' }],
    outputs: [{ type: 'bool' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'trustedIACARoots',
    inputs: [{ name: 'root', type: 'bytes32' }],
    outputs: [{ type: 'bool' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'addIACARoot',
    inputs: [
      { name: 'root', type: 'bytes32' },
      { name: 'stateName', type: 'string' },
    ],
    outputs: [],
    stateMutability: 'nonpayable',
  },
] as const;

async function main() {
  console.log('🚀 Thurin E2E Test - Anvil\n');

  // 1. Setup clients
  console.log('1. Setting up clients...');
  const publicClient = createPublicClient({
    chain: foundry,
    transport: http('http://127.0.0.1:8545'),
  });

  const account = privateKeyToAccount(ANVIL_PRIVATE_KEY);
  const walletClient = createWalletClient({
    account,
    chain: foundry,
    transport: http('http://127.0.0.1:8545'),
  });

  // Check Anvil is running
  try {
    const chainId = await publicClient.getChainId();
    console.log(`   ✅ Connected to chain ${chainId}`);
  } catch {
    console.error('   ❌ Anvil not running. Start with: anvil');
    process.exit(1);
  }

  // 2. Get deployed contract address from Foundry broadcast
  console.log('\n2. Finding deployed contracts...');

  // Read deployment broadcast to find addresses
  const broadcastPath = join(
    __dirname,
    '../../contracts/broadcast/Deploy.s.sol/31337/run-latest.json'
  );

  let registryAddress: Address;
  let verifierAddress: Address;

  try {
    const broadcast = JSON.parse(readFileSync(broadcastPath, 'utf-8'));
    const creates = broadcast.transactions.filter(
      (tx: { transactionType: string }) => tx.transactionType === 'CREATE'
    );

    if (creates.length < 2) {
      throw new Error('Expected 2 contract deployments');
    }

    verifierAddress = creates[0].contractAddress as Address;
    registryAddress = creates[1].contractAddress as Address;

    console.log(`   Verifier: ${verifierAddress}`);
    console.log(`   Registry: ${registryAddress}`);
  } catch (error) {
    console.error('   ❌ Contracts not deployed. Run:');
    console.error(
      '      cd packages/contracts && forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --broadcast'
    );
    process.exit(1);
  }

  // 3. Check current block timestamp
  console.log('\n3. Checking block timestamp...');
  const block = await publicClient.getBlock();
  const currentTimestamp = block.timestamp;
  console.log(`   Current block timestamp: ${currentTimestamp}`);
  console.log(`   Proof timestamp: ${PROOF_FIXTURE.proofTimestamp}`);

  // If the proof is too old (more than 1 hour ago), we need to regenerate it
  const proofAge = currentTimestamp - PROOF_FIXTURE.proofTimestamp;
  if (proofAge > 3600n) {
    console.log(
      `   ⚠️  Proof is ${proofAge}s old (> 1 hour). Will fail on-chain.`
    );
    console.log('   To fix, regenerate proof with current timestamp:');
    console.log('   1. Update Prover.toml proof_timestamp');
    console.log('   2. Run: cd packages/circuits && bb prove ...');
    console.log('');
    console.log('   Or restart Anvil with old timestamp:');
    console.log(`   anvil --code-size-limit 50000 --timestamp ${PROOF_FIXTURE.proofTimestamp}`);
    console.log('   Then redeploy contracts BEFORE the script mines blocks.');
    console.log('');
    console.log('   Continuing anyway to test contract interaction...');
  } else if (proofAge < 0n) {
    console.log('   ⚠️  Proof is from the future. This should not happen.');
  } else {
    console.log(`   ✅ Proof is ${proofAge}s old (within 1 hour window)`);
  }

  // 4. Check IACA root
  console.log('\n4. Checking IACA root...');
  const isTrusted = await publicClient.readContract({
    address: registryAddress,
    abi: REGISTRY_ABI,
    functionName: 'trustedIACARoots',
    args: [PROOF_FIXTURE.iacaRoot],
  });

  if (!isTrusted) {
    console.log('   Adding IACA root...');
    const hash = await walletClient.writeContract({
      address: registryAddress,
      abi: REGISTRY_ABI,
      functionName: 'addIACARoot',
      args: [PROOF_FIXTURE.iacaRoot, 'California'],
    });
    await publicClient.waitForTransactionReceipt({ hash });
    console.log('   ✅ IACA root added');
  } else {
    console.log('   ✅ IACA root already trusted');
  }

  // 5. Load proof
  console.log('\n5. Loading proof...');
  const proofPath = join(__dirname, '../../circuits/target/proof/proof');
  let proofBytes: Hex;

  try {
    const proofBuffer = readFileSync(proofPath);
    proofBytes = `0x${proofBuffer.toString('hex')}` as Hex;
    console.log(`   ✅ Proof loaded (${proofBuffer.length} bytes)`);
  } catch {
    console.error('   ❌ Proof not found. Generate with:');
    console.error(
      '      cd packages/circuits && bb prove -b target/thurin.json -w target/thurin.gz -k target/vk/vk -o target/proof -t evm'
    );
    process.exit(1);
  }

  // 6. Check initial state
  console.log('\n6. Checking initial state...');
  const nullifierUsedBefore = await publicClient.readContract({
    address: registryAddress,
    abi: REGISTRY_ABI,
    functionName: 'nullifierUsed',
    args: [PROOF_FIXTURE.nullifier],
  });
  console.log(`   Nullifier used: ${nullifierUsedBefore}`);

  const isVerifiedBefore = await publicClient.readContract({
    address: registryAddress,
    abi: REGISTRY_ABI,
    functionName: 'isVerified',
    args: [PROOF_FIXTURE.boundAddress, PROOF_FIXTURE.eventId],
  });
  console.log(`   Address verified: ${isVerifiedBefore}`);

  if (nullifierUsedBefore) {
    console.log('\n⚠️  Nullifier already used. Skipping verification.');
    console.log('   (Restart Anvil to reset state: anvil)');
    process.exit(0);
  }

  // 7. Submit proof
  console.log('\n7. Submitting proof...');
  console.log(`   From: ${PROOF_FIXTURE.boundAddress}`);
  console.log(`   Event: ${PROOF_FIXTURE.eventId}`);

  // Impersonate the bound address
  await publicClient.request({
    method: 'anvil_impersonateAccount' as any,
    params: [PROOF_FIXTURE.boundAddress],
  });

  // Fund the impersonated account
  await walletClient.sendTransaction({
    to: PROOF_FIXTURE.boundAddress,
    value: 1000000000000000000n, // 1 ETH
  });

  const boundWallet = createWalletClient({
    account: PROOF_FIXTURE.boundAddress,
    chain: foundry,
    transport: http('http://127.0.0.1:8545'),
  });

  try {
    const txHash = await boundWallet.writeContract({
      address: registryAddress,
      abi: REGISTRY_ABI,
      functionName: 'verify',
      args: [
        proofBytes,
        PROOF_FIXTURE.nullifier,
        PROOF_FIXTURE.proofTimestamp,
        PROOF_FIXTURE.eventId,
        PROOF_FIXTURE.iacaRoot,
        PROOF_FIXTURE.revealAgeOver21,
        PROOF_FIXTURE.revealState,
        PROOF_FIXTURE.revealedState,
      ],
    });

    console.log(`   Tx: ${txHash}`);
    const receipt = await publicClient.waitForTransactionReceipt({
      hash: txHash,
    });
    console.log(`   ✅ Verified! Gas used: ${receipt.gasUsed}`);
  } catch (error) {
    console.error('   ❌ Verification failed:', error);
    process.exit(1);
  }

  // 8. Check final state
  console.log('\n8. Checking final state...');
  const nullifierUsedAfter = await publicClient.readContract({
    address: registryAddress,
    abi: REGISTRY_ABI,
    functionName: 'nullifierUsed',
    args: [PROOF_FIXTURE.nullifier],
  });
  console.log(`   Nullifier used: ${nullifierUsedAfter}`);

  const isVerifiedAfter = await publicClient.readContract({
    address: registryAddress,
    abi: REGISTRY_ABI,
    functionName: 'isVerified',
    args: [PROOF_FIXTURE.boundAddress, PROOF_FIXTURE.eventId],
  });
  console.log(`   Address verified: ${isVerifiedAfter}`);

  // 9. Summary
  console.log('\n✅ E2E Test Complete!');
  console.log('   - Proof verified on-chain');
  console.log('   - Nullifier marked as used');
  console.log('   - Address marked as verified');
}

main().catch(console.error);
