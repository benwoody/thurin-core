import { describe, it, expect, beforeEach, afterEach, beforeAll } from 'vitest';
import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import {
  initProver,
  isProverInitialized,
  destroyProver,
  generateProof,
} from '../src/prover/index.js';
import type { Credential, CompiledCircuit } from '../src/prover/index.js';
import type { Address } from 'viem';

// Mock circuit for testing (won't actually prove, but tests API)
const mockCircuit: CompiledCircuit = {
  abi: {
    parameters: [
      { name: 'nullifier', type: { kind: 'field' }, visibility: 'public' },
      { name: 'proof_timestamp', type: { kind: 'field' }, visibility: 'public' },
    ],
  },
  bytecode: 'H4sIAAAAAAAA/wvIL0pVSM7PS0nMS1dIyy9KUQQABwpnTRIAAAA=', // minimal valid base64
};

// Mock credential for testing with correct field names and sizes
// State claim bytes need to have "CA" at offset 66 (STATE_CODE_OFFSET in circuit)
const STATE_CODE_OFFSET = 66;
const mockStateClaimBytes = new Uint8Array(107); // Size matching circuit's STATE_CLAIM_LEN
mockStateClaimBytes[STATE_CODE_OFFSET] = 67;     // 'C'
mockStateClaimBytes[STATE_CODE_OFFSET + 1] = 65; // 'A'

const mockCredential: Credential = {
  msoBytes: new Uint8Array(512),
  msoSignature: new Uint8Array(64),
  ageOver21ClaimBytes: new Uint8Array(96),  // Size matching circuit's AGE_OVER_21_CLAIM_LEN
  ageOver18ClaimBytes: new Uint8Array(96),  // Size matching circuit's AGE_OVER_18_CLAIM_LEN
  stateClaimBytes: mockStateClaimBytes,
  documentNumber: new Uint8Array(32),
  iacaPubkeyX: new Uint8Array(32),
  iacaPubkeyY: new Uint8Array(32),
};

describe('Prover Module Exports', () => {
  it('exports initProver function', () => {
    expect(initProver).toBeDefined();
    expect(typeof initProver).toBe('function');
  });

  it('exports isProverInitialized function', () => {
    expect(isProverInitialized).toBeDefined();
    expect(typeof isProverInitialized).toBe('function');
  });

  it('exports destroyProver function', () => {
    expect(destroyProver).toBeDefined();
    expect(typeof destroyProver).toBe('function');
  });
});

describe('Prover State', () => {
  afterEach(async () => {
    await destroyProver();
  });

  it('isProverInitialized returns false when not initialized', () => {
    expect(isProverInitialized()).toBe(false);
  });

  it('destroyProver resets state', async () => {
    await destroyProver();
    expect(isProverInitialized()).toBe(false);
  });
});

describe('Credential Type', () => {
  it('has expected shape', () => {
    expect(mockCredential.msoBytes).toBeInstanceOf(Uint8Array);
    expect(mockCredential.msoSignature).toBeInstanceOf(Uint8Array);
    expect(mockCredential.ageOver21ClaimBytes).toBeInstanceOf(Uint8Array);
    expect(mockCredential.ageOver18ClaimBytes).toBeInstanceOf(Uint8Array);
    expect(mockCredential.stateClaimBytes).toBeInstanceOf(Uint8Array);
    expect(mockCredential.documentNumber).toBeInstanceOf(Uint8Array);
    expect(mockCredential.iacaPubkeyX).toBeInstanceOf(Uint8Array);
    expect(mockCredential.iacaPubkeyY).toBeInstanceOf(Uint8Array);
  });

  it('state claim bytes contain valid state code at correct offset', () => {
    // State code is at STATE_CODE_OFFSET (66) in the claim bytes, matching circuit
    const stateCode = String.fromCharCode(
      mockCredential.stateClaimBytes[STATE_CODE_OFFSET] ?? 0,
      mockCredential.stateClaimBytes[STATE_CODE_OFFSET + 1] ?? 0
    );
    expect(stateCode).toBe('CA');
  });
});

describe('CompiledCircuit Type', () => {
  it('has expected shape', () => {
    expect(mockCircuit.abi).toBeDefined();
    expect(mockCircuit.abi.parameters).toBeInstanceOf(Array);
    expect(mockCircuit.bytecode).toBeDefined();
    expect(typeof mockCircuit.bytecode).toBe('string');
  });
});

/**
 * Pad array to specified length with zeros
 */
function padArray(arr: number[], targetLength: number): number[] {
  if (arr.length >= targetLength) return arr.slice(0, targetLength);
  return [...arr, ...new Array(targetLength - arr.length).fill(0)];
}

/**
 * Integration test with real circuit and test vectors.
 *
 * This test requires:
 * 1. Compiled circuit at packages/circuits/target/thurin.json
 * 2. Test vectors at packages/test-vectors/fixtures/california-over21.json
 *
 * Run with: pnpm test (skipped by default in CI due to long runtime)
 * To run explicitly: pnpm test -- --run prover.test.ts
 */
describe.skip('Prover Integration', () => {
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const circuitPath = join(__dirname, '../../circuits/target/thurin.json');
  const fixturesPath = join(__dirname, '../../test-vectors/fixtures/california-over21.json');

  let circuit: CompiledCircuit;
  let testVector: {
    iacaKey: {
      publicKeyX: number[];
      publicKeyY: number[];
    };
    claims: {
      ageOver21: { bytes: number[] };
      ageOver18: { bytes: number[] };
      issuingJurisdiction: { bytes: number[] };
    };
    mso: {
      bytes: number[];
      signature: number[];
    };
    documentNumber: number[];
  };

  beforeAll(() => {
    // Check if circuit exists
    if (!existsSync(circuitPath)) {
      throw new Error(
        'Compiled circuit not found. Run:\n' +
        '  cd packages/circuits && nargo compile'
      );
    }

    // Check if test vectors exist
    if (!existsSync(fixturesPath)) {
      throw new Error(
        'Test vectors not found. Run:\n' +
        '  pnpm generate-fixtures'
      );
    }

    // Load circuit and test vectors
    circuit = JSON.parse(readFileSync(circuitPath, 'utf-8'));
    testVector = JSON.parse(readFileSync(fixturesPath, 'utf-8'));
  });

  afterEach(async () => {
    await destroyProver();
  });

  it('should initialize prover with real circuit', async () => {
    await initProver(circuit);
    expect(isProverInitialized()).toBe(true);
  });

  it('should build credential from test vector', () => {
    // Pad arrays to circuit-expected sizes
    const credential: Credential = {
      msoBytes: new Uint8Array(padArray(testVector.mso.bytes, 512)),
      msoSignature: new Uint8Array(testVector.mso.signature),
      ageOver21ClaimBytes: new Uint8Array(testVector.claims.ageOver21.bytes),
      ageOver18ClaimBytes: new Uint8Array(testVector.claims.ageOver18.bytes),
      stateClaimBytes: new Uint8Array(testVector.claims.issuingJurisdiction.bytes),
      documentNumber: new Uint8Array(testVector.documentNumber),
      iacaPubkeyX: new Uint8Array(padArray(testVector.iacaKey.publicKeyX, 32)),
      iacaPubkeyY: new Uint8Array(padArray(testVector.iacaKey.publicKeyY, 32)),
    };

    // Verify credential has correct sizes for circuit
    expect(credential.msoBytes.length).toBe(512);
    expect(credential.msoSignature.length).toBe(64);
    expect(credential.ageOver21ClaimBytes.length).toBe(96);
    expect(credential.ageOver18ClaimBytes.length).toBe(96);
    expect(credential.stateClaimBytes.length).toBe(107);
    expect(credential.documentNumber.length).toBe(32);
    expect(credential.iacaPubkeyX.length).toBe(32);
    expect(credential.iacaPubkeyY.length).toBe(32);

    // Verify state code at correct offset
    const stateCode = String.fromCharCode(
      credential.stateClaimBytes[STATE_CODE_OFFSET],
      credential.stateClaimBytes[STATE_CODE_OFFSET + 1]
    );
    expect(stateCode).toBe('CA');
  });

  it('should generate proof with test vector credential', async () => {
    await initProver(circuit);

    // Pad arrays to circuit-expected sizes
    const credential: Credential = {
      msoBytes: new Uint8Array(padArray(testVector.mso.bytes, 512)),
      msoSignature: new Uint8Array(testVector.mso.signature),
      ageOver21ClaimBytes: new Uint8Array(testVector.claims.ageOver21.bytes),
      ageOver18ClaimBytes: new Uint8Array(testVector.claims.ageOver18.bytes),
      stateClaimBytes: new Uint8Array(testVector.claims.issuingJurisdiction.bytes),
      documentNumber: new Uint8Array(testVector.documentNumber),
      iacaPubkeyX: new Uint8Array(padArray(testVector.iacaKey.publicKeyX, 32)),
      iacaPubkeyY: new Uint8Array(padArray(testVector.iacaKey.publicKeyY, 32)),
    };

    const result = await generateProof(credential, {
      eventId: 'test-event-2024',
      boundAddress: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045' as Address,
      timestamp: 1704067200, // Fixed timestamp for reproducibility
      proveAgeOver21: true,
      proveAgeOver18: true,
      proveState: true,
    });

    // Verify proof was generated
    expect(result.proof).toBeDefined();
    expect(result.proof.startsWith('0x')).toBe(true);
    expect(result.proof.length).toBeGreaterThan(100);

    // Verify public inputs
    expect(result.publicInputs.nullifier).toBeDefined();
    expect(result.publicInputs.nullifier.startsWith('0x')).toBe(true);
    expect(result.publicInputs.proofTimestamp).toBe(1704067200n);
    expect(result.publicInputs.eventId).toBeDefined();
    expect(result.publicInputs.iacaRoot).toBeDefined();
    expect(result.publicInputs.boundAddress).toBe('0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045');
    expect(result.publicInputs.proveAgeOver21).toBe(true);
    expect(result.publicInputs.proveAgeOver18).toBe(true);
    expect(result.publicInputs.proveState).toBe(true);
    expect(result.publicInputs.provenState).toBe('CA');

    console.log('Generated proof nullifier:', result.publicInputs.nullifier);
    console.log('Generated proof IACA root:', result.publicInputs.iacaRoot);
  }, 120000); // 2 minute timeout for proof generation
});
