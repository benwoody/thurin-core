import { Noir } from '@noir-lang/noir_js';
import { UltraHonkBackend, Barretenberg } from '@aztec/bb.js';
import { keccak256, toHex, hexToBytes, type Address, type Hex } from 'viem';
import type {
  CompiledCircuit,
  Credential,
  ProofGenerationOptions,
  GeneratedProof,
} from './types.js';

// Must match circuit's STATE_CODE_OFFSET in main.nr
const STATE_CODE_OFFSET = 66;

// Singleton instances for reuse
let barretenbergAPI: Awaited<ReturnType<typeof Barretenberg.new>> | null = null;
let noir: Noir | null = null;
let backend: UltraHonkBackend | null = null;
let currentCircuit: CompiledCircuit | null = null;

/**
 * Initialize the prover with a compiled circuit
 *
 * @param circuit - Compiled Noir circuit (thurin.json)
 */
export async function initProver(circuit: CompiledCircuit): Promise<void> {
  // Skip if already initialized with same circuit
  if (currentCircuit === circuit && noir && backend) {
    return;
  }

  // Initialize Barretenberg WASM
  if (!barretenbergAPI) {
    barretenbergAPI = await Barretenberg.new();
  }

  // Initialize Noir with circuit
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  noir = new Noir(circuit as any);

  // Initialize proving backend
  backend = new UltraHonkBackend(circuit.bytecode, barretenbergAPI);
  currentCircuit = circuit;
}

/**
 * Check if the prover is initialized
 */
export function isProverInitialized(): boolean {
  return noir !== null && backend !== null;
}

/**
 * Generate a ZK proof from credential data
 *
 * @param credential - mDL credential data
 * @param options - Proof generation options
 * @returns Generated proof and public inputs
 */
export async function generateProof(
  credential: Credential,
  options: ProofGenerationOptions
): Promise<GeneratedProof> {
  if (!noir || !backend || !barretenbergAPI) {
    throw new Error('Prover not initialized. Call initProver() first.');
  }

  const timestamp = options.timestamp ?? Math.floor(Date.now() / 1000);

  // Build witness inputs matching circuit signature
  const witnessInputs = await buildWitnessInputs(barretenbergAPI, credential, options, timestamp);

  // Execute circuit to generate witness
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { witness } = await noir.execute(witnessInputs as any);

  // Generate proof using UltraHonk
  const proof = await backend.generateProof(witness);

  // Extract state code (2 ASCII chars) at offset matching circuit's STATE_CODE_OFFSET
  const stateCode = options.proveState
    ? String.fromCharCode(
        credential.stateClaimBytes[STATE_CODE_OFFSET] ?? 0,
        credential.stateClaimBytes[STATE_CODE_OFFSET + 1] ?? 0
      )
    : '\0\0';

  return {
    proof: toHex(proof.proof),
    publicInputs: {
      nullifier: witnessInputs.nullifier as Hex,
      proofTimestamp: BigInt(timestamp),
      eventId: witnessInputs.event_id as Hex,
      iacaRoot: witnessInputs.iaca_root as Hex,
      boundAddress: options.boundAddress,
      proveAgeOver21: options.proveAgeOver21 ?? false,
      proveAgeOver18: options.proveAgeOver18 ?? false,
      proveState: options.proveState ?? false,
      provenState: stateCode,
    },
  };
}

/**
 * Verify a proof locally (without submitting on-chain)
 */
export async function verifyProofLocally(proofBytes: Uint8Array): Promise<boolean> {
  if (!backend) {
    throw new Error('Prover not initialized. Call initProver() first.');
  }

  return backend.verifyProof({ proof: proofBytes, publicInputs: [] });
}

/**
 * Destroy the prover and free WASM resources
 */
export async function destroyProver(): Promise<void> {
  // UltraHonkBackend doesn't have destroy, just null the reference
  backend = null;

  if (barretenbergAPI) {
    await barretenbergAPI.destroy();
    barretenbergAPI = null;
  }
  noir = null;
  currentCircuit = null;
}

/**
 * Build witness inputs from credential and options
 */
async function buildWitnessInputs(
  bb: Barretenberg,
  credential: Credential,
  options: ProofGenerationOptions,
  timestamp: number
) {
  // Compute IACA root from public key using Poseidon2
  const iacaRoot = await computeIacaRoot(bb, credential.iacaPubkeyX, credential.iacaPubkeyY);

  // Hash event ID to bytes32
  const eventId = hashEventId(options.eventId);

  // Compute nullifier using Poseidon2
  const nullifier = await computeNullifier(bb, credential.documentNumber, eventId, iacaRoot);

  // State code at offset matching circuit's STATE_CODE_OFFSET (or zeros if not proving)
  const provenState = options.proveState
    ? [credential.stateClaimBytes[STATE_CODE_OFFSET] ?? 0, credential.stateClaimBytes[STATE_CODE_OFFSET + 1] ?? 0]
    : [0, 0];

  return {
    // Public inputs (must match circuit order)
    nullifier,
    proof_timestamp: timestamp,
    event_id: eventId,
    iaca_root: iacaRoot,
    bound_address: addressToField(options.boundAddress),
    prove_age_over_21: options.proveAgeOver21 ?? false,
    prove_age_over_18: options.proveAgeOver18 ?? false,
    prove_state: options.proveState ?? false,
    proven_state: provenState,

    // Private inputs
    mso_bytes: Array.from(credential.msoBytes),
    mso_signature: Array.from(credential.msoSignature),
    age_over_21_claim_bytes: Array.from(credential.ageOver21ClaimBytes),
    age_over_18_claim_bytes: Array.from(credential.ageOver18ClaimBytes),
    state_claim_bytes: Array.from(credential.stateClaimBytes),
    document_number: Array.from(credential.documentNumber),
    iaca_pubkey_x: Array.from(credential.iacaPubkeyX),
    iaca_pubkey_y: Array.from(credential.iacaPubkeyY),
  };
}

// BN254 field modulus (used by Noir circuits)
const BN254_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Hash event ID string to field element
 * keccak256 produces 256-bit values which may exceed BN254 modulus,
 * so we reduce modulo the field modulus
 */
function hashEventId(eventId: string): string {
  const hash = keccak256(toHex(eventId));
  const hashBigInt = BigInt(hash);
  const reduced = hashBigInt % BN254_MODULUS;
  return `0x${reduced.toString(16).padStart(64, '0')}`;
}

/**
 * Convert address to field element (as hex string)
 */
function addressToField(address: Address): string {
  // Address is 20 bytes, pad to 32 bytes
  return `0x${address.slice(2).toLowerCase().padStart(64, '0')}`;
}

/**
 * Pad a Uint8Array to 32 bytes (field element size)
 */
function padTo32Bytes(input: Uint8Array): Uint8Array {
  if (input.length >= 32) {
    return input.slice(0, 32);
  }
  const padded = new Uint8Array(32);
  padded.set(input, 32 - input.length); // Right-align (big-endian)
  return padded;
}

/**
 * Compute IACA root from public key coordinates using Poseidon2
 * Matches circuit's Poseidon2(pubkey_x, pubkey_y)
 */
async function computeIacaRoot(
  bb: Barretenberg,
  pubkeyX: Uint8Array,
  pubkeyY: Uint8Array
): Promise<string> {
  const result = await bb.poseidon2Hash({
    inputs: [padTo32Bytes(pubkeyX), padTo32Bytes(pubkeyY)],
  });
  return toHex(result.hash);
}

/**
 * Compute nullifier from document number, event ID, and IACA root using Poseidon2
 * Matches circuit's Poseidon2(doc_number, event_id, iaca_root)
 */
async function computeNullifier(
  bb: Barretenberg,
  documentNumber: Uint8Array,
  eventId: string,
  iacaRoot: string
): Promise<string> {
  const result = await bb.poseidon2Hash({
    inputs: [
      padTo32Bytes(documentNumber),
      hexToBytes(eventId as Hex),
      hexToBytes(iacaRoot as Hex),
    ],
  });
  return toHex(result.hash);
}
