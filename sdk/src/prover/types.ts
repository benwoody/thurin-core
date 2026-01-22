import type { Hex, Address } from 'viem';

/**
 * Compiled Noir circuit artifact
 */
export interface CompiledCircuit {
  abi: {
    parameters: Array<{
      name: string;
      type: { kind: string };
      visibility: string;
    }>;
  };
  bytecode: string;
}

/**
 * Raw mDL credential data extracted from wallet
 */
export interface Credential {
  /** MSO (Mobile Security Object) bytes */
  msoBytes: Uint8Array;
  /** ECDSA signature over MSO */
  msoSignature: Uint8Array;
  /** Age over 21 claim CBOR bytes */
  ageOver21ClaimBytes: Uint8Array;
  /** Age over 18 claim CBOR bytes */
  ageOver18ClaimBytes: Uint8Array;
  /** State claim CBOR bytes */
  stateClaimBytes: Uint8Array;
  /** Document number (private, used for nullifier) */
  documentNumber: Uint8Array;
  /** IACA public key X coordinate */
  iacaPubkeyX: Uint8Array;
  /** IACA public key Y coordinate */
  iacaPubkeyY: Uint8Array;
}

/**
 * Options for generating a proof
 */
export interface ProofGenerationOptions {
  /** Application-specific event ID */
  eventId: string;
  /** Wallet address to bind proof to */
  boundAddress: Address;
  /** Current timestamp (defaults to now) */
  timestamp?: number;
  /** Whether to prove age_over_21 */
  proveAgeOver21?: boolean;
  /** Whether to prove age_over_18 */
  proveAgeOver18?: boolean;
  /** Whether to prove state */
  proveState?: boolean;
}

/**
 * Generated proof data
 */
export interface GeneratedProof {
  /** Raw proof bytes */
  proof: Hex;
  /** Public inputs */
  publicInputs: {
    nullifier: Hex;
    proofTimestamp: bigint;
    eventId: Hex;
    iacaRoot: Hex;
    boundAddress: Address;
    proveAgeOver21: boolean;
    proveAgeOver18: boolean;
    proveState: boolean;
    provenState: string;
  };
}
