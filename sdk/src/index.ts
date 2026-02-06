/**
 * Thurin SDK
 *
 * TypeScript SDK for generating and verifying mDL zero-knowledge proofs.
 */

import {
  type Address,
  type Hash,
  type Hex,
  type PublicClient,
  type WalletClient,
  createPublicClient,
  http,
} from 'viem';
import { base, baseSepolia, mainnet, arbitrum, sepolia } from 'viem/chains';
import {
  ThurinSBT,
  ThurinVerifier,
  ThurinPoints,
  hashEventId,
  NO_REFERRER,
  type ThurinProof,
  type ThurinPublicInputs,
  type SBTStatus,
} from './contract/index.js';
import {
  initProver,
  isProverInitialized,
  generateProof as proverGenerateProof,
  destroyProver,
  type CompiledCircuit,
  type Credential,
} from './prover/index.js';
import {
  requestCredential as requestCredentialFromWallet,
  parseCredential,
  toProverCredential,
  isDigitalCredentialsSupported,
  createMockCredential,
  type ClaimType,
  type CredentialRequestOptions,
  CredentialError,
} from './credential/index.js';

// Re-export contract types and classes
export type { ThurinProof, ThurinPublicInputs, SBTStatus };
export type { DappInfo, LeaderboardEntry, MintOptions } from './contract/index.js';
export {
  hashEventId,
  ThurinSBT,
  ThurinVerifier,
  ThurinPoints,
  NO_REFERRER,
  THURIN_SBT_ABI,
  THURIN_VERIFIER_ABI,
  THURIN_POINTS_ABI,
} from './contract/index.js';

// Re-export prover types and functions
export type { CompiledCircuit, Credential, GeneratedProof } from './prover/index.js';
export { initProver, isProverInitialized, destroyProver } from './prover/index.js';

// Re-export credential types and functions
export type { ClaimType, CredentialRequestOptions } from './credential/index.js';
export {
  isDigitalCredentialsSupported,
  createMockCredential,
  CredentialError,
} from './credential/index.js';

/**
 * Contract addresses for Thurin deployment
 */
export interface ThurinAddresses {
  sbt: Address;
  verifier: Address;
  points: Address;
}

/**
 * Configuration for the Thurin SDK
 */
export interface ThurinConfig {
  /** Chain ID (8453 for Base, 84532 for Base Sepolia, etc.) */
  chainId: number;
  /** Contract addresses */
  addresses: ThurinAddresses;
  /** Optional RPC URL (uses public RPC if not provided) */
  rpcUrl?: string;
  /** Optional PublicClient (created from rpcUrl if not provided) */
  publicClient?: PublicClient;
  /** Optional WalletClient for write operations */
  walletClient?: WalletClient;
  /** Optional compiled circuit (for proof generation) */
  circuit?: CompiledCircuit;
}

/**
 * Options for requesting an mDL credential
 */
export interface CredentialRequest {
  /** Which claims to request from the wallet */
  claims: ClaimType[];
  /** Optional nonce for freshness */
  nonce?: string;
}

/**
 * Options for generating a proof
 */
export interface ProofOptions {
  /** Application-specific event ID for nullifier scoping */
  eventId: string;
  /** Wallet address to bind the proof to */
  boundAddress: Address;
  /** Whether to prove age_over_21 */
  proveAgeOver21?: boolean;
  /** Whether to prove age_over_18 */
  proveAgeOver18?: boolean;
  /** Whether to prove state */
  proveState?: boolean;
  /** Optional timestamp override (defaults to now) */
  timestamp?: number;
}

/**
 * Get the viem chain config for a chain ID
 */
function getChain(chainId: number) {
  switch (chainId) {
    case 1:
      return mainnet;
    case 8453:
      return base;
    case 84532:
      return baseSepolia;
    case 42161:
      return arbitrum;
    case 11155111:
      return sepolia;
    default:
      throw new Error(`Unsupported chain ID: ${chainId}`);
  }
}

/**
 * Main Thurin client for mDL verification
 *
 * @example
 * ```typescript
 * import { Thurin, initProver } from '@thurinlabs/sdk';
 * import circuit from './thurin.json';
 *
 * // Initialize prover (once, on app load)
 * await initProver(circuit);
 *
 * const thurin = new Thurin({
 *   chainId: 8453,
 *   addresses: {
 *     sbt: '0x...',
 *     verifier: '0x...',
 *     points: '0x...',
 *   },
 * });
 *
 * // Mint SBT with proof
 * const mintTx = await thurin.mint(proof);
 *
 * // Check SBT status
 * const status = await thurin.getSBTStatus(userAddress);
 * ```
 */
export class Thurin {
  private readonly config: ThurinConfig;
  private readonly publicClient: PublicClient;
  private readonly sbt: ThurinSBT;
  private readonly verifier: ThurinVerifier;
  private readonly points: ThurinPoints;

  constructor(config: ThurinConfig) {
    this.config = config;

    // Create or use provided public client
    if (config.publicClient) {
      this.publicClient = config.publicClient;
    } else {
      const chain = getChain(config.chainId);
      this.publicClient = createPublicClient({
        chain,
        transport: http(config.rpcUrl),
      });
    }

    // Create contract wrappers
    this.sbt = new ThurinSBT(
      config.addresses.sbt,
      this.publicClient,
      config.walletClient
    );
    this.verifier = new ThurinVerifier(
      config.addresses.verifier,
      this.publicClient,
      config.walletClient
    );
    this.points = new ThurinPoints(
      config.addresses.points,
      this.publicClient,
      config.walletClient
    );

    // Auto-initialize prover if circuit provided
    if (config.circuit && !isProverInitialized()) {
      initProver(config.circuit).catch(() => {
        // Silently ignore - user will get error when calling generateProof
      });
    }
  }

  /**
   * Update the wallet client (e.g., after user connects wallet)
   */
  setWalletClient(walletClient: WalletClient): Thurin {
    return new Thurin({
      ...this.config,
      publicClient: this.publicClient,
      walletClient,
    });
  }

  /**
   * Get the underlying SBT contract wrapper
   */
  getSBT(): ThurinSBT {
    return this.sbt;
  }

  /**
   * Get the underlying verifier contract wrapper
   */
  getVerifier(): ThurinVerifier {
    return this.verifier;
  }

  /**
   * Get the underlying points contract wrapper
   */
  getPoints(): ThurinPoints {
    return this.points;
  }

  /**
   * Request mDL credential from user's wallet via Digital Credentials API
   *
   * @param options - Which claims to request
   * @returns Credential ready for proof generation
   * @throws CredentialError if not supported, user cancels, or no credential available
   */
  async requestCredential(options: CredentialRequest): Promise<Credential> {
    const rawCredential = await requestCredentialFromWallet({
      claims: options.claims,
      nonce: options.nonce,
    });
    const parsedCredential = parseCredential(rawCredential);
    return toProverCredential(parsedCredential);
  }

  /**
   * Check if the Digital Credentials API is available in this browser
   */
  static isCredentialApiSupported(): boolean {
    return isDigitalCredentialsSupported();
  }

  /**
   * Create a mock credential for testing (when real mDL is not available)
   */
  static createMockCredential(options?: {
    ageOver21?: boolean;
    state?: string;
    documentNumber?: string;
    expiryDate?: Date;
  }): Credential {
    return createMockCredential(options);
  }

  /**
   * Generate a ZK proof from the credential
   *
   * @param credential - mDL credential from requestCredential()
   * @param options - Proof options
   * @returns Proof ready for submission
   */
  async generateProof(
    credential: Credential,
    options: ProofOptions
  ): Promise<ThurinProof> {
    if (!isProverInitialized()) {
      throw new Error(
        'Prover not initialized. Call initProver(circuit) before generating proofs.'
      );
    }

    const result = await proverGenerateProof(credential, {
      eventId: options.eventId,
      boundAddress: options.boundAddress,
      timestamp: options.timestamp,
      proveAgeOver21: options.proveAgeOver21,
      proveAgeOver18: options.proveAgeOver18,
      proveState: options.proveState,
    });

    return {
      proof: result.proof,
      publicInputs: {
        nullifier: result.publicInputs.nullifier,
        addressBinding: result.publicInputs.addressBinding,
        proofDate: result.publicInputs.proofDate,
        eventId: result.publicInputs.eventId,
        iacaRoot: result.publicInputs.iacaRoot,
        boundAddress: result.publicInputs.boundAddress,
        proveAgeOver21: result.publicInputs.proveAgeOver21,
        proveAgeOver18: result.publicInputs.proveAgeOver18,
        proveState: result.publicInputs.proveState,
        provenState: result.publicInputs.provenState,
      },
    };
  }

  // ============ SBT Operations ============

  /**
   * Mint an SBT with a ZK proof
   * @returns Transaction hash
   */
  async mint(
    proof: ThurinProof,
    options?: { referrerTokenId?: bigint; gas?: bigint }
  ): Promise<Hash> {
    return this.sbt.mint(proof, options);
  }

  /**
   * Get the current mint price
   */
  async getMintPrice(): Promise<bigint> {
    return this.sbt.getMintPrice();
  }

  /**
   * Get SBT status for a user
   */
  async getSBTStatus(user: Address): Promise<SBTStatus> {
    return this.sbt.getStatus(user);
  }

  /**
   * Check if a user has a valid (non-expired) SBT
   */
  async hasValidSBT(user: Address): Promise<boolean> {
    return this.sbt.isValid(user);
  }

  /**
   * Check if a nullifier has been used
   */
  async nullifierUsed(nullifier: Hex): Promise<boolean> {
    return this.sbt.nullifierUsed(nullifier);
  }

  /**
   * Check if an IACA root is trusted
   */
  async isTrustedIACARoot(root: Hex): Promise<boolean> {
    return this.sbt.isTrustedIACARoot(root);
  }

  /**
   * Get the state name for an IACA root
   */
  async getIACAStateName(root: Hex): Promise<string> {
    return this.sbt.getIACAStateName(root);
  }

  // ============ Points Operations ============

  /**
   * Get user's points balance
   */
  async getUserPoints(user: Address): Promise<bigint> {
    return this.points.getUserPoints(user);
  }

  /**
   * Get dApp's total points
   */
  async getDappPoints(dapp: Address): Promise<bigint> {
    return this.points.getTotalDappPoints(dapp);
  }

  /**
   * Get the leaderboard
   */
  async getLeaderboard(limit: number = 10) {
    return this.points.getTopDapps(limit);
  }
}
