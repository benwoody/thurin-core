import {
  type Address,
  type Hash,
  type Hex,
  type PublicClient,
  type WalletClient,
  toHex,
} from 'viem';
import { THURIN_VERIFIER_ABI } from './abi.js';
import type { ThurinProof } from './sbt.js';

/**
 * ThurinVerifier contract wrapper - for dApp verification
 * Privacy-preserving: returns only true/false, no events
 */
export class ThurinVerifier {
  public readonly address: Address;
  private readonly publicClient: PublicClient;
  private readonly walletClient?: WalletClient;

  constructor(
    address: Address,
    publicClient: PublicClient,
    walletClient?: WalletClient
  ) {
    this.address = address;
    this.publicClient = publicClient;
    this.walletClient = walletClient;
  }

  /**
   * Verify a user's proof (requires user to have valid SBT)
   * @returns Transaction hash
   * @throws NoValidSBT, InvalidProof, ProofExpired, ProofFromFuture
   */
  async verify(
    user: Address,
    proof: ThurinProof,
    options?: { gas?: bigint }
  ): Promise<Hash> {
    if (!this.walletClient) {
      throw new Error('WalletClient required for write operations');
    }

    const { publicInputs } = proof;
    const stateBytes = stateToBytes2(publicInputs.provenState);

    const hash = await this.walletClient.writeContract({
      address: this.address,
      abi: THURIN_VERIFIER_ABI,
      functionName: 'verify',
      args: [
        user,
        proof.proof,
        publicInputs.nullifier,
        publicInputs.addressBinding,
        publicInputs.proofDate,
        publicInputs.eventId,
        publicInputs.iacaRoot,
        publicInputs.proveAgeOver21,
        publicInputs.proveAgeOver18,
        publicInputs.proveState,
        stateBytes,
      ],
      gas: options?.gas,
    });

    return hash;
  }

  /**
   * Check if a user has a valid SBT
   */
  async hasValidSBT(user: Address): Promise<boolean> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: THURIN_VERIFIER_ABI,
      functionName: 'hasValidSBT',
      args: [user],
    });
    return result as boolean;
  }

  /**
   * Get the SBT expiry timestamp for a user
   */
  async getSBTExpiry(user: Address): Promise<bigint> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: THURIN_VERIFIER_ABI,
      functionName: 'getSBTExpiry',
      args: [user],
    });
    return result as bigint;
  }

  /**
   * Get the verification count for a dApp
   */
  async getDappVerificationCount(dapp: Address): Promise<bigint> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: THURIN_VERIFIER_ABI,
      functionName: 'dappVerificationCount',
      args: [dapp],
    });
    return result as bigint;
  }

  /**
   * Get the proof date tolerance (in days)
   */
  async getProofDateToleranceDays(): Promise<bigint> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: THURIN_VERIFIER_ABI,
      functionName: 'PROOF_DATE_TOLERANCE_DAYS',
    });
    return result as bigint;
  }
}

/**
 * Convert a 2-char state code to bytes2
 */
function stateToBytes2(state: string): Hex {
  if (state.length === 0) {
    return '0x0000';
  }
  if (state.length !== 2) {
    throw new Error('State code must be exactly 2 characters');
  }
  const bytes = new Uint8Array([state.charCodeAt(0), state.charCodeAt(1)]);
  return toHex(bytes) as Hex;
}
