import {
  type Address,
  type Hash,
  type Hex,
  type PublicClient,
  type WalletClient,
  toHex,
} from 'viem';
import { THURIN_SBT_ABI } from './abi.js';

/** No referrer constant - use this when minting without a referral */
export const NO_REFERRER = BigInt(
  '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
);

/**
 * Public inputs for a Thurin proof
 */
export interface ThurinPublicInputs {
  nullifier: Hex;
  addressBinding: Hex;
  proofDate: number;
  eventId: Hex;
  iacaRoot: Hex;
  boundAddress: Address;
  proveAgeOver21: boolean;
  proveAgeOver18: boolean;
  proveState: boolean;
  provenState: string; // 2-char state code like "CA"
}

/**
 * A complete Thurin proof ready for submission
 */
export interface ThurinProof {
  proof: Hex;
  publicInputs: ThurinPublicInputs;
}

/**
 * Options for minting an SBT
 */
export interface MintOptions {
  /** Referrer token ID (use NO_REFERRER for none) */
  referrerTokenId?: bigint;
  /** Gas limit override */
  gas?: bigint;
}

/**
 * SBT status for a user
 */
export interface SBTStatus {
  hasSBT: boolean;
  isValid: boolean;
  tokenId: bigint;
  expiry: bigint;
  points: bigint;
}

/**
 * ThurinSBT contract wrapper
 */
export class ThurinSBT {
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
   * Mint an SBT with a ZK proof
   * @returns Transaction hash
   */
  async mint(proof: ThurinProof, options?: MintOptions): Promise<Hash> {
    if (!this.walletClient) {
      throw new Error('WalletClient required for write operations');
    }

    const { publicInputs } = proof;
    const stateBytes = stateToBytes2(publicInputs.provenState);
    const price = await this.getMintPrice();

    const hash = await this.walletClient.writeContract({
      address: this.address,
      abi: THURIN_SBT_ABI,
      functionName: 'mint',
      args: [
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
        options?.referrerTokenId ?? NO_REFERRER,
      ],
      value: price,
      gas: options?.gas,
    });

    return hash;
  }

  /**
   * Check if a user has a valid (non-expired) SBT
   */
  async isValid(user: Address): Promise<boolean> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: THURIN_SBT_ABI,
      functionName: 'isValid',
      args: [user],
    });
    return result as boolean;
  }

  /**
   * Get the expiry timestamp for a user's SBT
   */
  async getExpiry(user: Address): Promise<bigint> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: THURIN_SBT_ABI,
      functionName: 'getExpiry',
      args: [user],
    });
    return result as bigint;
  }

  /**
   * Get the current mint price
   */
  async getMintPrice(): Promise<bigint> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: THURIN_SBT_ABI,
      functionName: 'getMintPrice',
    });
    return result as bigint;
  }

  /**
   * Get the total supply of minted SBTs
   */
  async totalSupply(): Promise<bigint> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: THURIN_SBT_ABI,
      functionName: 'totalSupply',
    });
    return result as bigint;
  }

  /**
   * Get user's points balance
   */
  async getPoints(user: Address): Promise<bigint> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: THURIN_SBT_ABI,
      functionName: 'points',
      args: [user],
    });
    return result as bigint;
  }

  /**
   * Get user's token ID
   */
  async getTokenId(user: Address): Promise<bigint> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: THURIN_SBT_ABI,
      functionName: 'userTokenId',
      args: [user],
    });
    return result as bigint;
  }

  /**
   * Check if a nullifier has been used
   */
  async nullifierUsed(nullifier: Hex): Promise<boolean> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: THURIN_SBT_ABI,
      functionName: 'nullifierUsed',
      args: [nullifier],
    });
    return result as boolean;
  }

  /**
   * Check if an IACA root is trusted
   */
  async isTrustedIACARoot(root: Hex): Promise<boolean> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: THURIN_SBT_ABI,
      functionName: 'trustedIACARoots',
      args: [root],
    });
    return result as boolean;
  }

  /**
   * Get the state name for an IACA root
   */
  async getIACAStateName(root: Hex): Promise<string> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: THURIN_SBT_ABI,
      functionName: 'iacaStateNames',
      args: [root],
    });
    return result as string;
  }

  /**
   * Get referral count for a token
   */
  async getReferralCount(tokenId: bigint): Promise<bigint> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: THURIN_SBT_ABI,
      functionName: 'referralCount',
      args: [tokenId],
    });
    return result as bigint;
  }

  /**
   * Get full SBT status for a user
   */
  async getStatus(user: Address): Promise<SBTStatus> {
    const [balance, isValidResult, tokenId, expiry, points] = await Promise.all(
      [
        this.publicClient.readContract({
          address: this.address,
          abi: THURIN_SBT_ABI,
          functionName: 'balanceOf',
          args: [user],
        }),
        this.isValid(user),
        this.getTokenId(user),
        this.getExpiry(user),
        this.getPoints(user),
      ]
    );

    return {
      hasSBT: (balance as bigint) > 0n,
      isValid: isValidResult,
      tokenId,
      expiry,
      points,
    };
  }

  /**
   * Renew an existing SBT with a fresh ZK proof
   * @returns Transaction hash
   */
  async renew(proof: ThurinProof, options?: { gas?: bigint }): Promise<Hash> {
    if (!this.walletClient) {
      throw new Error('WalletClient required for write operations');
    }

    const { publicInputs } = proof;
    const stateBytes = stateToBytes2(publicInputs.provenState);
    const price = await this.getRenewalPrice();

    const hash = await this.walletClient.writeContract({
      address: this.address,
      abi: THURIN_SBT_ABI,
      functionName: 'renew',
      args: [
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
      value: price,
      gas: options?.gas,
    });

    return hash;
  }

  /**
   * Burn your SBT (frees nullifier for re-minting)
   * @returns Transaction hash
   */
  async burn(options?: { gas?: bigint }): Promise<Hash> {
    if (!this.walletClient) {
      throw new Error('WalletClient required for write operations');
    }

    const hash = await this.walletClient.writeContract({
      address: this.address,
      abi: THURIN_SBT_ABI,
      functionName: 'burn',
      args: [],
      gas: options?.gas,
    });

    return hash;
  }

  /**
   * Get the current renewal price
   */
  async getRenewalPrice(): Promise<bigint> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: THURIN_SBT_ABI,
      functionName: 'getRenewalPrice',
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
