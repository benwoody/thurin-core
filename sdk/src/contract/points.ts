import {
  type Address,
  type Hash,
  type PublicClient,
  type WalletClient,
} from 'viem';
import { THURIN_POINTS_ABI } from './abi.js';

/**
 * dApp info from the registry
 */
export interface DappInfo {
  name: string;
  points: bigint;
  verifications: bigint;
}

/**
 * Leaderboard entry
 */
export interface LeaderboardEntry {
  dapp: Address;
  verifications: bigint;
}

/**
 * ThurinPoints contract wrapper - for dApp points tracking
 */
export class ThurinPoints {
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
   * Register a dApp with a name
   * @returns Transaction hash
   */
  async registerDapp(name: string, options?: { gas?: bigint }): Promise<Hash> {
    if (!this.walletClient) {
      throw new Error('WalletClient required for write operations');
    }

    const hash = await this.walletClient.writeContract({
      address: this.address,
      abi: THURIN_POINTS_ABI,
      functionName: 'registerDapp',
      args: [name],
      gas: options?.gas,
    });

    return hash;
  }

  /**
   * Claim points for a dApp's verifications
   * @returns Transaction hash
   */
  async claimDappPoints(
    dapp: Address,
    options?: { gas?: bigint }
  ): Promise<Hash> {
    if (!this.walletClient) {
      throw new Error('WalletClient required for write operations');
    }

    const hash = await this.walletClient.writeContract({
      address: this.address,
      abi: THURIN_POINTS_ABI,
      functionName: 'claimDappPoints',
      args: [dapp],
      gas: options?.gas,
    });

    return hash;
  }

  /**
   * Get pending (unclaimed) points for a dApp
   */
  async getPendingDappPoints(dapp: Address): Promise<bigint> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: THURIN_POINTS_ABI,
      functionName: 'pendingDappPoints',
      args: [dapp],
    });
    return result as bigint;
  }

  /**
   * Get total dApp points (claimed + pending)
   */
  async getTotalDappPoints(dapp: Address): Promise<bigint> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: THURIN_POINTS_ABI,
      functionName: 'totalDappPoints',
      args: [dapp],
    });
    return result as bigint;
  }

  /**
   * Get claimed points for a dApp
   */
  async getDappPoints(dapp: Address): Promise<bigint> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: THURIN_POINTS_ABI,
      functionName: 'dappPoints',
      args: [dapp],
    });
    return result as bigint;
  }

  /**
   * Get user points (from SBT)
   */
  async getUserPoints(user: Address): Promise<bigint> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: THURIN_POINTS_ABI,
      functionName: 'userPoints',
      args: [user],
    });
    return result as bigint;
  }

  /**
   * Check if a user has a valid SBT
   */
  async hasValidSBT(user: Address): Promise<boolean> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: THURIN_POINTS_ABI,
      functionName: 'hasValidSBT',
      args: [user],
    });
    return result as boolean;
  }

  /**
   * Get dApp info
   */
  async getDappInfo(dapp: Address): Promise<DappInfo> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: THURIN_POINTS_ABI,
      functionName: 'getDappInfo',
      args: [dapp],
    });
    const [name, points, verifications] = result as [string, bigint, bigint];
    return { name, points, verifications };
  }

  /**
   * Check if a dApp is registered
   */
  async isDappRegistered(dapp: Address): Promise<boolean> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: THURIN_POINTS_ABI,
      functionName: 'dappRegistered',
      args: [dapp],
    });
    return result as boolean;
  }

  /**
   * Get registered dApp count
   */
  async getRegisteredDappCount(): Promise<bigint> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: THURIN_POINTS_ABI,
      functionName: 'registeredDappCount',
    });
    return result as bigint;
  }

  /**
   * Get top dApps by verification count
   */
  async getTopDapps(limit: number): Promise<LeaderboardEntry[]> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: THURIN_POINTS_ABI,
      functionName: 'getTopDapps',
      args: [BigInt(limit)],
    });
    const [dapps, verifications] = result as [Address[], bigint[]];

    return dapps.map((dapp, i) => ({
      dapp,
      verifications: verifications[i],
    }));
  }

  /**
   * Get points per verification constant
   */
  async getPointsPerVerification(): Promise<bigint> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: THURIN_POINTS_ABI,
      functionName: 'POINTS_PER_VERIFICATION',
    });
    return result as bigint;
  }
}
