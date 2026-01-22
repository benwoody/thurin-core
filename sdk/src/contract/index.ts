// ABIs
export {
  THURIN_SBT_ABI,
  THURIN_VERIFIER_ABI,
  THURIN_POINTS_ABI,
} from './abi.js';

// SBT
export {
  ThurinSBT,
  NO_REFERRER,
  type ThurinProof,
  type ThurinPublicInputs,
  type MintOptions,
  type SBTStatus,
} from './sbt.js';

// Verifier
export { ThurinVerifier } from './verifier.js';

// Points
export {
  ThurinPoints,
  type DappInfo,
  type LeaderboardEntry,
} from './points.js';

// Utility
import { keccak256, toHex } from 'viem';
import type { Hex } from 'viem';

/**
 * Hash an event ID string to bytes32
 */
export function hashEventId(eventId: string): Hex {
  return keccak256(toHex(eventId));
}
