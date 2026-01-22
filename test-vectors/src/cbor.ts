/**
 * CBOR encoding utilities for mDL structures
 */

import { encode } from 'cborg';
import type { IssuerSignedItem, MobileSecurityObject } from './types';

/**
 * Encode an IssuerSignedItem to CBOR bytes
 * cborg produces deterministic output by default (sorted keys, smallest representations)
 */
export function encodeIssuerSignedItem(item: IssuerSignedItem): Uint8Array {
  // ISO 18013-5 requires deterministic CBOR encoding
  return encode({
    digestID: item.digestID,
    random: item.random,
    elementIdentifier: item.elementIdentifier,
    elementValue: item.elementValue,
  });
}

/**
 * Encode a Mobile Security Object to CBOR bytes
 */
export function encodeMSO(mso: MobileSecurityObject): Uint8Array {
  return encode(mso);
}

/**
 * Create an IssuerSignedItem for age_over_21
 */
export function createAgeOver21Item(
  value: boolean,
  digestID: number = 0
): IssuerSignedItem {
  return {
    digestID,
    random: crypto.getRandomValues(new Uint8Array(32)),
    elementIdentifier: 'age_over_21',
    elementValue: value,
  };
}

/**
 * Create an IssuerSignedItem for age_over_18
 */
export function createAgeOver18Item(
  value: boolean,
  digestID: number = 2
): IssuerSignedItem {
  return {
    digestID,
    random: crypto.getRandomValues(new Uint8Array(32)),
    elementIdentifier: 'age_over_18',
    elementValue: value,
  };
}

/**
 * Create an IssuerSignedItem for issuing_jurisdiction
 */
export function createIssuingJurisdictionItem(
  stateCode: string,
  digestID: number = 1
): IssuerSignedItem {
  if (stateCode.length !== 2) {
    throw new Error('State code must be 2 characters');
  }
  return {
    digestID,
    random: crypto.getRandomValues(new Uint8Array(32)),
    elementIdentifier: 'issuing_jurisdiction',
    elementValue: stateCode,
  };
}
