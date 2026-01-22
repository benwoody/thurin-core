/**
 * IACA (Issuing Authority Certificate Authority) utilities
 */

import { p256 } from '@noble/curves/p256';

export interface IACAKeyPair {
  privateKey: Uint8Array;
  publicKeyX: Uint8Array;
  publicKeyY: Uint8Array;
}

/**
 * Generate a test IACA P-256 key pair
 */
export function generateTestIACAKey(): IACAKeyPair {
  const privateKey = p256.utils.randomPrivateKey();
  const publicKey = p256.getPublicKey(privateKey, false); // uncompressed

  // Public key is 65 bytes: 0x04 || x (32 bytes) || y (32 bytes)
  const publicKeyX = publicKey.slice(1, 33);
  const publicKeyY = publicKey.slice(33, 65);

  return {
    privateKey: new Uint8Array(privateKey),
    publicKeyX: new Uint8Array(publicKeyX),
    publicKeyY: new Uint8Array(publicKeyY),
  };
}

/**
 * Sign a message hash with the IACA private key
 */
export function signWithIACA(
  messageHash: Uint8Array,
  privateKey: Uint8Array
): Uint8Array {
  const signature = p256.sign(messageHash, privateKey);
  // Return r || s (64 bytes total)
  return signature.toCompactRawBytes();
}

/**
 * Verify a signature with the IACA public key
 */
export function verifyIACASignature(
  messageHash: Uint8Array,
  signature: Uint8Array,
  publicKeyX: Uint8Array,
  publicKeyY: Uint8Array
): boolean {
  // Reconstruct uncompressed public key
  const publicKey = new Uint8Array(65);
  publicKey[0] = 0x04;
  publicKey.set(publicKeyX, 1);
  publicKey.set(publicKeyY, 33);

  return p256.verify(signature, messageHash, publicKey);
}

/**
 * California DMV IACA public key (production)
 * Source: https://trust.dmv.ca.gov/certificates/
 */
export const CALIFORNIA_IACA = {
  publicKeyX: new Uint8Array([
    0x60, 0xcc, 0xa0, 0x79, 0x42, 0xc4, 0x57, 0x60, 0x6c, 0x66, 0x21, 0xaa,
    0x40, 0xde, 0x29, 0x4b, 0xa1, 0x70, 0x83, 0xc6, 0x04, 0xcc, 0x23, 0x62,
    0x40, 0xac, 0x0e, 0xf6, 0x55, 0x0f, 0x60, 0x2f,
  ]),
  publicKeyY: new Uint8Array([
    0x60, 0xc8, 0x2a, 0x40, 0x40, 0x72, 0x52, 0x98, 0x6b, 0x2c, 0x7b, 0xbd,
    0x0c, 0x14, 0x6e, 0x16, 0xc7, 0xef, 0xa9, 0xa7, 0x99, 0xb3, 0x85, 0x4b,
    0x16, 0x25, 0x08, 0x9b, 0x62, 0x95, 0xf9, 0x75,
  ]),
};
