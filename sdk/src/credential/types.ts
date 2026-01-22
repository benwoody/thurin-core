/**
 * Credential types for mDL handling
 */

/**
 * Encrypted credential document from wallet (ISO 18013-7)
 * This is the raw structure returned by the Digital Credentials API
 */
export interface EncryptedCredentialResponse {
  /** Protocol version */
  version: string;
  /** HPKE encryption parameters */
  encryptionParameters: {
    version: string;
    /** HPKE encapsulated key (pkEm) - 65 bytes for P-256 */
    EDeviceKey: Uint8Array;
    /** Origin info bytes */
    originInfoBytes: Uint8Array;
  };
  /** HPKE ciphertext containing DeviceResponse */
  data: Uint8Array;
}

/**
 * Raw credential response from Digital Credentials API (after decryption)
 * This is the decrypted DeviceResponse structure
 */
export interface RawCredentialResponse {
  /** COSE_Sign1 containing the MSO */
  issuerAuth: Uint8Array;
  /** Namespaced claim data */
  namespaces: {
    'org.iso.18013.5.1': RawIssuerSignedItem[];
  };
}

/**
 * Raw IssuerSignedItem from mDL response
 */
export interface RawIssuerSignedItem {
  /** Index into MSO digest list */
  digestID: number;
  /** 32 random bytes */
  random: Uint8Array;
  /** Field name (e.g., "age_over_21") */
  elementIdentifier: string;
  /** The actual value */
  elementValue: unknown;
  /** Original CBOR bytes for hashing */
  rawBytes: Uint8Array;
}

/**
 * Parsed claim with its bytes for circuit input
 */
export interface ParsedClaim {
  /** Claim identifier */
  id: string;
  /** Original CBOR bytes (for hashing in circuit) */
  bytes: Uint8Array;
  /** Decoded value */
  value: unknown;
  /** Index in MSO digest list */
  digestIndex: number;
}

/**
 * Parsed Mobile Security Object (MSO)
 */
export interface ParsedMSO {
  /** Raw MSO bytes (for hashing in circuit) */
  bytes: Uint8Array;
  /** ECDSA signature over MSO */
  signature: Uint8Array;
  /** Validity info */
  validityInfo: {
    signed: Date;
    validFrom: Date;
    validUntil: Date;
  };
  /** Digest algorithm (should be "SHA-256") */
  digestAlgorithm: string;
  /** Document type */
  docType: string;
}

/**
 * Parsed credential ready for proof generation
 * This maps to the Credential type in prover/types.ts
 */
export interface ParsedCredential {
  /** Parsed MSO */
  mso: ParsedMSO;
  /** Parsed claims by identifier */
  claims: Map<string, ParsedClaim>;
  /** IACA public key */
  iacaPubkey: {
    x: Uint8Array;
    y: Uint8Array;
  };
  /** Document number (used for nullifier, never revealed) */
  documentNumber: Uint8Array;
}

/**
 * Claim types that can be requested
 */
export type ClaimType =
  | 'age_over_21'
  | 'age_over_18'
  | 'issuing_jurisdiction'
  | 'document_number'
  | 'expiry_date';

/**
 * Options for requesting a credential
 */
export interface CredentialRequestOptions {
  /** Which claims to request from the wallet */
  claims: ClaimType[];
  /** Optional nonce for freshness (generated if not provided) */
  nonce?: string;
}

/**
 * Errors that can occur during credential operations
 */
export class CredentialError extends Error {
  constructor(
    message: string,
    public readonly code: CredentialErrorCode
  ) {
    super(message);
    this.name = 'CredentialError';
  }
}

export type CredentialErrorCode =
  | 'NOT_SUPPORTED' // Browser doesn't support Digital Credentials API
  | 'USER_CANCELLED' // User declined the request
  | 'NO_CREDENTIAL' // No mDL available
  | 'PARSE_ERROR' // Failed to parse response
  | 'INVALID_CLAIM' // Requested claim not present
  | 'EXPIRED' // Credential or MSO expired
  | 'UNKNOWN';
