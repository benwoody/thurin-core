/**
 * CBOR parsing for mDL credential responses
 *
 * Uses fixed-schema parsing for known mDL structures per ISO 18013-5.
 * We don't build a general CBOR parser - we know the exact structure.
 */

import { decode, encode } from 'cborg';
import {
  type RawCredentialResponse,
  type ParsedCredential,
  type ParsedMSO,
  type ParsedClaim,
  CredentialError,
} from './types.js';
import type { Credential } from '../prover/types.js';

/**
 * Parse a raw credential response into a format ready for proof generation
 *
 * @param raw - Raw response from Digital Credentials API
 * @returns Parsed credential with MSO, claims, and keys
 */
export function parseCredential(raw: RawCredentialResponse): ParsedCredential {
  try {
    // Parse the issuerAuth (COSE_Sign1 containing MSO)
    const mso = parseMSO(raw.issuerAuth);

    // Parse all claims from the namespace
    const claims = new Map<string, ParsedClaim>();
    const namespace = raw.namespaces['org.iso.18013.5.1'];

    if (!namespace) {
      throw new CredentialError(
        'Missing org.iso.18013.5.1 namespace in credential',
        'PARSE_ERROR'
      );
    }

    for (const item of namespace) {
      claims.set(item.elementIdentifier, {
        id: item.elementIdentifier,
        bytes: item.rawBytes,
        value: item.elementValue,
        digestIndex: item.digestID,
      });
    }

    // Extract document number for nullifier
    const docNumberClaim = claims.get('document_number');
    if (!docNumberClaim) {
      throw new CredentialError(
        'document_number claim is required but not present',
        'INVALID_CLAIM'
      );
    }

    const documentNumber = stringToBytes(docNumberClaim.value as string, 32);

    // Extract IACA public key from the certificate chain
    // Note: In a real implementation, this would come from the certificate
    // For now, we expect it to be provided or extracted from issuerAuth
    const iacaPubkey = extractIACAPubkey(raw.issuerAuth);

    return {
      mso,
      claims,
      iacaPubkey,
      documentNumber,
    };
  } catch (error) {
    if (error instanceof CredentialError) {
      throw error;
    }
    throw new CredentialError(
      `Failed to parse credential: ${error instanceof Error ? error.message : 'Unknown error'}`,
      'PARSE_ERROR'
    );
  }
}

/**
 * Parse COSE_Sign1 structure containing the MSO
 */
function parseMSO(issuerAuth: Uint8Array): ParsedMSO {
  // COSE_Sign1 = [protected, unprotected, payload, signature]
  const coseSign1 = decode(issuerAuth);

  if (!Array.isArray(coseSign1) || coseSign1.length < 4) {
    throw new CredentialError('Invalid COSE_Sign1 structure', 'PARSE_ERROR');
  }

  const [_protected, _unprotected, payload, signature] = coseSign1;

  // Payload is the MSO
  const msoBytes = payload instanceof Uint8Array ? payload : encode(payload);
  const msoDecoded = decode(msoBytes);

  // Extract validity info
  const validityInfo = msoDecoded.validityInfo ?? {};
  const signed = parseDate(validityInfo.signed);
  const validFrom = parseDate(validityInfo.validFrom);
  const validUntil = parseDate(validityInfo.validUntil);

  return {
    bytes: msoBytes,
    signature: signature as Uint8Array,
    validityInfo: {
      signed,
      validFrom,
      validUntil,
    },
    digestAlgorithm: msoDecoded.digestAlgorithm ?? 'SHA-256',
    docType: msoDecoded.docType ?? 'org.iso.18013.5.1.mDL',
  };
}

/**
 * Extract IACA public key from issuerAuth certificate chain
 *
 * Note: This is a simplified implementation. In production, you would:
 * 1. Extract the X.509 certificate from the COSE_Sign1 header
 * 2. Parse the certificate to get the public key
 * 3. Validate the certificate chain back to a trusted root
 */
function extractIACAPubkey(issuerAuth: Uint8Array): {
  x: Uint8Array;
  y: Uint8Array;
} {
  // Decode COSE_Sign1
  const coseSign1 = decode(issuerAuth);

  if (!Array.isArray(coseSign1) || coseSign1.length < 2) {
    throw new CredentialError(
      'Invalid COSE_Sign1 structure for key extraction',
      'PARSE_ERROR'
    );
  }

  // The protected header contains the certificate chain
  const protectedHeader = decode(coseSign1[0]);

  // x5chain (33) contains the certificate chain
  const x5chain = protectedHeader.get?.(33) ?? protectedHeader[33];

  if (!x5chain || !Array.isArray(x5chain) || x5chain.length === 0) {
    // If no x5chain, try to get from unprotected header
    const unprotectedHeader = coseSign1[1];
    const certChain =
      unprotectedHeader?.get?.(33) ?? unprotectedHeader?.[33] ?? [];

    if (!certChain || certChain.length === 0) {
      throw new CredentialError(
        'No certificate chain found in issuerAuth',
        'PARSE_ERROR'
      );
    }

    return extractPubkeyFromCert(certChain[0]);
  }

  // First certificate in chain is the issuer certificate
  return extractPubkeyFromCert(x5chain[0]);
}

/**
 * Extract P-256 public key from an X.509 certificate
 *
 * Note: This is a simplified parser for the specific case of
 * ECDSA P-256 keys. A full implementation would use a proper
 * ASN.1 parser.
 */
function extractPubkeyFromCert(certBytes: Uint8Array): {
  x: Uint8Array;
  y: Uint8Array;
} {
  // This is a placeholder - in production, use a proper X.509 parser
  // The public key is in the SubjectPublicKeyInfo field
  //
  // For P-256, the public key is 65 bytes: 0x04 || x (32) || y (32)
  // We need to find this in the certificate

  // Look for the uncompressed point marker (0x04) followed by 64 bytes
  for (let i = 0; i < certBytes.length - 64; i++) {
    if (certBytes[i] === 0x04) {
      // Check if this looks like a valid public key position
      // (heuristic: preceded by length byte 0x41 = 65)
      if (i > 0 && certBytes[i - 1] === 0x41) {
        const x = certBytes.slice(i + 1, i + 33);
        const y = certBytes.slice(i + 33, i + 65);

        // Basic validation: x and y should not be all zeros
        if (!isAllZeros(x) && !isAllZeros(y)) {
          return { x, y };
        }
      }
    }
  }

  throw new CredentialError(
    'Could not extract public key from certificate',
    'PARSE_ERROR'
  );
}

/**
 * Check if a byte array is all zeros
 */
function isAllZeros(bytes: Uint8Array): boolean {
  return bytes.every((b) => b === 0);
}

/**
 * Parse a CBOR date string to Date object
 */
function parseDate(dateValue: unknown): Date {
  if (dateValue instanceof Date) {
    return dateValue;
  }
  if (typeof dateValue === 'string') {
    return new Date(dateValue);
  }
  if (typeof dateValue === 'number') {
    return new Date(dateValue * 1000); // Unix timestamp
  }
  return new Date(0); // Invalid date
}

/**
 * Convert a string to a fixed-size byte array (padded with zeros)
 */
function stringToBytes(str: string, size: number): Uint8Array {
  const bytes = new TextEncoder().encode(str);
  const result = new Uint8Array(size);
  result.set(bytes.slice(0, size));
  return result;
}

/**
 * Convert parsed credential to the format expected by the prover
 */
export function toProverCredential(parsed: ParsedCredential): Credential {
  // Get required claims
  const ageOver21Claim = parsed.claims.get('age_over_21');
  const ageOver18Claim = parsed.claims.get('age_over_18');
  const stateClaim = parsed.claims.get('issuing_jurisdiction');

  if (!ageOver21Claim) {
    throw new CredentialError(
      'age_over_21 claim is required',
      'INVALID_CLAIM'
    );
  }

  if (!ageOver18Claim) {
    throw new CredentialError(
      'age_over_18 claim is required',
      'INVALID_CLAIM'
    );
  }

  if (!stateClaim) {
    throw new CredentialError(
      'issuing_jurisdiction claim is required',
      'INVALID_CLAIM'
    );
  }

  return {
    msoBytes: padToSize(parsed.mso.bytes, 512),
    msoSignature: padToSize(parsed.mso.signature, 64),
    ageOver21ClaimBytes: padToSize(ageOver21Claim.bytes, 96),
    ageOver18ClaimBytes: padToSize(ageOver18Claim.bytes, 96),
    stateClaimBytes: padToSize(stateClaim.bytes, 107),
    documentNumber: parsed.documentNumber,
    iacaPubkeyX: padToSize(parsed.iacaPubkey.x, 32),
    iacaPubkeyY: padToSize(parsed.iacaPubkey.y, 32),
  };
}

/**
 * Pad or truncate a byte array to a specific size
 */
function padToSize(bytes: Uint8Array, size: number): Uint8Array {
  if (bytes.length === size) {
    return bytes;
  }
  const result = new Uint8Array(size);
  result.set(bytes.slice(0, size));
  return result;
}

/**
 * Create a mock credential for testing (when real mDL is not available)
 */
export function createMockCredential(options?: {
  ageOver21?: boolean;
  ageOver18?: boolean;
  state?: string;
  documentNumber?: string;
  expiryDate?: Date;
}): Credential {
  const ageOver21 = options?.ageOver21 ?? true;
  const ageOver18 = options?.ageOver18 ?? true;
  const state = options?.state ?? 'CA';
  const documentNumber = options?.documentNumber ?? 'D1234567';
  const expiryDate = options?.expiryDate ?? new Date('2030-01-01');

  // Create mock CBOR-encoded claims
  const ageOver21Claim = encode({
    digestID: 0,
    random: crypto.getRandomValues(new Uint8Array(32)),
    elementIdentifier: 'age_over_21',
    elementValue: ageOver21,
  });

  const ageOver18Claim = encode({
    digestID: 2,
    random: crypto.getRandomValues(new Uint8Array(32)),
    elementIdentifier: 'age_over_18',
    elementValue: ageOver18,
  });

  const stateClaim = encode({
    digestID: 1,
    random: crypto.getRandomValues(new Uint8Array(32)),
    elementIdentifier: 'issuing_jurisdiction',
    elementValue: state,
  });

  // Create mock MSO (simplified - real MSO has more structure)
  const mso = encode({
    digestAlgorithm: 'SHA-256',
    docType: 'org.iso.18013.5.1.mDL',
    valueDigests: {
      'org.iso.18013.5.1': {
        0: crypto.getRandomValues(new Uint8Array(32)), // age_over_21 digest
        1: crypto.getRandomValues(new Uint8Array(32)), // state digest
        2: crypto.getRandomValues(new Uint8Array(32)), // age_over_18 digest
      },
    },
    validityInfo: {
      signed: new Date().toISOString(),
      validFrom: new Date().toISOString(),
      validUntil: expiryDate.toISOString(),
    },
  });

  // Generate mock keys (not real - for testing only)
  const mockPubkeyX = crypto.getRandomValues(new Uint8Array(32));
  const mockPubkeyY = crypto.getRandomValues(new Uint8Array(32));
  const mockSignature = crypto.getRandomValues(new Uint8Array(64));

  return {
    msoBytes: padToSize(mso, 512),
    msoSignature: mockSignature,
    ageOver21ClaimBytes: padToSize(ageOver21Claim, 96),
    ageOver18ClaimBytes: padToSize(ageOver18Claim, 96),
    stateClaimBytes: padToSize(stateClaim, 107),
    documentNumber: stringToBytes(documentNumber, 32),
    iacaPubkeyX: mockPubkeyX,
    iacaPubkeyY: mockPubkeyY,
  };
}
