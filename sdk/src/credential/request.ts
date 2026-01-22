/**
 * Digital Credentials API integration for requesting mDL credentials
 *
 * Uses ISO 18013-7 Annex C format (org-iso-mdoc protocol) which works on:
 * - Safari iOS 26+ (exclusively supports org-iso-mdoc)
 * - Chrome Android 128+ (supports both org-iso-mdoc and openid4vp)
 */

import { encode, decode } from 'cborg';
import {
  type CredentialRequestOptions,
  type RawCredentialResponse,
  type EncryptedCredentialResponse,
  type ClaimType,
  CredentialError,
} from './types.js';
import {
  createHPKESession,
  decryptCredentialResponse,
  type HPKESession,
} from './hpke.js';

/**
 * Check if the Digital Credentials API is supported in this browser
 */
export function isDigitalCredentialsSupported(): boolean {
  return (
    typeof navigator !== 'undefined' &&
    'credentials' in navigator &&
    'get' in navigator.credentials
  );
}

/**
 * Map claim types to ISO 18013-5 element identifiers
 */
function mapClaimToElement(claim: ClaimType): string {
  switch (claim) {
    case 'age_over_21':
      return 'age_over_21';
    case 'age_over_18':
      return 'age_over_18';
    case 'issuing_jurisdiction':
      return 'issuing_jurisdiction';
    case 'document_number':
      return 'document_number';
    case 'expiry_date':
      return 'expiry_date';
    default:
      throw new CredentialError(`Unknown claim type: ${claim}`, 'INVALID_CLAIM');
  }
}

/**
 * Build the nameSpaces object for ISO 18013-5 ItemsRequest
 */
function buildNameSpaces(claims: ClaimType[]): Record<string, boolean> {
  const elements: Record<string, boolean> = {};

  for (const claim of claims) {
    elements[mapClaimToElement(claim)] = false; // false = don't retain
  }

  // Always request document_number for nullifier
  if (!claims.includes('document_number')) {
    elements['document_number'] = false;
  }

  // Always request expiry_date for validity check
  if (!claims.includes('expiry_date')) {
    elements['expiry_date'] = false;
  }

  return elements;
}

/**
 * Build CBOR-encoded DeviceRequest per ISO 18013-7
 */
function buildDeviceRequest(claims: ClaimType[]): Uint8Array {
  const nameSpaces = buildNameSpaces(claims);

  // Build ItemsRequest per ISO 18013-5 clause 8.3.2.1.2.1
  const itemsRequest = encode({
    docType: 'org.iso.18013.5.1.mDL',
    nameSpaces: encode({
      'org.iso.18013.5.1': encode(nameSpaces),
    }),
  });

  // Build DeviceRequest per ISO 18013-7
  return encode({
    version: '1.0',
    docRequests: [{ itemsRequest }],
  });
}

/**
 * Get the current origin for HPKE session binding
 */
function getCurrentOrigin(): string {
  if (typeof window !== 'undefined' && window.location) {
    return window.location.origin;
  }
  // Fallback for non-browser environments (testing)
  return 'https://localhost';
}

/**
 * Convert Uint8Array to base64 string
 */
function toBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

/**
 * Request mDL credential from the user's wallet via Digital Credentials API
 *
 * @param options - Which claims to request
 * @returns Raw credential response from the wallet (decrypted)
 * @throws CredentialError if not supported, user cancels, or no credential available
 */
export async function requestCredential(
  options: CredentialRequestOptions
): Promise<RawCredentialResponse> {
  // Check browser support
  if (!isDigitalCredentialsSupported()) {
    throw new CredentialError(
      'Digital Credentials API is not supported in this browser. ' +
        'Please use Safari on iOS 26+ or Chrome on Android 128+.',
      'NOT_SUPPORTED'
    );
  }

  try {
    // Build the request components
    const deviceRequest = buildDeviceRequest(options.claims);

    // Create HPKE session for encrypted response
    const origin = getCurrentOrigin();
    const { session, encryptionInfo } = await createHPKESession(origin);

    // Call the Digital Credentials API with org-iso-mdoc protocol
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const credential = await (navigator.credentials as any).get({
      mediation: 'required',
      digital: {
        requests: [
          {
            protocol: 'org-iso-mdoc',
            data: {
              deviceRequest: toBase64(deviceRequest),
              encryptionInfo: toBase64(encryptionInfo),
            },
          },
        ],
      },
    });

    if (!credential) {
      throw new CredentialError(
        'No credential returned from wallet',
        'NO_CREDENTIAL'
      );
    }

    // Extract the encrypted response from the credential
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const rawResponse = (credential as any).data ?? (credential as any).response;

    if (!rawResponse) {
      throw new CredentialError(
        'Invalid credential response structure',
        'PARSE_ERROR'
      );
    }

    // Check if response is encrypted (has encryptionParameters)
    if (rawResponse.encryptionParameters && rawResponse.data) {
      // Decrypt the response using HPKE
      const encryptedResponse = rawResponse as EncryptedCredentialResponse;
      const decryptedBytes = await decryptCredentialResponse(
        {
          version: encryptedResponse.version,
          encryptionParameters: encryptedResponse.encryptionParameters,
          data: encryptedResponse.data,
        },
        session
      );

      // Parse the decrypted DeviceResponse CBOR
      const deviceResponse = decode(decryptedBytes);
      return parseDeviceResponse(deviceResponse);
    }

    // Response might already be decrypted (for testing or some implementations)
    return rawResponse as RawCredentialResponse;
  } catch (error) {
    // Handle specific error types
    if (error instanceof CredentialError) {
      throw error;
    }

    const message = error instanceof Error ? error.message : 'Unknown error';

    // No mDL in wallet
    if (message.includes('No supported document requests')) {
      throw new CredentialError(
        'No mobile driver\'s license found in wallet. ' +
          'Please add your mDL to Apple Wallet or Google Wallet first.',
        'NO_CREDENTIAL'
      );
    }

    if (error instanceof DOMException) {
      if (error.name === 'NotAllowedError') {
        throw new CredentialError(
          'User declined the credential request',
          'USER_CANCELLED'
        );
      }
      if (error.name === 'NotSupportedError') {
        throw new CredentialError(
          'Digital Credentials API is not supported',
          'NOT_SUPPORTED'
        );
      }
    }

    throw new CredentialError(
      `Failed to request credential: ${message}`,
      'UNKNOWN'
    );
  }
}

/**
 * Parse DeviceResponse structure to extract credential data
 * DeviceResponse = { documents: [Document], status: uint }
 * Document = { docType: tstr, issuerSigned: IssuerSigned, ... }
 */
function parseDeviceResponse(deviceResponse: unknown): RawCredentialResponse {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const resp = deviceResponse as any;

  if (!resp.documents || !Array.isArray(resp.documents) || resp.documents.length === 0) {
    throw new CredentialError(
      'No documents in DeviceResponse',
      'PARSE_ERROR'
    );
  }

  // Get the first mDL document
  const doc = resp.documents.find(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (d: any) => d.docType === 'org.iso.18013.5.1.mDL'
  );

  if (!doc) {
    throw new CredentialError(
      'No mDL document in DeviceResponse',
      'PARSE_ERROR'
    );
  }

  const issuerSigned = doc.issuerSigned;
  if (!issuerSigned) {
    throw new CredentialError(
      'No issuerSigned in document',
      'PARSE_ERROR'
    );
  }

  // Extract issuerAuth (COSE_Sign1)
  const issuerAuth = issuerSigned.issuerAuth;
  if (!issuerAuth) {
    throw new CredentialError(
      'No issuerAuth in issuerSigned',
      'PARSE_ERROR'
    );
  }

  // Extract namespaces with IssuerSignedItems
  const nameSpaces = issuerSigned.nameSpaces;
  if (!nameSpaces) {
    throw new CredentialError(
      'No nameSpaces in issuerSigned',
      'PARSE_ERROR'
    );
  }

  // Parse the mDL namespace items
  const mdlNamespace = nameSpaces['org.iso.18013.5.1'];
  if (!mdlNamespace || !Array.isArray(mdlNamespace)) {
    throw new CredentialError(
      'No org.iso.18013.5.1 namespace in response',
      'PARSE_ERROR'
    );
  }

  // Convert IssuerSignedItemBytes to our format
  // Each item is tagged CBOR (tag 24) containing the IssuerSignedItem
  const items = mdlNamespace.map((itemBytes: Uint8Array) => {
    const item = decode(itemBytes);
    return {
      digestID: item.digestID,
      random: item.random,
      elementIdentifier: item.elementIdentifier,
      elementValue: item.elementValue,
      rawBytes: itemBytes,
    };
  });

  return {
    issuerAuth: issuerAuth instanceof Uint8Array ? issuerAuth : encode(issuerAuth),
    namespaces: {
      'org.iso.18013.5.1': items,
    },
  };
}

/**
 * Alternative: Request credential using the IdentityCredential API
 * This is the emerging W3C standard that some browsers may support
 */
export async function requestCredentialIdentity(
  options: CredentialRequestOptions
): Promise<RawCredentialResponse> {
  // Check for IdentityCredential support
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  if (!('IdentityCredential' in (globalThis as any))) {
    throw new CredentialError(
      'IdentityCredential API is not supported',
      'NOT_SUPPORTED'
    );
  }

  const nonce = options.nonce ?? generateNonce();

  try {
    // Use the IdentityCredential API
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const credential = await (navigator as any).identity.get({
      mdl: {
        claims: options.claims,
        readerAuthentication: {
          nonce,
        },
      },
    });

    if (!credential) {
      throw new CredentialError('No credential returned', 'NO_CREDENTIAL');
    }

    return credential as RawCredentialResponse;
  } catch (error) {
    if (error instanceof CredentialError) {
      throw error;
    }

    throw new CredentialError(
      `Failed to request credential: ${error instanceof Error ? error.message : 'Unknown error'}`,
      'UNKNOWN'
    );
  }
}
