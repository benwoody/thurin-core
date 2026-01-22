/**
 * Type definitions for mDL test data
 */

export interface IssuerSignedItem {
  digestID: number;
  random: Uint8Array;
  elementIdentifier: string;
  elementValue: unknown;
}

export interface MobileSecurityObject {
  digestAlgorithm: string;
  docType: string;
  valueDigests: {
    [namespace: string]: {
      [digestID: number]: Uint8Array;
    };
  };
  validityInfo: {
    signed: string;
    validFrom: string;
    validUntil: string;
  };
}

export interface TestIACAKey {
  privateKey: Uint8Array;
  publicKeyX: Uint8Array;
  publicKeyY: Uint8Array;
  root: string; // Poseidon hash as hex
}

export interface TestVector {
  name: string;
  description: string;
  iacaKey: TestIACAKey;
  claims: {
    ageOver21: {
      item: IssuerSignedItem;
      bytes: Uint8Array;
      hash: Uint8Array;
    };
    ageOver18?: {
      item: IssuerSignedItem;
      bytes: Uint8Array;
      hash: Uint8Array;
    };
    issuingJurisdiction?: {
      item: IssuerSignedItem;
      bytes: Uint8Array;
      hash: Uint8Array;
    };
  };
  mso: {
    object: MobileSecurityObject;
    bytes: Uint8Array;
    hash: Uint8Array;
    signature: Uint8Array;
  };
  documentNumber: Uint8Array;
  expectedNullifier: string;
}
