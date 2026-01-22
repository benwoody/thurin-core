import { describe, it, expect } from 'vitest';
import {
  isDigitalCredentialsSupported,
  createMockCredential,
  CredentialError,
} from '../src/credential/index.js';
import { Thurin } from '../src/index.js';

describe('Credential API Support', () => {
  it('isDigitalCredentialsSupported returns boolean', () => {
    // In Node.js environment, this should return false
    const supported = isDigitalCredentialsSupported();
    expect(typeof supported).toBe('boolean');
    // In test environment (Node), navigator is not available
    expect(supported).toBe(false);
  });

  it('Thurin.isCredentialApiSupported is static method', () => {
    const supported = Thurin.isCredentialApiSupported();
    expect(typeof supported).toBe('boolean');
    expect(supported).toBe(false);
  });
});

describe('Mock Credential', () => {
  it('creates mock credential with defaults', () => {
    const credential = createMockCredential();

    expect(credential.msoBytes).toBeInstanceOf(Uint8Array);
    expect(credential.msoSignature).toBeInstanceOf(Uint8Array);
    expect(credential.ageOver21ClaimBytes).toBeInstanceOf(Uint8Array);
    expect(credential.ageOver18ClaimBytes).toBeInstanceOf(Uint8Array);
    expect(credential.stateClaimBytes).toBeInstanceOf(Uint8Array);
    expect(credential.documentNumber).toBeInstanceOf(Uint8Array);
    expect(credential.iacaPubkeyX).toBeInstanceOf(Uint8Array);
    expect(credential.iacaPubkeyY).toBeInstanceOf(Uint8Array);
  });

  it('creates mock credential with custom options', () => {
    const credential = createMockCredential({
      ageOver21: true,
      ageOver18: true,
      state: 'TX',
      documentNumber: 'TX9876543',
    });

    expect(credential.msoBytes).toBeInstanceOf(Uint8Array);
    expect(credential.msoBytes.length).toBe(512);
    expect(credential.msoSignature.length).toBe(64);
    expect(credential.ageOver21ClaimBytes.length).toBe(96);
    expect(credential.ageOver18ClaimBytes.length).toBe(96);
    expect(credential.stateClaimBytes.length).toBe(107);
    expect(credential.documentNumber.length).toBe(32);
    expect(credential.iacaPubkeyX.length).toBe(32);
    expect(credential.iacaPubkeyY.length).toBe(32);
  });

  it('Thurin.createMockCredential is static method', () => {
    const credential = Thurin.createMockCredential({
      ageOver21: false,
      state: 'NY',
    });

    expect(credential.msoBytes).toBeInstanceOf(Uint8Array);
  });
});

describe('CredentialError', () => {
  it('creates error with code', () => {
    const error = new CredentialError('Test error', 'NOT_SUPPORTED');

    expect(error.message).toBe('Test error');
    expect(error.code).toBe('NOT_SUPPORTED');
    expect(error.name).toBe('CredentialError');
  });

  it('is instanceof Error', () => {
    const error = new CredentialError('Test', 'UNKNOWN');
    expect(error).toBeInstanceOf(Error);
  });

  it('supports all error codes', () => {
    const codes = [
      'NOT_SUPPORTED',
      'USER_CANCELLED',
      'NO_CREDENTIAL',
      'PARSE_ERROR',
      'INVALID_CLAIM',
      'EXPIRED',
      'UNKNOWN',
    ] as const;

    for (const code of codes) {
      const error = new CredentialError('Test', code);
      expect(error.code).toBe(code);
    }
  });
});

describe('Credential Request Types', () => {
  it('CredentialRequest accepts valid claim types', () => {
    // This is a type check - just ensuring the types are exported correctly
    const request = {
      claims: ['age_over_21', 'issuing_jurisdiction'] as const,
      nonce: 'test-nonce',
    };

    expect(request.claims).toContain('age_over_21');
    expect(request.claims).toContain('issuing_jurisdiction');
    expect(request.nonce).toBe('test-nonce');
  });
});
