export {
  requestCredential,
  requestCredentialIdentity,
  isDigitalCredentialsSupported,
} from './request.js';

export {
  parseCredential,
  toProverCredential,
  createMockCredential,
} from './parse.js';

export {
  createHPKESession,
  decryptCredentialResponse,
} from './hpke.js';

export type {
  RawCredentialResponse,
  RawIssuerSignedItem,
  EncryptedCredentialResponse,
  ParsedCredential,
  ParsedMSO,
  ParsedClaim,
  ClaimType,
  CredentialRequestOptions,
  CredentialErrorCode,
} from './types.js';

export type { HPKESession } from './hpke.js';

export { CredentialError } from './types.js';
