/**
 * HPKE decryption for ISO 18013-7 mDL responses
 *
 * Uses DHKEM(P-256, HKDF-SHA256) + AES-128-GCM as specified in ISO 18013-7
 * Reference: RFC 9180 (HPKE)
 */

import { encode } from 'cborg';
import { CredentialError } from './types.js';

/**
 * HPKE cipher suite constants for ISO 18013-7
 * KEM: DHKEM(P-256, HKDF-SHA256) - 0x0010
 * KDF: HKDF-SHA256 - 0x0001
 * AEAD: AES-128-GCM - 0x0001
 */
const HPKE_MODE_BASE = 0x00;
const KEM_ID = 0x0010; // DHKEM(P-256, HKDF-SHA256)
const KDF_ID = 0x0001; // HKDF-SHA256
const AEAD_ID = 0x0001; // AES-128-GCM

// Derived constants
const N_SECRET = 32; // HKDF-SHA256 output size
const N_ENC = 65; // P-256 uncompressed point size
const N_PK = 65; // P-256 public key size
const N_SK = 32; // P-256 private key size
const N_K = 16; // AES-128 key size
const N_N = 12; // AES-GCM nonce size

/**
 * Session context for HPKE decryption
 */
export interface HPKESession {
  /** Verifier's private key */
  privateKey: CryptoKey;
  /** Verifier's public key (raw bytes) */
  publicKeyBytes: Uint8Array;
  /** Nonce used in the request */
  nonce: Uint8Array;
  /** Origin of the requesting website */
  origin: string;
}

/**
 * Encrypted credential document from wallet
 */
export interface EncryptedCredentialDocument {
  version: string;
  encryptionParameters: {
    version: string;
    EDeviceKey: Uint8Array; // HPKE encapsulated key (pkEm)
    originInfoBytes: Uint8Array;
  };
  data: Uint8Array; // HPKE ciphertext
}

/**
 * Create an HPKE session for credential requests
 * Returns the session context and encryption info to send to wallet
 */
export async function createHPKESession(origin: string): Promise<{
  session: HPKESession;
  encryptionInfo: Uint8Array;
}> {
  // Generate ephemeral P-256 key pair
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );

  // Export public key as raw bytes
  const publicKeyRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
  const publicKeyBytes = new Uint8Array(publicKeyRaw);

  // Generate nonce (12 bytes for AES-GCM compatibility)
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  // Build EncryptionInfo per ISO 18013-7
  const encryptionInfo = encode({
    publicKey: publicKeyBytes,
    nonce: nonce,
  });

  return {
    session: {
      privateKey: keyPair.privateKey,
      publicKeyBytes,
      nonce,
      origin,
    },
    encryptionInfo,
  };
}

/**
 * Build SessionTranscript for AAD in HPKE decryption
 *
 * For browser-based presentation (BrowserHandover):
 * SessionTranscript = [null, null, BrowserHandover]
 * BrowserHandover = ["BrowserHandoverv1", Nonce, OriginInfoBytes, RequesterIdentity, pkEm]
 */
function buildSessionTranscript(
  session: HPKESession,
  pkEm: Uint8Array
): Uint8Array {
  // Build OriginInfoBytes - origin of the requesting website
  const originInfo = encode({
    origin: session.origin,
  });

  // RequesterIdentity - can be empty for basic requests
  const requesterIdentity = encode({});

  // BrowserHandover structure
  const browserHandover = [
    'BrowserHandoverv1',
    session.nonce,
    originInfo,
    requesterIdentity,
    pkEm,
  ];

  // SessionTranscript = [DeviceEngagementBytes, EReaderKeyBytes, Handover]
  // For browser API, DeviceEngagementBytes and EReaderKeyBytes are null
  const sessionTranscript = [null, null, browserHandover];

  return encode(sessionTranscript);
}

/**
 * Labeled extract for HPKE key schedule
 */
async function labeledExtract(
  salt: Uint8Array,
  label: string,
  ikm: Uint8Array,
  suiteId: Uint8Array
): Promise<Uint8Array> {
  // labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
  const labelBytes = new TextEncoder().encode(label);
  const hpkeV1 = new TextEncoder().encode('HPKE-v1');

  const labeledIkm = new Uint8Array(
    hpkeV1.length + suiteId.length + labelBytes.length + ikm.length
  );
  let offset = 0;
  labeledIkm.set(hpkeV1, offset);
  offset += hpkeV1.length;
  labeledIkm.set(suiteId, offset);
  offset += suiteId.length;
  labeledIkm.set(labelBytes, offset);
  offset += labelBytes.length;
  labeledIkm.set(ikm, offset);

  // HKDF-Extract
  const key = await crypto.subtle.importKey(
    'raw',
    salt.length > 0 ? salt : new Uint8Array(32),
    { name: 'HKDF' },
    false,
    ['deriveBits']
  );

  // For extract, we use HKDF with the labeled IKM
  const hmacKey = await crypto.subtle.importKey(
    'raw',
    salt.length > 0 ? salt : new Uint8Array(32),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const prk = await crypto.subtle.sign('HMAC', hmacKey, labeledIkm);
  return new Uint8Array(prk);
}

/**
 * Labeled expand for HPKE key schedule
 */
async function labeledExpand(
  prk: Uint8Array,
  label: string,
  info: Uint8Array,
  length: number,
  suiteId: Uint8Array
): Promise<Uint8Array> {
  // labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id, label, info)
  const labelBytes = new TextEncoder().encode(label);
  const hpkeV1 = new TextEncoder().encode('HPKE-v1');

  const labeledInfo = new Uint8Array(
    2 + hpkeV1.length + suiteId.length + labelBytes.length + info.length
  );
  let offset = 0;
  // I2OSP(length, 2)
  labeledInfo[offset++] = (length >> 8) & 0xff;
  labeledInfo[offset++] = length & 0xff;
  labeledInfo.set(hpkeV1, offset);
  offset += hpkeV1.length;
  labeledInfo.set(suiteId, offset);
  offset += suiteId.length;
  labeledInfo.set(labelBytes, offset);
  offset += labelBytes.length;
  labeledInfo.set(info, offset);

  // HKDF-Expand
  const key = await crypto.subtle.importKey(
    'raw',
    prk,
    { name: 'HKDF' },
    false,
    ['deriveBits']
  );

  const derived = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: labeledInfo,
    },
    key,
    length * 8
  );

  return new Uint8Array(derived);
}

/**
 * Build HPKE suite ID
 */
function buildSuiteId(): Uint8Array {
  // suite_id = concat("HPKE", I2OSP(kem_id, 2), I2OSP(kdf_id, 2), I2OSP(aead_id, 2))
  const suiteId = new Uint8Array(10);
  const hpke = new TextEncoder().encode('HPKE');
  suiteId.set(hpke, 0);
  suiteId[4] = (KEM_ID >> 8) & 0xff;
  suiteId[5] = KEM_ID & 0xff;
  suiteId[6] = (KDF_ID >> 8) & 0xff;
  suiteId[7] = KDF_ID & 0xff;
  suiteId[8] = (AEAD_ID >> 8) & 0xff;
  suiteId[9] = AEAD_ID & 0xff;
  return suiteId;
}

/**
 * Build KEM suite ID
 */
function buildKemSuiteId(): Uint8Array {
  // kem_suite_id = concat("KEM", I2OSP(kem_id, 2))
  const kemSuiteId = new Uint8Array(5);
  const kem = new TextEncoder().encode('KEM');
  kemSuiteId.set(kem, 0);
  kemSuiteId[3] = (KEM_ID >> 8) & 0xff;
  kemSuiteId[4] = KEM_ID & 0xff;
  return kemSuiteId;
}

/**
 * Derive shared secret using ECDH
 */
async function deriveSharedSecret(
  privateKey: CryptoKey,
  publicKeyBytes: Uint8Array
): Promise<Uint8Array> {
  // Import the public key
  const publicKey = await crypto.subtle.importKey(
    'raw',
    publicKeyBytes,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

  // Perform ECDH
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: publicKey },
    privateKey,
    256
  );

  return new Uint8Array(sharedBits);
}

/**
 * HPKE Decap - decapsulate the shared secret
 */
async function decap(
  enc: Uint8Array,
  skR: CryptoKey,
  pkR: Uint8Array
): Promise<Uint8Array> {
  const kemSuiteId = buildKemSuiteId();

  // Derive shared secret via ECDH
  const dh = await deriveSharedSecret(skR, enc);

  // kem_context = concat(enc, pkR)
  const kemContext = new Uint8Array(enc.length + pkR.length);
  kemContext.set(enc, 0);
  kemContext.set(pkR, enc.length);

  // shared_secret = ExtractAndExpand(dh, kem_context)
  const prk = await labeledExtract(
    new Uint8Array(0),
    'eae_prk',
    dh,
    kemSuiteId
  );

  const sharedSecret = await labeledExpand(
    prk,
    'shared_secret',
    kemContext,
    N_SECRET,
    kemSuiteId
  );

  return sharedSecret;
}

/**
 * HPKE KeyScheduleR - derive key and nonce for decryption
 */
async function keyScheduleR(
  sharedSecret: Uint8Array,
  info: Uint8Array
): Promise<{ key: Uint8Array; baseNonce: Uint8Array }> {
  const suiteId = buildSuiteId();

  // psk_id_hash = LabeledExtract("", "psk_id_hash", "")
  const pskIdHash = await labeledExtract(
    new Uint8Array(0),
    'psk_id_hash',
    new Uint8Array(0),
    suiteId
  );

  // info_hash = LabeledExtract("", "info_hash", info)
  const infoHash = await labeledExtract(
    new Uint8Array(0),
    'info_hash',
    info,
    suiteId
  );

  // ks_context = concat(mode, psk_id_hash, info_hash)
  const ksContext = new Uint8Array(1 + pskIdHash.length + infoHash.length);
  ksContext[0] = HPKE_MODE_BASE;
  ksContext.set(pskIdHash, 1);
  ksContext.set(infoHash, 1 + pskIdHash.length);

  // secret = LabeledExtract(shared_secret, "secret", psk)
  const secret = await labeledExtract(
    sharedSecret,
    'secret',
    new Uint8Array(0), // psk is empty for mode_base
    suiteId
  );

  // key = LabeledExpand(secret, "key", ks_context, Nk)
  const key = await labeledExpand(secret, 'key', ksContext, N_K, suiteId);

  // base_nonce = LabeledExpand(secret, "base_nonce", ks_context, Nn)
  const baseNonce = await labeledExpand(
    secret,
    'base_nonce',
    ksContext,
    N_N,
    suiteId
  );

  return { key, baseNonce };
}

/**
 * Decrypt ciphertext using AES-128-GCM
 */
async function aesGcmDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );

  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
      additionalData: aad,
    },
    cryptoKey,
    ciphertext
  );

  return new Uint8Array(plaintext);
}

/**
 * Decrypt an ISO 18013-7 encrypted credential response
 *
 * @param encrypted - The encrypted credential document from the wallet
 * @param session - The HPKE session created during the request
 * @returns Decrypted DeviceResponse CBOR bytes
 */
export async function decryptCredentialResponse(
  encrypted: EncryptedCredentialDocument,
  session: HPKESession
): Promise<Uint8Array> {
  try {
    const enc = encrypted.encryptionParameters.EDeviceKey;
    const ciphertext = encrypted.data;

    // Build SessionTranscript for AAD
    const sessionTranscript = buildSessionTranscript(session, enc);

    // Decap: derive shared secret
    const sharedSecret = await decap(
      enc,
      session.privateKey,
      session.publicKeyBytes
    );

    // KeyScheduleR: derive key and nonce
    // info is empty for ISO 18013-7
    const { key, baseNonce } = await keyScheduleR(
      sharedSecret,
      new Uint8Array(0)
    );

    // Decrypt using AES-128-GCM
    // For the first message, sequence number is 0, so nonce = base_nonce XOR 0 = base_nonce
    const plaintext = await aesGcmDecrypt(
      key,
      baseNonce,
      sessionTranscript,
      ciphertext
    );

    return plaintext;
  } catch (error) {
    throw new CredentialError(
      `Failed to decrypt credential response: ${error instanceof Error ? error.message : 'Unknown error'}`,
      'PARSE_ERROR'
    );
  }
}
