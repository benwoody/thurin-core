/**
 * Generate test vectors for Thurin circuits
 *
 * Run with: pnpm generate
 */

import { writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import {
  createAgeOver21Item,
  createAgeOver18Item,
  createIssuingJurisdictionItem,
  encodeIssuerSignedItem,
  encodeMSO,
} from './cbor';
import { generateTestIACAKey, signWithIACA } from './iaca';
import type { MobileSecurityObject, TestVector } from './types';

function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest());
}

interface TestVectorConfig {
  name: string;
  description: string;
  ageOver21: boolean;
  ageOver18: boolean;
  stateCode: string;
  validUntil: string;
}

function generateTestVector(config: TestVectorConfig): TestVector {
  console.log(`\nGenerating: ${config.name}`);

  console.log('  Creating IACA key pair...');
  const iacaKey = generateTestIACAKey();

  console.log('  Creating age_over_21 claim...');
  const ageOver21Item = createAgeOver21Item(config.ageOver21, 0);
  const ageOver21Bytes = encodeIssuerSignedItem(ageOver21Item);
  const ageOver21Hash = sha256(ageOver21Bytes);

  console.log('  Creating age_over_18 claim...');
  const ageOver18Item = createAgeOver18Item(config.ageOver18, 2);
  const ageOver18Bytes = encodeIssuerSignedItem(ageOver18Item);
  const ageOver18Hash = sha256(ageOver18Bytes);

  console.log('  Creating issuing_jurisdiction claim...');
  const stateItem = createIssuingJurisdictionItem(config.stateCode, 1);
  const stateBytes = encodeIssuerSignedItem(stateItem);
  const stateHash = sha256(stateBytes);

  console.log('  Building MSO...');
  const mso: MobileSecurityObject = {
    digestAlgorithm: 'SHA-256',
    docType: 'org.iso.18013.5.1.mDL',
    valueDigests: {
      'org.iso.18013.5.1': {
        0: ageOver21Hash,
        1: stateHash,
        2: ageOver18Hash,
      },
    },
    validityInfo: {
      signed: '2026-01-01',
      validFrom: '2026-01-01',
      validUntil: config.validUntil,
    },
  };

  const msoBytes = encodeMSO(mso);

  // Pad MSO to 512 bytes (must match circuit's fixed array size)
  const MSO_PADDED_SIZE = 512;
  const msoPadded = new Uint8Array(MSO_PADDED_SIZE);
  msoPadded.set(msoBytes);
  // Rest is already zeros

  // Hash the PADDED MSO (this is what the circuit will hash)
  const msoHash = sha256(msoPadded);

  console.log(`  MSO size: ${msoBytes.length} bytes, padded to ${MSO_PADDED_SIZE}`);
  console.log('  Signing padded MSO...');
  const msoSignature = signWithIACA(msoHash, iacaKey.privateKey);

  console.log('  Generating document number...');
  const documentNumber = new Uint8Array(32);
  crypto.getRandomValues(documentNumber.subarray(0, 16));

  return {
    name: config.name,
    description: config.description,
    iacaKey: {
      privateKey: iacaKey.privateKey,
      publicKeyX: iacaKey.publicKeyX,
      publicKeyY: iacaKey.publicKeyY,
      root: '0x' + Buffer.from(iacaKey.publicKeyX).toString('hex').slice(0, 16),
    },
    claims: {
      ageOver21: {
        item: ageOver21Item,
        bytes: ageOver21Bytes,
        hash: ageOver21Hash,
      },
      ageOver18: {
        item: ageOver18Item,
        bytes: ageOver18Bytes,
        hash: ageOver18Hash,
      },
      issuingJurisdiction: {
        item: stateItem,
        bytes: stateBytes,
        hash: stateHash,
      },
    },
    mso: {
      object: mso,
      bytes: msoBytes,
      hash: msoHash,
      signature: msoSignature,
    },
    documentNumber,
    expectedNullifier: 'TODO: compute with Poseidon',
  };
}

const TEST_VECTORS: TestVectorConfig[] = [
  {
    name: 'california-over21',
    description: 'California mDL with age_over_21=true, age_over_18=true',
    ageOver21: true,
    ageOver18: true,
    stateCode: 'CA',
    validUntil: '2030-01-01',
  },
  {
    name: 'texas-under21',
    description: 'Texas mDL with age_over_21=false, age_over_18=true',
    ageOver21: false,
    ageOver18: true,
    stateCode: 'TX',
    validUntil: '2030-01-01',
  },
];

function writeTestVector(fixturesDir: string, vector: TestVector) {
  const prefix = `${fixturesDir}/${vector.name}`;

  // Write full test vector as JSON
  writeFileSync(
    `${prefix}.json`,
    JSON.stringify(
      vector,
      (_, v) => (v instanceof Uint8Array ? Array.from(v) : v),
      2
    )
  );

  // Write raw bytes for circuit testing
  writeFileSync(`${prefix}-age-over-21-claim.bin`, Buffer.from(vector.claims.ageOver21.bytes));
  writeFileSync(`${prefix}-age-over-18-claim.bin`, Buffer.from(vector.claims.ageOver18!.bytes));
  writeFileSync(`${prefix}-state-claim.bin`, Buffer.from(vector.claims.issuingJurisdiction!.bytes));
  writeFileSync(`${prefix}-mso.bin`, Buffer.from(vector.mso.bytes));
  writeFileSync(`${prefix}-mso-signature.bin`, Buffer.from(vector.mso.signature));
  writeFileSync(`${prefix}-iaca-pubkey-x.bin`, Buffer.from(vector.iacaKey.publicKeyX));
  writeFileSync(`${prefix}-iaca-pubkey-y.bin`, Buffer.from(vector.iacaKey.publicKeyY));

  console.log(`  Written: ${prefix}.*`);
}

function main() {
  const fixturesDir = './fixtures';
  mkdirSync(fixturesDir, { recursive: true });

  console.log('Generating test vectors...');

  for (const config of TEST_VECTORS) {
    const vector = generateTestVector(config);
    writeTestVector(fixturesDir, vector);
  }

  console.log('\nDone!');
}

main();
