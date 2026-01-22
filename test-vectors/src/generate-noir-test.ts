/**
 * Generate Noir integration test from fixture data
 *
 * Run with: pnpm tsx src/generate-noir-test.ts
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function formatNoirArray(bytes: number[], name: string, size: number): string {
  // Pad or truncate to exact size
  const padded = [...bytes.slice(0, size)];
  while (padded.length < size) {
    padded.push(0);
  }

  // Format as Noir array with 8 bytes per line
  const lines: string[] = [];
  for (let i = 0; i < padded.length; i += 8) {
    const chunk = padded.slice(i, Math.min(i + 8, padded.length));
    lines.push('        ' + chunk.join(', ') + ',');
  }

  return `    let ${name}: [u8; ${size}] = [\n${lines.join('\n')}\n    ];`;
}

function main() {
  const fixturePath = process.argv[2] || './fixtures/california-over21.json';
  console.log(`Loading fixture: ${fixturePath}`);

  const fixture = JSON.parse(readFileSync(fixturePath, 'utf-8'));

  // Extract byte arrays
  const ageClaim = fixture.claims.ageOver21.bytes;
  const stateClaim = fixture.claims.issuingJurisdiction.bytes;
  const msoBytes = fixture.mso.bytes.data || fixture.mso.bytes;
  const msoSignature = fixture.mso.signature;
  const documentNumber = fixture.documentNumber;
  const pubkeyX = fixture.iacaKey.publicKeyX;
  const pubkeyY = fixture.iacaKey.publicKeyY;

  // Get expected hashes for verification
  const ageHash = fixture.claims.ageOver21.hash;
  const stateHash = fixture.claims.issuingJurisdiction.hash;

  // State code
  const stateCode = fixture.claims.issuingJurisdiction.item.elementValue;

  const testCode = `
#[test]
fn test_california_fixture_claim_extraction() {
    // Test that we can correctly extract claims from California fixture

${formatNoirArray(ageClaim, 'age_claim', 96)}

${formatNoirArray(stateClaim, 'state_claim', 107)}

    // Test age extraction - should be true for California over-21 fixture
    let is_over_21 = extract_age_over_21(age_claim);
    assert(is_over_21 == true);

    // Test state code extraction - should be "CA"
    let state = extract_state_code(state_claim);
    assert(state[0] == ${stateCode.charCodeAt(0)}); // '${stateCode[0]}'
    assert(state[1] == ${stateCode.charCodeAt(1)}); // '${stateCode[1]}'
}

#[test]
fn test_california_fixture_claim_hashes() {
    // Test that claim bytes hash to expected digests

${formatNoirArray(ageClaim, 'age_claim', 96)}

${formatNoirArray(stateClaim, 'state_claim', 107)}

    // Expected hashes from fixture
${formatNoirArray(ageHash, 'expected_age_hash', 32)}

${formatNoirArray(stateHash, 'expected_state_hash', 32)}

    // Compute hashes and verify
    let age_hash = sha256_digest(age_claim);
    let state_hash = sha256_digest(state_claim);

    assert(bytes32_eq(age_hash, expected_age_hash));
    assert(bytes32_eq(state_hash, expected_state_hash));
}

#[test]
fn test_california_fixture_mso_digests() {
    // Test that MSO contains the expected claim digests at correct offsets

${formatNoirArray(msoBytes, 'mso', 512)}

    // Expected digests (should match claim hashes)
${formatNoirArray(ageHash, 'expected_age_digest', 32)}

${formatNoirArray(stateHash, 'expected_state_digest', 32)}

    // Extract digests from MSO
    let age_digest = extract_mso_digest(mso, MSO_DIGEST_0_OFFSET);
    let state_digest = extract_mso_digest(mso, MSO_DIGEST_1_OFFSET);

    assert(bytes32_eq(age_digest, expected_age_digest));
    assert(bytes32_eq(state_digest, expected_state_digest));
}

#[test]
fn test_california_full_claim_verification() {
    // Full integration: verify claims hash correctly and match MSO digests

${formatNoirArray(ageClaim, 'age_claim', 96)}

${formatNoirArray(stateClaim, 'state_claim', 107)}

${formatNoirArray(msoBytes, 'mso', 512)}

    // Hash the claims
    let age_hash = sha256_digest(age_claim);
    let state_hash = sha256_digest(state_claim);

    // Extract expected digests from MSO
    let expected_age = extract_mso_digest(mso, MSO_DIGEST_0_OFFSET);
    let expected_state = extract_mso_digest(mso, MSO_DIGEST_1_OFFSET);

    // Verify they match
    assert(bytes32_eq(age_hash, expected_age));
    assert(bytes32_eq(state_hash, expected_state));

    // Extract and verify claim values
    let is_over_21 = extract_age_over_21(age_claim);
    let state_code = extract_state_code(state_claim);

    assert(is_over_21 == true);
    assert(state_code[0] == ${stateCode.charCodeAt(0)}); // '${stateCode[0]}'
    assert(state_code[1] == ${stateCode.charCodeAt(1)}); // '${stateCode[1]}'
}
`;

  // Write to a file that can be appended to main.nr
  const outputPath = join(__dirname, '..', '..', 'circuits', 'src', 'integration_tests.nr');
  writeFileSync(outputPath, testCode.trim());
  console.log(`Generated: ${outputPath}`);
  console.log('\nTo use these tests, append to main.nr or include as a module.');
}

main();
