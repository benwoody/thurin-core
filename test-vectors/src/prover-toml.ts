/**
 * Generate Prover.toml for Noir circuit from test fixtures
 *
 * Run with: pnpm tsx src/prover-toml.ts
 */

import { readFileSync, writeFileSync } from 'node:fs';

// Format a byte array as Noir array syntax
function formatBytes(bytes: number[], size?: number): string {
  const arr = size ? bytes.slice(0, size).concat(Array(size - bytes.length).fill(0)) : bytes;
  return `[${arr.join(', ')}]`;
}

// Format a field as hex string
function formatField(hex: string): string {
  return `"${hex}"`;
}

function main() {
  const fixturePath = process.argv[2] || './fixtures/california-over21.json';
  const outputPath = process.argv[3] || '../../packages/circuits/Prover.toml';

  console.log(`Loading fixture: ${fixturePath}`);
  const fixture = JSON.parse(readFileSync(fixturePath, 'utf-8'));

  // For now, use placeholder values for nullifier and iaca_root
  // These would need to be computed with the same Pedersen hash as the circuit
  // We'll use dummy values and let the circuit compute them
  const nullifier = "0x0"; // Placeholder - circuit will verify
  const iacaRoot = "0x0";  // Placeholder - circuit will verify
  const eventId = "0x1";   // Test event ID
  const proofTimestamp = 1704067200; // 2024-01-01 00:00:00 UTC

  // Pad MSO bytes to 512
  const msoBytes = fixture.mso.bytes.data || fixture.mso.bytes;
  const msoPadded = [...msoBytes, ...Array(512 - msoBytes.length).fill(0)];

  // Example bound address (vitalik.eth)
  const boundAddress = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";

  const proverToml = `# Thurin Circuit - Prover inputs
# Generated from: ${fixturePath}

# === Public inputs ===
nullifier = ${formatField(nullifier)}
proof_timestamp = ${proofTimestamp}
event_id = ${formatField(eventId)}
iaca_root = ${formatField(iacaRoot)}
bound_address = ${formatField(boundAddress)}
reveal_age_over_21 = true
reveal_age_over_18 = true
reveal_state = true
revealed_state = [${fixture.claims.issuingJurisdiction.item.elementValue.charCodeAt(0)}, ${fixture.claims.issuingJurisdiction.item.elementValue.charCodeAt(1)}]

# === Private inputs ===

# Age over 21 claim bytes (96 bytes)
age_over_21_claim_bytes = ${formatBytes(fixture.claims.ageOver21.bytes)}

# Age over 18 claim bytes (96 bytes)
age_over_18_claim_bytes = ${formatBytes(fixture.claims.ageOver18.bytes)}

# State claim bytes (107 bytes)
state_claim_bytes = ${formatBytes(fixture.claims.issuingJurisdiction.bytes)}

# MSO bytes (512 bytes, padded)
mso_bytes = ${formatBytes(msoPadded)}

# MSO signature (64 bytes)
mso_signature = ${formatBytes(fixture.mso.signature)}

# Document number (32 bytes)
document_number = ${formatBytes(fixture.documentNumber)}

# IACA public key X (32 bytes)
iaca_pubkey_x = ${formatBytes(fixture.iacaKey.publicKeyX)}

# IACA public key Y (32 bytes)
iaca_pubkey_y = ${formatBytes(fixture.iacaKey.publicKeyY)}
`;

  console.log(`Writing: ${outputPath}`);
  writeFileSync(outputPath, proverToml);
  console.log('Done!');

  console.log('\nNote: nullifier and iaca_root are placeholders.');
  console.log('To get correct values, we need to compute Pedersen hashes in TS.');
}

main();
