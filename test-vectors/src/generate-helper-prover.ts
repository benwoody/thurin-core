/**
 * Generate Prover.toml for the helper circuit
 *
 * Run with: pnpm tsx src/generate-helper-prover.ts
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function formatBytes(bytes: number[]): string {
  return `[${bytes.join(', ')}]`;
}

function main() {
  const fixturePath = process.argv[2] || './fixtures/california-over21.json';
  const outputPath = process.argv[3] || '../circuits-helper/Prover.toml';

  console.log(`Loading fixture: ${fixturePath}`);
  const fixture = JSON.parse(readFileSync(fixturePath, 'utf-8'));

  const eventId = '0x1'; // Test event ID

  const proverToml = `# Helper circuit inputs - computes iaca_root and nullifier
# Generated from: ${fixturePath}

# IACA public key X (32 bytes)
pubkey_x = ${formatBytes(fixture.iacaKey.publicKeyX)}

# IACA public key Y (32 bytes)
pubkey_y = ${formatBytes(fixture.iacaKey.publicKeyY)}

# Document number (32 bytes)
document_number = ${formatBytes(fixture.documentNumber)}

# Event ID
event_id = "${eventId}"
`;

  console.log(`Writing: ${outputPath}`);
  writeFileSync(join(__dirname, '..', outputPath), proverToml);
  console.log('Done!');
  console.log('\nNow run: cd ../circuits-helper && nargo execute');
}

main();
