// Helper circuit to compute Poseidon2 hashes for Prover.toml
//
// This outputs the iaca_root and nullifier values needed for the main circuit.
// Run with: nargo execute

use poseidon::poseidon2::Poseidon2;

/// Convert 32 bytes to a Field element (big-endian)
fn bytes32_to_field(bytes: [u8; 32]) -> Field {
    let mut result: Field = 0;
    for i in 0..32 {
        result = result * 256 + bytes[i] as Field;
    }
    result
}

/// Compute IACA root from public key coordinates
fn compute_iaca_root(pubkey_x: [u8; 32], pubkey_y: [u8; 32]) -> Field {
    let x_field = bytes32_to_field(pubkey_x);
    let y_field = bytes32_to_field(pubkey_y);
    Poseidon2::hash([x_field, y_field], 2)
}

/// Compute nullifier from document number, event ID, and IACA root
fn compute_nullifier(
    document_number: [u8; 32],
    event_id: Field,
    iaca_root: Field,
) -> Field {
    let doc_field = bytes32_to_field(document_number);
    Poseidon2::hash([doc_field, event_id, iaca_root], 3)
}

fn main(
    // Inputs from fixture
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],
    document_number: [u8; 32],
    event_id: Field,
) -> pub (Field, Field) {
    // Compute IACA root
    let iaca_root = compute_iaca_root(pubkey_x, pubkey_y);

    // Compute nullifier
    let nullifier = compute_nullifier(document_number, event_id, iaca_root);

    // Return both values - these will be printed by nargo execute
    (iaca_root, nullifier)
}
