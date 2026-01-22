// Nullifier and IACA root computation
//
// Uses Poseidon2 hashing for efficient in-circuit computation.

use poseidon::poseidon2::Poseidon2;

/// Convert 32 bytes to a Field element (big-endian)
pub fn bytes32_to_field(bytes: [u8; 32]) -> Field {
    let mut result: Field = 0;
    for i in 0..32 {
        result = result * 256 + bytes[i] as Field;
    }
    result
}

/// Compute IACA root from public key coordinates
/// This creates a unique identifier for an IACA certificate
pub fn compute_iaca_root(pubkey_x: [u8; 32], pubkey_y: [u8; 32]) -> Field {
    // Convert bytes to fields and hash with Poseidon2
    let x_field = bytes32_to_field(pubkey_x);
    let y_field = bytes32_to_field(pubkey_y);
    Poseidon2::hash([x_field, y_field], 2)
}

/// Compute nullifier from document number, event ID, and IACA root
/// The nullifier is deterministic but unlinkable across different events
pub fn compute_nullifier(
    document_number: [u8; 32],
    event_id: Field,
    iaca_root: Field,
) -> Field {
    let doc_hash = bytes32_to_field(document_number);
    Poseidon2::hash([doc_hash, event_id, iaca_root], 3)
}

#[test]
fn test_nullifier_deterministic() {
    let doc = [1u8; 32];
    let event_id: Field = 12345;
    let iaca_root: Field = 67890;

    let null1 = compute_nullifier(doc, event_id, iaca_root);
    let null2 = compute_nullifier(doc, event_id, iaca_root);

    assert(null1 == null2);
}

#[test]
fn test_iaca_root_computation() {
    // Test with known public key bytes
    let pubkey_x: [u8; 32] = [1; 32];
    let pubkey_y: [u8; 32] = [2; 32];

    let root1 = compute_iaca_root(pubkey_x, pubkey_y);
    let root2 = compute_iaca_root(pubkey_x, pubkey_y);

    // Same inputs = same root
    assert(root1 == root2);

    // Different inputs = different root
    let pubkey_y2: [u8; 32] = [3; 32];
    let root3 = compute_iaca_root(pubkey_x, pubkey_y2);
    assert(root1 != root3);
}
