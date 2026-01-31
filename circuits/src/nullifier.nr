// Nullifier and IACA root computation
//
// Uses Poseidon2 hashing for efficient in-circuit computation.
// All hashes use domain separation to prevent cross-context collisions.

use poseidon::poseidon2::Poseidon2;

// Domain separators for Poseidon2 hashes
// These prevent hash collisions across different contexts
global DOMAIN_IACA_ROOT: Field = 0x01;
global DOMAIN_NULLIFIER: Field = 0x02;
global DOMAIN_ADDRESS_BINDING: Field = 0x03;

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
    Poseidon2::hash([DOMAIN_IACA_ROOT, x_field, y_field], 3)
}

/// Compute nullifier from document number, event ID, and IACA root
/// The nullifier is deterministic but unlinkable across different events
pub fn compute_nullifier(
    document_number: [u8; 32],
    event_id: Field,
    iaca_root: Field,
) -> Field {
    let doc_hash = bytes32_to_field(document_number);
    Poseidon2::hash([DOMAIN_NULLIFIER, doc_hash, event_id, iaca_root], 4)
}

/// Compute address binding from nullifier and bound address
/// This binds the proof to a specific wallet address for front-running protection
/// while keeping the nullifier unchanged for sybil resistance
pub fn compute_address_binding(nullifier: Field, bound_address: Field) -> Field {
    Poseidon2::hash([DOMAIN_ADDRESS_BINDING, nullifier, bound_address], 3)
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
fn test_address_binding() {
    let doc = [1u8; 32];
    let event_id: Field = 12345;
    let iaca_root: Field = 67890;
    let address1: Field = 0x1234567890abcdef;
    let address2: Field = 0xfedcba0987654321;

    let nullifier = compute_nullifier(doc, event_id, iaca_root);

    // Same nullifier + same address = same binding
    let binding1 = compute_address_binding(nullifier, address1);
    let binding2 = compute_address_binding(nullifier, address1);
    assert(binding1 == binding2);

    // Same nullifier + different address = different binding
    let binding3 = compute_address_binding(nullifier, address2);
    assert(binding1 != binding3);
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
