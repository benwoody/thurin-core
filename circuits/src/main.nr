// Thurin - Zero-knowledge mDL verification circuit
//
// Proves claims about a mobile driver's license (mDL) without revealing
// personal information. Uses fixed-schema CBOR parsing for efficiency.

mod cbor;
mod mso;
mod nullifier;
mod utils;

use sha256::digest as sha256_digest;
use std::ecdsa_secp256r1;

use cbor::{extract_age_over_21, extract_age_over_18, extract_state_code};
use mso::{extract_mso_digest, extract_mso_valid_until, MSO_DIGEST_0_OFFSET, MSO_DIGEST_1_OFFSET, MSO_DIGEST_2_OFFSET};
use nullifier::{compute_iaca_root, compute_nullifier};
use utils::{bytes32_eq, timestamp_to_yyyymmdd};

/// Main circuit entry point
fn main(
    // === Public inputs (revealed on-chain) ===
    nullifier: pub Field,
    proof_timestamp: pub u64,
    event_id: pub Field,
    iaca_root: pub Field,
    _bound_address: pub Field, // Wallet address this proof is bound to
    // Optional proofs (0 = don't verify/prove)
    prove_age_over_21: pub bool,
    prove_age_over_18: pub bool,
    prove_state: pub bool,
    proven_state: pub [u8; 2],

    // === Private inputs (never revealed) ===
    // Age over 21 claim (digestID=0 at MSO offset 143)
    age_over_21_claim_bytes: [u8; 96],

    // Age over 18 claim (digestID=2 at MSO offset 215)
    age_over_18_claim_bytes: [u8; 96],

    // State claim (digestID=1 at MSO offset 179)
    state_claim_bytes: [u8; 107],

    // MSO (Mobile Security Object)
    mso_bytes: [u8; 512],
    mso_signature: [u8; 64],

    // Document number (for nullifier)
    document_number: [u8; 32],

    // IACA public key
    iaca_pubkey_x: [u8; 32],
    iaca_pubkey_y: [u8; 32],
) {
    // 1. Verify IACA public key matches the expected root
    let computed_iaca_root = compute_iaca_root(iaca_pubkey_x, iaca_pubkey_y);
    assert(computed_iaca_root == iaca_root);

    // 2. Verify MSO signature with IACA public key
    let mso_hash = sha256_digest(mso_bytes);
    let sig_valid = ecdsa_secp256r1::verify_signature(
        iaca_pubkey_x,
        iaca_pubkey_y,
        mso_signature,
        mso_hash,
    );
    assert(sig_valid);

    // 3. Verify age_over_21 claim hashes to MSO digest
    let age_over_21_hash = sha256_digest(age_over_21_claim_bytes);
    let expected_age_21_digest = extract_mso_digest(mso_bytes, MSO_DIGEST_0_OFFSET);
    assert(bytes32_eq(age_over_21_hash, expected_age_21_digest));

    // 4. Verify age_over_18 claim hashes to MSO digest
    let age_over_18_hash = sha256_digest(age_over_18_claim_bytes);
    let expected_age_18_digest = extract_mso_digest(mso_bytes, MSO_DIGEST_2_OFFSET);
    assert(bytes32_eq(age_over_18_hash, expected_age_18_digest));

    // 5. Verify state claim hashes to MSO digest
    let state_claim_hash = sha256_digest(state_claim_bytes);
    let expected_state_digest = extract_mso_digest(mso_bytes, MSO_DIGEST_1_OFFSET);
    assert(bytes32_eq(state_claim_hash, expected_state_digest));

    // 6. Extract and verify age_over_21
    let is_over_21 = extract_age_over_21(age_over_21_claim_bytes);
    if prove_age_over_21 {
        assert(is_over_21); // Must be true if proving
    }

    // 7. Extract and verify age_over_18
    let is_over_18 = extract_age_over_18(age_over_18_claim_bytes);
    if prove_age_over_18 {
        assert(is_over_18); // Must be true if proving
    }

    // 8. Extract and verify state code
    let state_code = extract_state_code(state_claim_bytes);
    if prove_state {
        assert(state_code[0] == proven_state[0]);
        assert(state_code[1] == proven_state[1]);
    }

    // 9. Verify nullifier derivation
    let computed_nullifier = compute_nullifier(document_number, event_id, iaca_root);
    assert(computed_nullifier == nullifier);

    // 10. Check MSO has not expired
    let mso_expiry = extract_mso_valid_until(mso_bytes);
    let proof_date = timestamp_to_yyyymmdd(proof_timestamp);
    assert(mso_expiry >= proof_date); // MSO must not be expired at proof time
}

// ============================================================
// Integration tests with real California fixture data
// ============================================================

#[test]
fn test_california_fixture_claim_extraction() {
    // Test that we can correctly extract claims from California fixture

    let age_claim: [u8; 96] = [
        164, 102, 114, 97, 110, 100, 111, 109,
        88, 32, 246, 234, 201, 152, 94, 234,
        49, 103, 226, 168, 243, 31, 161, 59,
        86, 180, 159, 223, 217, 222, 187, 44,
        196, 108, 69, 88, 132, 216, 175, 243,
        69, 182, 104, 100, 105, 103, 101, 115,
        116, 73, 68, 0, 108, 101, 108, 101,
        109, 101, 110, 116, 86, 97, 108, 117,
        101, 245, 113, 101, 108, 101, 109, 101,
        110, 116, 73, 100, 101, 110, 116, 105,
        102, 105, 101, 114, 107, 97, 103, 101,
        95, 111, 118, 101, 114, 95, 50, 49,
    ];

    let state_claim: [u8; 107] = [
        164, 102, 114, 97, 110, 100, 111, 109,
        88, 32, 12, 131, 178, 23, 149, 149,
        250, 211, 6, 76, 58, 217, 180, 126,
        236, 215, 41, 108, 117, 54, 76, 70,
        153, 213, 135, 41, 196, 211, 78, 129,
        91, 29, 104, 100, 105, 103, 101, 115,
        116, 73, 68, 1, 108, 101, 108, 101,
        109, 101, 110, 116, 86, 97, 108, 117,
        101, 98, 67, 65, 113, 101, 108, 101,
        109, 101, 110, 116, 73, 100, 101, 110,
        116, 105, 102, 105, 101, 114, 116, 105,
        115, 115, 117, 105, 110, 103, 95, 106,
        117, 114, 105, 115, 100, 105, 99, 116,
        105, 111, 110,
    ];

    // Test age extraction - should be true for California over-21 fixture
    let is_over_21 = extract_age_over_21(age_claim);
    assert(is_over_21 == true);

    // Test state code extraction - should be "CA"
    let state = extract_state_code(state_claim);
    assert(state[0] == 67); // 'C'
    assert(state[1] == 65); // 'A'
}

#[test]
fn test_california_fixture_claim_hashes() {
    // Test that claim bytes hash to expected digests

    let age_claim: [u8; 96] = [
        164, 102, 114, 97, 110, 100, 111, 109,
        88, 32, 246, 234, 201, 152, 94, 234,
        49, 103, 226, 168, 243, 31, 161, 59,
        86, 180, 159, 223, 217, 222, 187, 44,
        196, 108, 69, 88, 132, 216, 175, 243,
        69, 182, 104, 100, 105, 103, 101, 115,
        116, 73, 68, 0, 108, 101, 108, 101,
        109, 101, 110, 116, 86, 97, 108, 117,
        101, 245, 113, 101, 108, 101, 109, 101,
        110, 116, 73, 100, 101, 110, 116, 105,
        102, 105, 101, 114, 107, 97, 103, 101,
        95, 111, 118, 101, 114, 95, 50, 49,
    ];

    let state_claim: [u8; 107] = [
        164, 102, 114, 97, 110, 100, 111, 109,
        88, 32, 12, 131, 178, 23, 149, 149,
        250, 211, 6, 76, 58, 217, 180, 126,
        236, 215, 41, 108, 117, 54, 76, 70,
        153, 213, 135, 41, 196, 211, 78, 129,
        91, 29, 104, 100, 105, 103, 101, 115,
        116, 73, 68, 1, 108, 101, 108, 101,
        109, 101, 110, 116, 86, 97, 108, 117,
        101, 98, 67, 65, 113, 101, 108, 101,
        109, 101, 110, 116, 73, 100, 101, 110,
        116, 105, 102, 105, 101, 114, 116, 105,
        115, 115, 117, 105, 110, 103, 95, 106,
        117, 114, 105, 115, 100, 105, 99, 116,
        105, 111, 110,
    ];

    // Expected hashes from fixture
    let expected_age_hash: [u8; 32] = [
        60, 254, 14, 176, 200, 166, 101, 127,
        88, 99, 23, 51, 55, 5, 73, 152,
        223, 151, 119, 98, 247, 212, 205, 46,
        42, 43, 110, 167, 59, 108, 200, 0,
    ];

    let expected_state_hash: [u8; 32] = [
        190, 186, 18, 149, 215, 115, 222, 199,
        190, 42, 218, 163, 140, 79, 139, 222,
        16, 62, 249, 153, 246, 246, 225, 130,
        63, 249, 14, 192, 221, 117, 157, 212,
    ];

    // Compute hashes and verify
    let age_hash = sha256_digest(age_claim);
    let state_hash = sha256_digest(state_claim);

    assert(bytes32_eq(age_hash, expected_age_hash));
    assert(bytes32_eq(state_hash, expected_state_hash));
}

#[test]
fn test_california_fixture_mso_digests() {
    // Test that MSO contains the expected claim digests at correct offsets

    let mso: [u8; 512] = [
        164, 103, 100, 111, 99, 84, 121, 112,
        101, 117, 111, 114, 103, 46, 105, 115,
        111, 46, 49, 56, 48, 49, 51, 46,
        53, 46, 49, 46, 109, 68, 76, 108,
        118, 97, 108, 105, 100, 105, 116, 121,
        73, 110, 102, 111, 163, 102, 115, 105,
        103, 110, 101, 100, 106, 50, 48, 50,
        54, 45, 48, 49, 45, 48, 49, 105,
        118, 97, 108, 105, 100, 70, 114, 111,
        109, 106, 50, 48, 50, 54, 45, 48,
        49, 45, 48, 49, 106, 118, 97, 108,
        105, 100, 85, 110, 116, 105, 108, 106,
        50, 48, 51, 48, 45, 48, 49, 45,
        48, 49, 108, 118, 97, 108, 117, 101,
        68, 105, 103, 101, 115, 116, 115, 161,
        113, 111, 114, 103, 46, 105, 115, 111,
        46, 49, 56, 48, 49, 51, 46, 53,
        46, 49, 162, 97, 48, 88, 32, 60,
        254, 14, 176, 200, 166, 101, 127, 88,
        99, 23, 51, 55, 5, 73, 152, 223,
        151, 119, 98, 247, 212, 205, 46, 42,
        43, 110, 167, 59, 108, 200, 0, 97,
        49, 88, 32, 190, 186, 18, 149, 215,
        115, 222, 199, 190, 42, 218, 163, 140,
        79, 139, 222, 16, 62, 249, 153, 246,
        246, 225, 130, 63, 249, 14, 192, 221,
        117, 157, 212, 111, 100, 105, 103, 101,
        115, 116, 65, 108, 103, 111, 114, 105,
        116, 104, 109, 103, 83, 72, 65, 45,
        50, 53, 54, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    ];

    // Expected digests (should match claim hashes)
    let expected_age_digest: [u8; 32] = [
        60, 254, 14, 176, 200, 166, 101, 127,
        88, 99, 23, 51, 55, 5, 73, 152,
        223, 151, 119, 98, 247, 212, 205, 46,
        42, 43, 110, 167, 59, 108, 200, 0,
    ];

    let expected_state_digest: [u8; 32] = [
        190, 186, 18, 149, 215, 115, 222, 199,
        190, 42, 218, 163, 140, 79, 139, 222,
        16, 62, 249, 153, 246, 246, 225, 130,
        63, 249, 14, 192, 221, 117, 157, 212,
    ];

    // Extract digests from MSO
    let age_digest = extract_mso_digest(mso, MSO_DIGEST_0_OFFSET);
    let state_digest = extract_mso_digest(mso, MSO_DIGEST_1_OFFSET);

    assert(bytes32_eq(age_digest, expected_age_digest));
    assert(bytes32_eq(state_digest, expected_state_digest));
}

#[test]
fn test_california_full_claim_verification() {
    // Full integration: verify claims hash correctly and match MSO digests

    let age_claim: [u8; 96] = [
        164, 102, 114, 97, 110, 100, 111, 109,
        88, 32, 246, 234, 201, 152, 94, 234,
        49, 103, 226, 168, 243, 31, 161, 59,
        86, 180, 159, 223, 217, 222, 187, 44,
        196, 108, 69, 88, 132, 216, 175, 243,
        69, 182, 104, 100, 105, 103, 101, 115,
        116, 73, 68, 0, 108, 101, 108, 101,
        109, 101, 110, 116, 86, 97, 108, 117,
        101, 245, 113, 101, 108, 101, 109, 101,
        110, 116, 73, 100, 101, 110, 116, 105,
        102, 105, 101, 114, 107, 97, 103, 101,
        95, 111, 118, 101, 114, 95, 50, 49,
    ];

    let state_claim: [u8; 107] = [
        164, 102, 114, 97, 110, 100, 111, 109,
        88, 32, 12, 131, 178, 23, 149, 149,
        250, 211, 6, 76, 58, 217, 180, 126,
        236, 215, 41, 108, 117, 54, 76, 70,
        153, 213, 135, 41, 196, 211, 78, 129,
        91, 29, 104, 100, 105, 103, 101, 115,
        116, 73, 68, 1, 108, 101, 108, 101,
        109, 101, 110, 116, 86, 97, 108, 117,
        101, 98, 67, 65, 113, 101, 108, 101,
        109, 101, 110, 116, 73, 100, 101, 110,
        116, 105, 102, 105, 101, 114, 116, 105,
        115, 115, 117, 105, 110, 103, 95, 106,
        117, 114, 105, 115, 100, 105, 99, 116,
        105, 111, 110,
    ];

    let mso: [u8; 512] = [
        164, 103, 100, 111, 99, 84, 121, 112,
        101, 117, 111, 114, 103, 46, 105, 115,
        111, 46, 49, 56, 48, 49, 51, 46,
        53, 46, 49, 46, 109, 68, 76, 108,
        118, 97, 108, 105, 100, 105, 116, 121,
        73, 110, 102, 111, 163, 102, 115, 105,
        103, 110, 101, 100, 106, 50, 48, 50,
        54, 45, 48, 49, 45, 48, 49, 105,
        118, 97, 108, 105, 100, 70, 114, 111,
        109, 106, 50, 48, 50, 54, 45, 48,
        49, 45, 48, 49, 106, 118, 97, 108,
        105, 100, 85, 110, 116, 105, 108, 106,
        50, 48, 51, 48, 45, 48, 49, 45,
        48, 49, 108, 118, 97, 108, 117, 101,
        68, 105, 103, 101, 115, 116, 115, 161,
        113, 111, 114, 103, 46, 105, 115, 111,
        46, 49, 56, 48, 49, 51, 46, 53,
        46, 49, 162, 97, 48, 88, 32, 60,
        254, 14, 176, 200, 166, 101, 127, 88,
        99, 23, 51, 55, 5, 73, 152, 223,
        151, 119, 98, 247, 212, 205, 46, 42,
        43, 110, 167, 59, 108, 200, 0, 97,
        49, 88, 32, 190, 186, 18, 149, 215,
        115, 222, 199, 190, 42, 218, 163, 140,
        79, 139, 222, 16, 62, 249, 153, 246,
        246, 225, 130, 63, 249, 14, 192, 221,
        117, 157, 212, 111, 100, 105, 103, 101,
        115, 116, 65, 108, 103, 111, 114, 105,
        116, 104, 109, 103, 83, 72, 65, 45,
        50, 53, 54, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    ];

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
    assert(state_code[0] == 67); // 'C'
    assert(state_code[1] == 65); // 'A'
}
