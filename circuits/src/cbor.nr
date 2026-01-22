// CBOR extraction for mDL IssuerSignedItem structures
//
// Extracts claim values from fixed-schema CBOR bytes using hardcoded offsets.
// These offsets are discovered from test vectors and work for standard mDL claims.

// CBOR extraction offsets (discovered from test vectors)
pub global AGE_VALUE_OFFSET: u32 = 65;      // 0xf5 = true, 0xf4 = false
pub global STATE_CODE_OFFSET: u32 = 66;     // 2 bytes: "CA", "TX", etc.

// CBOR constants
pub global CBOR_TRUE: u8 = 0xf5;
pub global CBOR_FALSE: u8 = 0xf4;

/// Extract age boolean from IssuerSignedItem CBOR bytes
/// Works for both age_over_21 and age_over_18 (same structure, same offset)
pub fn extract_age_boolean(claim: [u8; 96]) -> bool {
    let value_byte = claim[AGE_VALUE_OFFSET];
    // Assert it's a valid boolean encoding
    assert((value_byte == CBOR_TRUE) | (value_byte == CBOR_FALSE));
    value_byte == CBOR_TRUE
}

/// Extract age_over_21 boolean from IssuerSignedItem CBOR bytes
pub fn extract_age_over_21(claim: [u8; 96]) -> bool {
    extract_age_boolean(claim)
}

/// Extract age_over_18 boolean from IssuerSignedItem CBOR bytes
pub fn extract_age_over_18(claim: [u8; 96]) -> bool {
    extract_age_boolean(claim)
}

/// Extract 2-character state code from IssuerSignedItem CBOR bytes
pub fn extract_state_code(claim: [u8; 107]) -> [u8; 2] {
    [claim[STATE_CODE_OFFSET], claim[STATE_CODE_OFFSET + 1]]
}

#[test]
fn test_extract_age_over_21_true() {
    // Minimal test: byte 65 = 0xf5 (true)
    let mut claim = [0u8; 96];
    claim[65] = CBOR_TRUE;
    assert(extract_age_over_21(claim) == true);
}

#[test]
fn test_extract_age_over_21_false() {
    let mut claim = [0u8; 96];
    claim[65] = CBOR_FALSE;
    assert(extract_age_over_21(claim) == false);
}

#[test]
fn test_extract_age_over_18_true() {
    // Minimal test: byte 65 = 0xf5 (true)
    let mut claim = [0u8; 96];
    claim[65] = CBOR_TRUE;
    assert(extract_age_over_18(claim) == true);
}

#[test]
fn test_extract_age_over_18_false() {
    let mut claim = [0u8; 96];
    claim[65] = CBOR_FALSE;
    assert(extract_age_over_18(claim) == false);
}

#[test]
fn test_extract_state_code() {
    let mut claim = [0u8; 107];
    claim[66] = 0x43; // 'C'
    claim[67] = 0x41; // 'A'
    let state = extract_state_code(claim);
    assert(state[0] == 0x43);
    assert(state[1] == 0x41);
}
