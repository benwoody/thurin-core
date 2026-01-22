// Mobile Security Object (MSO) verification
//
// Extracts digests and validity information from MSO CBOR structures.

// MSO digest offsets (for digestID "0", "1", and "2")
pub global MSO_DIGEST_0_OFFSET: u32 = 143;  // 32-byte hash for digestID 0 (age_over_21)
pub global MSO_DIGEST_1_OFFSET: u32 = 179;  // 32-byte hash for digestID 1 (state)
pub global MSO_DIGEST_2_OFFSET: u32 = 215;  // 32-byte hash for digestID 2 (age_over_18)

// MSO validity date offset
pub global MSO_VALID_UNTIL_OFFSET: u32 = 96;  // 10-byte ISO date "YYYY-MM-DD"

/// Extract a 32-byte digest from MSO at the given offset
pub fn extract_mso_digest(mso: [u8; 512], offset: u32) -> [u8; 32] {
    let mut digest = [0u8; 32];
    for i in 0..32 {
        digest[i] = mso[offset + i];
    }
    digest
}

/// Extract validUntil date from MSO as YYYYMMDD integer
/// Date format: "YYYY-MM-DD" (10 ASCII bytes)
pub fn extract_mso_valid_until(mso: [u8; 512]) -> u32 {
    let offset = MSO_VALID_UNTIL_OFFSET;

    // Parse year (4 digits)
    let year = parse_ascii_digit(mso[offset]) * 1000
        + parse_ascii_digit(mso[offset + 1]) * 100
        + parse_ascii_digit(mso[offset + 2]) * 10
        + parse_ascii_digit(mso[offset + 3]);

    // Skip hyphen at offset+4

    // Parse month (2 digits)
    let month = parse_ascii_digit(mso[offset + 5]) * 10
        + parse_ascii_digit(mso[offset + 6]);

    // Skip hyphen at offset+7

    // Parse day (2 digits)
    let day = parse_ascii_digit(mso[offset + 8]) * 10
        + parse_ascii_digit(mso[offset + 9]);

    // Return as YYYYMMDD
    year * 10000 + month * 100 + day
}

/// Convert ASCII digit byte to integer (0-9)
pub fn parse_ascii_digit(byte: u8) -> u32 {
    assert(byte >= 48); // '0' = 48
    assert(byte <= 57); // '9' = 57
    (byte - 48) as u32
}

#[test]
fn test_extract_mso_digest() {
    // Create mock MSO with known digest at offset 143
    let mut mso = [0u8; 512];

    // Place a known 32-byte digest at offset 143
    let expected_digest: [u8; 32] = [
        0x3c, 0xfe, 0x0e, 0xb0, 0xc8, 0xa6, 0x65, 0x7f,
        0x58, 0x63, 0x17, 0x33, 0x37, 0x05, 0x49, 0x98,
        0xdf, 0x97, 0x77, 0x62, 0xf7, 0xd4, 0xcd, 0x2e,
        0x2a, 0x2b, 0x6e, 0xa7, 0x3b, 0x6c, 0xc8, 0x00
    ];

    for i in 0..32 {
        mso[143 + i] = expected_digest[i];
    }

    let extracted = extract_mso_digest(mso, MSO_DIGEST_0_OFFSET);

    // Compare manually
    for i in 0..32 {
        assert(extracted[i] == expected_digest[i]);
    }
}

#[test]
fn test_parse_ascii_digit() {
    assert(parse_ascii_digit(48) == 0); // '0'
    assert(parse_ascii_digit(49) == 1); // '1'
    assert(parse_ascii_digit(53) == 5); // '5'
    assert(parse_ascii_digit(57) == 9); // '9'
}

#[test]
fn test_extract_mso_valid_until() {
    // Create MSO with validUntil at offset 96: "2030-01-01"
    let mut mso = [0u8; 512];

    // "2030-01-01" as ASCII bytes at offset 96
    mso[96] = 50;  // '2'
    mso[97] = 48;  // '0'
    mso[98] = 51;  // '3'
    mso[99] = 48;  // '0'
    mso[100] = 45; // '-'
    mso[101] = 48; // '0'
    mso[102] = 49; // '1'
    mso[103] = 45; // '-'
    mso[104] = 48; // '0'
    mso[105] = 49; // '1'

    let expiry = extract_mso_valid_until(mso);
    assert(expiry == 20300101);
}
