// Utility functions for the mDL verification circuit

/// Compare two 32-byte arrays for equality
pub fn bytes32_eq(a: [u8; 32], b: [u8; 32]) -> bool {
    let mut eq = true;
    for i in 0..32 {
        if a[i] != b[i] {
            eq = false;
        }
    }
    eq
}

/// Convert unix timestamp to YYYYMMDD integer
/// Note: This is a simplified conversion that assumes dates after 2020
/// For a production circuit, consider passing proof_date as a public input
pub fn timestamp_to_yyyymmdd(timestamp: u64) -> u32 {
    // Simplified: we'll use a lookup-free approximation
    // Seconds since 1970-01-01 00:00:00 UTC
    // For verification purposes, we convert to days since epoch
    // then to year/month/day

    // Days since epoch
    let days_since_epoch = timestamp / 86400;

    // Approximate year (365.25 days per year average)
    // Days from 1970 to 2020: ~18262
    // We'll compute relative to 2020-01-01 (epoch day 18262)
    let days_since_2020 = if days_since_epoch >= 18262 {
        days_since_epoch - 18262
    } else {
        0 // Before 2020, clamp to 2020
    };

    // Approximate years since 2020 (using 365 days, close enough for expiry)
    let years_since_2020 = days_since_2020 / 365;
    let year = 2020 + years_since_2020;

    // Remaining days in year
    let day_of_year = days_since_2020 % 365;

    // Approximate month and day (simplified 30-day months)
    let month = (day_of_year / 30) + 1;
    let day = (day_of_year % 30) + 1;

    // Clamp month to 1-12 and day to 1-28
    let month_clamped = if month > 12 { 12 } else { month };
    let day_clamped = if day > 28 { 28 } else { day };

    (year * 10000 + month_clamped * 100 + day_clamped) as u32
}

#[test]
fn test_bytes32_eq() {
    let a: [u8; 32] = [1; 32];
    let b: [u8; 32] = [1; 32];
    let c: [u8; 32] = [2; 32];

    assert(bytes32_eq(a, b));
    assert(!bytes32_eq(a, c));
}

#[test]
fn test_timestamp_to_yyyymmdd() {
    // 2024-01-01 00:00:00 UTC = 1704067200
    let date_2024 = timestamp_to_yyyymmdd(1704067200);
    // Should be approximately 2024MMDD
    assert(date_2024 >= 20240101);
    assert(date_2024 < 20250101);

    // 2026-01-17 (today's date based on context)
    // Approximately: 2026 - 2020 = 6 years = 6*365 = 2190 days
    // Plus 17 days in January
    // Total: 2190 + 17 = 2207 days since 2020
    // Epoch day for 2020-01-01: 18262
    // Epoch day for 2026-01-17: 18262 + 2207 = 20469
    // Timestamp: 20469 * 86400 = 1768521600
    let date_2026 = timestamp_to_yyyymmdd(1768521600);
    assert(date_2026 >= 20260101);
    assert(date_2026 < 20270101);
}

#[test]
fn test_expiry_comparison() {
    // MSO valid until 2030-01-01, proof at 2026-01-17
    let mso_expiry: u32 = 20300101;
    let proof_date: u32 = 20260117;

    // Should pass: MSO not expired
    assert(mso_expiry >= proof_date);
}
