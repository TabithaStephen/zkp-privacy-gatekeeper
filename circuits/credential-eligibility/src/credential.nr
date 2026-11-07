// Canonical ZKPG_INCOME_V1 encoding (docs/credential-format.md §2).
// schema_tag || subject_id || income || issued_at || expires_at || credential_id,
// each u64 big-endian, 48 bytes total.

pub global SCHEMA_TAG: u64 = 0x5A4B50475F494E31; // "ZKPG_IN1"
pub global MESSAGE_LENGTH: u32 = 48;

pub fn encode(
    subject_id: u64,
    income: u64,
    issued_at: u64,
    expires_at: u64,
    credential_id: u64,
) -> [u8; MESSAGE_LENGTH] {
    let fields = [SCHEMA_TAG, subject_id, income, issued_at, expires_at, credential_id];
    let mut out = [0; MESSAGE_LENGTH];
    for i in 0..6 {
        let bytes: [u8; 8] = (fields[i] as Field).to_be_bytes();
        for j in 0..8 {
            out[i * 8 + j] = bytes[j];
        }
    }
    out
}

#[test]
fn encoding_matches_typescript_and_python_test_vector() {
    // Same vector as packages/credentials/test/encoding.test.ts (independently
    // computed with Python struct.pack(">Q")).
    let expected: [u8; 48] = [
        0x5a, 0x4b, 0x50, 0x47, 0x5f, 0x49, 0x4e, 0x31, // schema tag
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe9, // subject 1001
        0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x7e, 0xf0, // income 950000
        0x00, 0x00, 0x00, 0x00, 0x69, 0x55, 0xb9, 0x00, // issued_at 1767225600
        0x00, 0x00, 0x00, 0x00, 0x6b, 0x36, 0xec, 0x80, // expires_at 1798761600
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, // credential_id 42
    ];
    assert_eq(encode(1001, 950000, 1767225600, 1798761600, 42), expected);
}
