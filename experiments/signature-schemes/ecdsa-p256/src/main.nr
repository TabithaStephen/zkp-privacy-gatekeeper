// EXPERIMENT (Milestone 2): ECDSA P-256 (secp256r1) issuer signature verified in-circuit.
//
// Credential encoding (canonical, fixed length, 40 bytes):
//   schema_tag | subject_id | income | issued_at | expires_at   — each u64, big-endian.
// The issuer signs SHA-256(credential_bytes) with ECDSA P-256 (Node.js `crypto`).
// The circuit recomputes the hash from the PRIVATE fields, so a changed field
// produces a different hash and the signature check fails.
global SCHEMA_TAG: u64 = 0x5A4B50475F494E31; // "ZKPG_IN1": domain separation for this credential type

fn encode_credential(subject_id: u64, income: u64, issued_at: u64, expires_at: u64) -> [u8; 40] {
    let fields = [SCHEMA_TAG, subject_id, income, issued_at, expires_at];
    let mut out = [0; 40];
    for i in 0..5 {
        let bytes: [u8; 8] = (fields[i] as Field).to_be_bytes();
        for j in 0..8 {
            out[i * 8 + j] = bytes[j];
        }
    }
    out
}

fn main(
    // public
    issuer_pub_key_x: pub [u8; 32],
    issuer_pub_key_y: pub [u8; 32],
    minimum_income: pub u64,
    // private
    signature: [u8; 64],
    subject_id: u64,
    income: u64,
    issued_at: u64,
    expires_at: u64,
) {
    let message = encode_credential(subject_id, income, issued_at, expires_at);
    let message_hash = sha256::digest(message);
    let valid = std::ecdsa_secp256r1::verify_signature(
        issuer_pub_key_x,
        issuer_pub_key_y,
        signature,
        message_hash,
    );
    assert(valid, "invalid issuer signature");
    assert(income >= minimum_income, "income below threshold");
}
