// Circuit tests. Signatures come from test_vectors.nr (generated with the real
// TypeScript issuer code), so these also check JS ↔ Noir compatibility.
use crate::main;
use crate::test_vectors::{
    HIGH_CREDENTIAL_ID, HIGH_EXPIRES_AT, HIGH_INCOME, HIGH_ISSUED_AT, HIGH_SIGNATURE,
    HIGH_SUBJECT_ID, ISSUER_X, ISSUER_Y, LOW_CREDENTIAL_ID, LOW_EXPIRES_AT, LOW_INCOME,
    LOW_ISSUED_AT, LOW_SIGNATURE, LOW_SUBJECT_ID, OTHER_ISSUER_X, OTHER_ISSUER_Y, T0,
};

global THRESHOLD: u64 = 800000;
global NOW: u64 = T0 + 86400; // one day after issue
global CHALLENGE: Field = 0x1234;

// Calls main() with the HIGH (₹9.5L) credential, overriding one aspect at a time.
fn prove_high(threshold: u64, now: u64, income: u64, key_x: [u8; 32], key_y: [u8; 32]) {
    main(
        key_x,
        key_y,
        threshold,
        now,
        CHALLENGE,
        HIGH_SIGNATURE,
        HIGH_SUBJECT_ID,
        income,
        HIGH_ISSUED_AT,
        HIGH_EXPIRES_AT,
        HIGH_CREDENTIAL_ID,
    );
}

#[test]
fn valid_credential_above_threshold() {
    prove_high(THRESHOLD, NOW, HIGH_INCOME, ISSUER_X, ISSUER_Y);
}

#[test]
fn valid_at_exact_threshold_and_validity_boundaries() {
    prove_high(HIGH_INCOME, NOW, HIGH_INCOME, ISSUER_X, ISSUER_Y); // income == threshold
    prove_high(THRESHOLD, HIGH_ISSUED_AT, HIGH_INCOME, ISSUER_X, ISSUER_Y); // first valid second
    prove_high(THRESHOLD, HIGH_EXPIRES_AT - 1, HIGH_INCOME, ISSUER_X, ISSUER_Y); // last valid second
}

#[test(should_fail_with = "invalid issuer signature")]
fn tampered_income_is_rejected() {
    // Holder claims ₹15L using a signature over ₹9.5L.
    prove_high(THRESHOLD, NOW, 1500000, ISSUER_X, ISSUER_Y);
}

#[test(should_fail_with = "invalid issuer signature")]
fn tampered_expiry_is_rejected() {
    main(
        ISSUER_X,
        ISSUER_Y,
        THRESHOLD,
        NOW,
        CHALLENGE,
        HIGH_SIGNATURE,
        HIGH_SUBJECT_ID,
        HIGH_INCOME,
        HIGH_ISSUED_AT,
        HIGH_EXPIRES_AT + 31536000, // extend by a year
        HIGH_CREDENTIAL_ID,
    );
}

#[test(should_fail_with = "invalid issuer signature")]
fn wrong_issuer_key_is_rejected() {
    prove_high(THRESHOLD, NOW, HIGH_INCOME, OTHER_ISSUER_X, OTHER_ISSUER_Y);
}

#[test(should_fail_with = "invalid issuer signature")]
fn tampered_signature_is_rejected() {
    let mut sig = HIGH_SIGNATURE;
    sig[10] = sig[10] ^ 0x01;
    main(
        ISSUER_X,
        ISSUER_Y,
        THRESHOLD,
        NOW,
        CHALLENGE,
        sig,
        HIGH_SUBJECT_ID,
        HIGH_INCOME,
        HIGH_ISSUED_AT,
        HIGH_EXPIRES_AT,
        HIGH_CREDENTIAL_ID,
    );
}

#[test(should_fail_with = "invalid issuer signature")]
fn signature_from_another_credential_is_rejected() {
    // LOW credential's signature with HIGH credential's claims.
    main(
        ISSUER_X,
        ISSUER_Y,
        THRESHOLD,
        NOW,
        CHALLENGE,
        LOW_SIGNATURE,
        HIGH_SUBJECT_ID,
        HIGH_INCOME,
        HIGH_ISSUED_AT,
        HIGH_EXPIRES_AT,
        HIGH_CREDENTIAL_ID,
    );
}

#[test(should_fail_with = "credential expired")]
fn expired_credential_is_rejected() {
    prove_high(THRESHOLD, HIGH_EXPIRES_AT, HIGH_INCOME, ISSUER_X, ISSUER_Y);
}

#[test(should_fail_with = "credential not yet valid")]
fn not_yet_valid_credential_is_rejected() {
    prove_high(THRESHOLD, HIGH_ISSUED_AT - 1, HIGH_INCOME, ISSUER_X, ISSUER_Y);
}

#[test(should_fail_with = "income below threshold")]
fn genuine_credential_below_threshold_is_rejected() {
    main(
        ISSUER_X,
        ISSUER_Y,
        THRESHOLD,
        NOW,
        CHALLENGE,
        LOW_SIGNATURE,
        LOW_SUBJECT_ID,
        LOW_INCOME,
        LOW_ISSUED_AT,
        LOW_EXPIRES_AT,
        LOW_CREDENTIAL_ID,
    );
}
