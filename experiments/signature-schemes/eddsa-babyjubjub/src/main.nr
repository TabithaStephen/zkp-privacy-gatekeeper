// EXPERIMENT (Milestone 2): EdDSA over BabyJubJub with Poseidon, verified in-circuit.
//
// Credential encoding: message = Poseidon(schema_tag, subject_id, income, issued_at, expires_at)
// over BN254 field elements. The issuer signs `message` with EdDSA-Poseidon
// (@zk-kit/eddsa-poseidon). The circuit recomputes the Poseidon hash from the PRIVATE
// fields, so any changed field breaks the signature check.
use eddsa::eddsa_verify;
use poseidon::poseidon::PoseidonHasher;

global SCHEMA_TAG: Field = 0x5A4B50475F494E31; // "ZKPG_IN1"

fn main(
    // public
    issuer_pub_key_x: pub Field,
    issuer_pub_key_y: pub Field,
    minimum_income: pub u64,
    // private
    signature_s: Field,
    signature_r8_x: Field,
    signature_r8_y: Field,
    subject_id: u64,
    income: u64,
    issued_at: u64,
    expires_at: u64,
) {
    let message = poseidon::poseidon::bn254::hash_5([
        SCHEMA_TAG,
        subject_id as Field,
        income as Field,
        issued_at as Field,
        expires_at as Field,
    ]);
    let valid = eddsa_verify::<PoseidonHasher>(
        issuer_pub_key_x,
        issuer_pub_key_y,
        signature_s,
        signature_r8_x,
        signature_r8_y,
        message,
    );
    assert(valid, "invalid issuer signature");
    assert(income >= minimum_income, "income below threshold");
}
