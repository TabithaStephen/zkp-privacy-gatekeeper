// Milestone 3: credential-aware income eligibility.
//
// STATEMENT PROVEN
//   "I hold a ZKPG_INCOME_V1 credential, signed with ECDSA P-256 by the issuer whose
//    public key is (issuer_pub_key_x, issuer_pub_key_y), that is valid at current_time,
//    and whose income is at least minimum_income."
//
// PUBLIC INPUTS (seen by the verifier, bound into the proof)
//   issuer_pub_key_x/y — which issuer signed; the verifier checks it is trusted
//   minimum_income     — the verifier's threshold (whole rupees)
//   current_time       — the verifier's "as of" time (unix seconds); the verifier
//                        checks it is close to the real time
//   challenge          — the verifier's random nonce for this request; binding it into
//                        the proof prevents reuse in another request (tracked in M5)
//
// PRIVATE WITNESS (never leaves the holder's device)
//   signature and all five claims, including the exact income.
//
// Credential encoding must match packages/credentials/src/encoding.ts and
// docs/credential-format.md exactly (48 bytes, u64 big-endian).

mod credential;
// Test-only modules: their #[test] functions run under `nargo test` and do not
// add constraints to the compiled circuit.
mod test_vectors;
mod tests;

fn main(
    // public
    issuer_pub_key_x: pub [u8; 32],
    issuer_pub_key_y: pub [u8; 32],
    minimum_income: pub u64,
    current_time: pub u64,
    challenge: pub Field,
    // private
    signature: [u8; 64],
    subject_id: u64,
    income: u64,
    issued_at: u64,
    expires_at: u64,
    credential_id: u64,
) {
    // 1. Issuer authenticity: the signature covers exactly these claims.
    let message = credential::encode(subject_id, income, issued_at, expires_at, credential_id);
    let message_hash = sha256::digest(message);
    assert(
        std::ecdsa_secp256r1::verify_signature(
            issuer_pub_key_x,
            issuer_pub_key_y,
            signature,
            message_hash,
        ),
        "invalid issuer signature",
    );

    // 2. Validity window at the verifier's time.
    assert(issued_at <= current_time, "credential not yet valid");
    assert(current_time < expires_at, "credential expired");

    // 3. The eligibility condition itself.
    assert(income >= minimum_income, "income below threshold");

    // `challenge` needs no constraint: as a public input it is part of the proof's
    // transcript, so a proof made for one challenge fails verification for any other.
    // This is tested end-to-end, not assumed.
    let _ = challenge;
}
