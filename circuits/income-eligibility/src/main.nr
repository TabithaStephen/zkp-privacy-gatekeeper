// Milestone 1 — first learning circuit: "my income is at least the threshold".
//
// WHAT THIS PROVES
//   "I know a value `income` such that income >= minimum_income."
//   The verifier learns `minimum_income` (public) and that the statement holds.
//   The verifier does NOT learn `income`.
//
// WHAT THIS DOES NOT PROVE (deliberate limitation of Milestone 1)
//   Nothing ties `income` to a bank or any trusted issuer. The prover can pick
//   any number. Issuer-signed credentials are added in Milestones 2–3.
//
// INPUTS
//   income          — PRIVATE witness (no `pub`): known only to the prover.
//   minimum_income  — PUBLIC input (`pub`): known to both prover and verifier,
//                     and bound into the proof, so it cannot be swapped later.
//
// Amounts are whole rupees. u64 (max ≈ 1.8 × 10^19) leaves ample headroom;
// Noir range-checks u64 values, so a negative or wrapped value cannot be used.
fn main(income: u64, minimum_income: pub u64) {
    assert(income >= minimum_income, "income below threshold");
}

// ── Circuit tests (run with `nargo test`) ─────────────────────────────────
// All values are fictional.

#[test]
fn test_income_above_threshold() {
    main(950_000, 800_000);
}

#[test]
fn test_income_exactly_at_threshold() {
    // ">=": meeting the threshold exactly counts as eligible.
    main(800_000, 800_000);
}

#[test(should_fail_with = "income below threshold")]
fn test_income_below_threshold() {
    main(650_000, 800_000);
}

#[test(should_fail_with = "income below threshold")]
fn test_income_one_rupee_below_threshold() {
    main(799_999, 800_000);
}

#[test]
fn test_zero_threshold() {
    main(0, 0);
}

#[test]
fn test_max_u64_income() {
    main(18_446_744_073_709_551_615, 800_000);
}
