use {
    crate::{scalar, VerificationCriteria, PUBKEY_SERIALIZED_SIZE, SIGNATURE_SERIALIZED_SIZE},
    solana_curve25519::{
        edwards::{add_edwards, multiscalar_multiply_edwards, subtract_edwards, PodEdwardsPoint},
        scalar::PodScalar,
    },
    solana_program_error::ProgramError,
};

const ED25519_BASEPOINT_NEGATED_COMPRESSED: PodEdwardsPoint = PodEdwardsPoint([
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0xe6,
]);
/// Identity point of the Edwards curve, in compressed form.
pub(crate) const EDWARDS_IDENTITY_COMPRESSED_BYTES: [u8; PUBKEY_SERIALIZED_SIZE] = [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const EDWARDS_IDENTITY_COMPRESSED: PodEdwardsPoint =
    PodEdwardsPoint(EDWARDS_IDENTITY_COMPRESSED_BYTES);

/// Stateless, zero-allocation Ed25519 verifier.
///
/// The verification behavior is selected by [`VerificationCriteria`]. A verifier
/// created with [`Ed25519Verifier::new`] uses the [`VerificationCriteria::zip215`]
/// preset, matching this crate's historical behavior.
#[derive(Debug, Clone, Copy)]
pub struct Ed25519Verifier {
    criteria: VerificationCriteria,
}

impl Default for Ed25519Verifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Ed25519Verifier {
    /// Initializes a verifier using the default [ZIP-215] criteria.
    ///
    /// [ZIP-215]: VerificationCriteria::zip215
    pub const fn new() -> Self {
        Self {
            criteria: VerificationCriteria::zip215(),
        }
    }

    /// Initializes a verifier with explicit [`VerificationCriteria`].
    pub const fn with_criteria(criteria: VerificationCriteria) -> Self {
        Self { criteria }
    }

    /// Returns the criteria this verifier enforces.
    pub const fn criteria(&self) -> VerificationCriteria {
        self.criteria
    }

    /// Verifies one Ed25519 signature according to the configured criteria.
    ///
    /// The core relation is `S*B - H(R || A || M)*A == R`. Depending on
    /// [`VerificationCriteria::cofactored`], the check is performed either
    /// cofactored — `[8](S*B - H*A - R) == identity`, matching the
    /// ed25519-zebra batch verification shape — or cofactorless —
    /// `S*B - H*A - R == identity`. The canonical-encoding and
    /// small-order rejections are applied first per the configured knobs.
    pub fn verify_signature(
        &self,
        signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
        public_key: &[u8; PUBKEY_SERIALIZED_SIZE],
        message: &[u8],
    ) -> Result<(), ProgramError> {
        let (r_bytes, s_bytes) = signature.split_at(32);
        let r_bytes: &[u8; 32] = r_bytes.try_into().unwrap();
        let s_bytes: &[u8; 32] = s_bytes.try_into().unwrap();

        // `require_canonical_s` is deliberately not checked because
        // `multiscalar_multiply_edwards` converts `PodScalar` through
        // `Scalar::from_canonical_bytes` and returns `None` on a non-canonical
        // scalar, which maps to the same `InvalidArgument` below. Re-checking
        // it in-program duplicates work the curve backend already performs.

        if self.criteria.require_canonical_a && !scalar::is_canonical_point_encoding(public_key) {
            return Err(ProgramError::InvalidArgument);
        }
        if self.criteria.require_canonical_r && !scalar::is_canonical_point_encoding(r_bytes) {
            return Err(ProgramError::InvalidArgument);
        }

        let r_point = PodEdwardsPoint(*r_bytes);
        let public_key_point = PodEdwardsPoint(*public_key);

        if self.criteria.reject_small_order_a && is_small_order(&public_key_point)? {
            return Err(ProgramError::InvalidArgument);
        }
        if self.criteria.reject_small_order_r && is_small_order(&r_point)? {
            return Err(ProgramError::InvalidArgument);
        }

        let challenge = compute_challenge(r_bytes, public_key, message);

        // S*(-B) + H*A = -(S*B - H*A), so this yields the negation of the value
        // the verification equation compares against R.
        let neg_lhs = multiscalar_multiply_edwards(
            &[PodScalar(*s_bytes), PodScalar(challenge)],
            &[ED25519_BASEPOINT_NEGATED_COMPRESSED, public_key_point],
        )
        .ok_or(ProgramError::InvalidArgument)?;

        // Flip the sign bit back to recover the encoding of `S*B - H*A`, then
        // compare against `R` as supplied. `neg_lhs` is canonical, so the flip
        // yields the canonical encoding of `lhs` (except when `lhs` has x = 0,
        // where it yields negative zero — which can only miss, never falsely
        // match). A match therefore implies `R == lhs` as points, so `lhs - R`
        // is the identity and both the cofactorless and the cofactored equation
        // hold. Deciding here skips the `subtract_edwards` syscall on the path
        // every honestly generated signature follows.
        let mut lhs_bytes = neg_lhs.0;
        lhs_bytes[31] ^= 0x80;
        if lhs_bytes == *r_bytes {
            return Ok(());
        }

        let lhs = PodEdwardsPoint(lhs_bytes);
        let difference = subtract_edwards(&lhs, &r_point).ok_or(ProgramError::InvalidArgument)?;

        // An exact-identity difference satisfies both the cofactorless and the
        // cofactored equation, so accept it without the cofactor multiplication.
        // This is the common case for honestly generated (prime-order) signatures,
        // so it saves the `multiply_by_8` syscalls on the hot path.
        if difference == EDWARDS_IDENTITY_COMPRESSED {
            return Ok(());
        }
        // Cofactorless verification requires an exact identity, which is now ruled
        // out. Cofactored verification additionally accepts a difference that
        // clears to identity once multiplied by the cofactor 8 (the mixed-order
        // points that ZIP-215 tolerates).
        if !self.criteria.cofactored {
            return Err(ProgramError::InvalidArgument);
        }
        if multiply_by_8(&difference).ok_or(ProgramError::InvalidArgument)?
            != EDWARDS_IDENTITY_COMPRESSED
        {
            return Err(ProgramError::InvalidArgument);
        }

        Ok(())
    }
}

/// Returns `Ok(true)` if `point` decompresses to a small-order (torsion) point.
///
/// A point has order dividing the cofactor 8 exactly when `[8]P` is the
/// identity. This decompresses `point` (accepting non-canonical encodings, which
/// reduce modulo `p`). An encoding that does not decompress returns
/// `Err(InvalidArgument)` so the caller can reject it immediately, rather than
/// treating it as non-small-order and paying for the subsequent verification
/// syscalls only to fail there.
fn is_small_order(point: &PodEdwardsPoint) -> Result<bool, ProgramError> {
    let product = multiply_by_8(point).ok_or(ProgramError::InvalidArgument)?;
    Ok(product == EDWARDS_IDENTITY_COMPRESSED)
}

/// Multiplies `point` by the cofactor 8 via three point doublings.
///
/// Cheaper than a scalar multiplication by 8: three `sol_curve_group_op`
/// additions (473 CU each, 1,419 total) versus one multiplication (2,177 CU).
/// Returns `None` if `point` is not a valid curve encoding.
fn multiply_by_8(point: &PodEdwardsPoint) -> Option<PodEdwardsPoint> {
    let double = add_edwards(point, point)?;
    let quadruple = add_edwards(&double, &double)?;
    add_edwards(&quadruple, &quadruple)
}

fn compute_challenge(signature_r: &[u8; 32], public_key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let digest = solana_sha512_hasher::hashv(&[signature_r, public_key, message]).to_bytes();
    scalar::reduce_wide(&digest)
}

#[cfg(test)]
mod tests {
    use {super::*, curve25519_dalek::traits::Identity, ed25519_dalek::SigningKey};

    const SMALL_ORDER_PUBLIC_KEY_COMPRESSED: [u8; PUBKEY_SERIALIZED_SIZE] = [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];

    const NON_DECOMPRESSING_ENCODING: [u8; PUBKEY_SERIALIZED_SIZE] = [
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    fn prime_order_point() -> PodEdwardsPoint {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        PodEdwardsPoint(signing_key.verifying_key().to_bytes())
    }

    #[test]
    fn negated_basepoint_constant_matches_curve25519_dalek() {
        let mut expected = curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED.to_bytes();
        // Negating a compressed Edwards point flips only the sign bit of `x`,
        // stored in the top bit of the last byte; the `y`-coordinate bytes are
        // unchanged.
        expected[31] ^= 0x80;

        assert_eq!(ED25519_BASEPOINT_NEGATED_COMPRESSED.0, expected);
    }

    #[test]
    fn identity_constant_matches_curve25519_dalek() {
        let expected = curve25519_dalek::edwards::EdwardsPoint::identity()
            .compress()
            .to_bytes();

        assert_eq!(EDWARDS_IDENTITY_COMPRESSED_BYTES, expected);
    }

    #[test]
    fn multiply_by_8_maps_identity_to_identity() {
        assert_eq!(
            multiply_by_8(&EDWARDS_IDENTITY_COMPRESSED),
            Some(EDWARDS_IDENTITY_COMPRESSED)
        );
    }

    #[test]
    fn multiply_by_8_clears_small_order_point() {
        let point = PodEdwardsPoint(SMALL_ORDER_PUBLIC_KEY_COMPRESSED);
        assert_eq!(multiply_by_8(&point), Some(EDWARDS_IDENTITY_COMPRESSED));
    }

    #[test]
    fn multiply_by_8_does_not_clear_prime_order_point() {
        assert_ne!(
            multiply_by_8(&prime_order_point()),
            Some(EDWARDS_IDENTITY_COMPRESSED)
        );
    }

    #[test]
    fn multiply_by_8_rejects_non_decompressing_encoding() {
        let point = PodEdwardsPoint(NON_DECOMPRESSING_ENCODING);
        assert_eq!(multiply_by_8(&point), None);
    }

    #[test]
    fn is_small_order_true_for_torsion_point() {
        let point = PodEdwardsPoint(SMALL_ORDER_PUBLIC_KEY_COMPRESSED);
        assert_eq!(is_small_order(&point), Ok(true));
    }

    #[test]
    fn is_small_order_false_for_prime_order_point() {
        assert_eq!(is_small_order(&prime_order_point()), Ok(false));
    }

    #[test]
    fn is_small_order_propagates_decompression_failure() {
        let point = PodEdwardsPoint(NON_DECOMPRESSING_ENCODING);
        assert_eq!(is_small_order(&point), Err(ProgramError::InvalidArgument));
    }

    #[test]
    fn compute_challenge_hashes_r_then_a_then_message() {
        // Independently re-derives H(R || A || M) via a differently-shaped
        // `hashv` call (three slices, matching the argument order in the RFC
        // 8032 challenge definition) so this test doesn't just echo
        // `compute_challenge`'s own call, and would catch R/A getting swapped
        // in a future refactor.
        let r = [0x11u8; 32];
        let a = [0x22u8; 32];
        let message = b"order check";

        let digest = solana_sha512_hasher::hashv(&[&r, &a, message]).to_bytes();
        let expected = scalar::reduce_wide(&digest);

        assert_eq!(compute_challenge(&r, &a, message), expected);
    }
}
