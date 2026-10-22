//! Public fixed-base tables; no secret scalars or trapdoor encodings are stored.
use super::{Image, ValidatedSetup};
use ark_bls12_381::{Fr, G1Projective as G1, G2Affine, G2Projective as G2};
use ark_ec::{
    scalar_mul::{glv::GLVConfig, BatchMulPreprocessing, ScalarMul},
    short_weierstrass::{Affine, Projective},
    AdditiveGroup, AffineRepr, CurveGroup,
};
use ark_ff::{BitIteratorBE, PrimeField};
use ark_std::Zero;
use std::marker::PhantomData;
use zeroize::Zeroize;

// Window widths are bounded to 3..=8. Scalars and their temporary digits are
// private during Contribute, so the digit buffer is erased on drop.
struct WindowDigits {
    values: [u8; 85],
    window: usize,
}
impl WindowDigits {
    fn new(s: &Fr, window: usize) -> Self {
        let mut bits = s.into_bigint();
        let mut values = [0; 85];
        let mask = (1u64 << window) - 1;
        for (outer, digit) in values
            .iter_mut()
            .take(255usize.div_ceil(window))
            .enumerate()
        {
            let bit = outer * window;
            let limb = bit / 64;
            let offset = bit % 64;
            let mut word = bits.0[limb] >> offset;
            if offset + window > 64 && limb + 1 < bits.0.len() {
                word |= bits.0[limb + 1] << (64 - offset);
            }
            *digit = (word & mask) as u8;
        }
        bits.zeroize();
        Self { values, window }
    }
}
impl Drop for WindowDigits {
    fn drop(&mut self) {
        self.values.zeroize();
    }
}

pub(crate) struct Fixed<G: ScalarMul<ScalarField = Fr>>(BatchMulPreprocessing<G>);
impl<G: ScalarMul<ScalarField = Fr>> Fixed<G> {
    pub fn new(base: G) -> Self {
        Self(BatchMulPreprocessing::new(base, 128))
    }
    pub fn for_uses(base: G, uses: usize) -> Self {
        // Public workload only. Cap the window at 8 to bound table memory;
        // small committees avoid paying for rarely used large tables.
        Self(BatchMulPreprocessing::new(base, uses.clamp(1, 4096)))
    }
    pub fn window_for_uses(uses: usize) -> usize {
        BatchMulPreprocessing::<G>::compute_window_size(uses.clamp(1, 4096))
    }
    pub fn mul(&self, s: &Fr) -> G {
        self.mul_digits(&WindowDigits::new(s, self.0.window))
    }
    fn mul_digits(&self, digits: &WindowDigits) -> G {
        debug_assert_eq!(digits.window, self.0.window);
        let mut result = G::zero();
        for (row, &digit) in self.0.table.iter().zip(&digits.values) {
            result += &row[digit as usize];
        }
        result
    }
}

/// Public Fiat-Shamir challenge multiplication on already validated points.
/// The library's GLV decomposition is shared across all coordinates of a group.
/// Every product is returned separately; no equations or bases are aggregated.
pub(crate) struct ChallengeMul<C: GLVConfig<ScalarField = Fr>> {
    positive: [bool; 2],
    digits: Vec<u8>,
    curve: PhantomData<C>,
}
impl<C: GLVConfig<ScalarField = Fr>> ChallengeMul<C> {
    pub fn new(c: Fr) -> Self {
        let ((a, k1), (b, k2)) = C::scalar_decomposition(c);
        let digits = BitIteratorBE::new(k1.into_bigint())
            .zip(BitIteratorBE::new(k2.into_bigint()))
            .map(|(a, b)| u8::from(a) | (u8::from(b) << 1))
            .skip_while(|&digit| digit == 0)
            .collect();
        Self {
            positive: [a, b],
            digits,
            curve: PhantomData,
        }
    }
    pub fn mul(&self, base: Affine<C>) -> Projective<C> {
        let a = if self.positive[0] { base } else { -base };
        let endo = C::endomorphism_affine(&base);
        let b = if self.positive[1] { endo } else { -endo };
        let both = a + b;
        let mut result = Projective::<C>::zero();
        for digit in &self.digits {
            result.double_in_place();
            match digit {
                1 => result += a,
                2 => result += b,
                3 => result += both,
                _ => (),
            }
        }
        result
    }
}
pub(crate) struct ProjectiveImage {
    pub g1: [G1; 2],
    pub g2: [G2; 6],
}
impl ProjectiveImage {
    pub fn normalize(images: &[Self]) -> Vec<Image> {
        let a = G1::normalize_batch(&images.iter().flat_map(|p| p.g1).collect::<Vec<_>>());
        let b = G2::normalize_batch(&images.iter().flat_map(|p| p.g2).collect::<Vec<_>>());
        (0..images.len())
            .map(|i| Image {
                g1: [a[2 * i], a[2 * i + 1]],
                g2: std::array::from_fn(|k| b[6 * i + k]),
            })
            .collect()
    }
}
pub(crate) struct ImageBases {
    c: Fixed<G1>,
    shift: Fixed<G1>,
    g: Fixed<G1>,
    q: Fixed<G2>,
    z: Fixed<G2>,
    tau: Fixed<G2>,
    minus: Fixed<G2>,
}
impl ImageBases {
    pub fn new(pp: &ValidatedSetup, uses: usize) -> Self {
        let d = pp.data();
        let c = &d.crs;
        let q = c.g2[0];
        Self {
            c: Fixed::for_uses(d.aggregate.into_group(), uses),
            shift: Fixed::for_uses(c.g1[pp.threshold() + 1].into_group(), uses),
            g: Fixed::for_uses(c.g1[0].into_group(), uses),
            q: Fixed::for_uses(q.into_group(), uses),
            z: Fixed::for_uses(c.g2[pp.slots()] - q, uses),
            tau: Fixed::for_uses(c.g2[1].into_group(), uses),
            minus: Fixed::for_uses(c.g2[1] - q, uses),
        }
    }
    pub fn image(&self, h: &Fixed<G2>, s: &[Fr; 5]) -> ProjectiveImage {
        let window = self.c.0.window;
        let digits = s.each_ref().map(|s| WindowDigits::new(s, window));
        let mut sum = s[0] + s[1];
        let sum_digits = WindowDigits::new(&sum, window);
        sum.zeroize();
        let h_digits = (h.0.window != window).then(|| WindowDigits::new(&s[2], h.0.window));
        let a = [
            self.c.mul_digits(&digits[0])
                + self.shift.mul_digits(&digits[3])
                + self.g.mul_digits(&digits[4]),
            self.g.mul_digits(&digits[2]),
        ];
        let b = [
            self.q.mul_digits(&digits[0]) + h.mul_digits(h_digits.as_ref().unwrap_or(&digits[2])),
            self.z.mul_digits(&digits[0]),
            self.tau.mul_digits(&sum_digits),
            self.q.mul_digits(&digits[1]),
            self.q.mul_digits(&digits[3]),
            self.minus.mul_digits(&digits[4]),
        ];
        ProjectiveImage { g1: a, g2: b }
    }
}
pub(crate) fn input_base(h: G2Affine, uses: usize) -> Fixed<G2> {
    Fixed::for_uses(h.into_group(), uses)
}
