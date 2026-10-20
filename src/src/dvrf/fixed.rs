//! Public fixed-base tables; no secret scalars or trapdoor encodings are stored.
use super::{Image, ValidatedSetup};
use ark_bls12_381::{Fr, G1Projective as G1, G2Affine, G2Projective as G2};
use ark_ec::{
    scalar_mul::{BatchMulPreprocessing, ScalarMul},
    AffineRepr, CurveGroup,
};
use ark_ff::{BigInteger, PrimeField};

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
    pub fn mul(&self, s: &Fr) -> G {
        let bits = s.into_bigint();
        let table = &self.0;
        let mut result = G::zero();
        for (outer, row) in table.table.iter().enumerate() {
            let mut inner = 0;
            for i in 0..table.window {
                let bit = outer * table.window + i;
                if bits.get_bit(bit) {
                    inner |= 1 << i;
                }
            }
            result += &row[inner];
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
        let a = [
            self.c.mul(&s[0]) + self.shift.mul(&s[3]) + self.g.mul(&s[4]),
            self.g.mul(&s[2]),
        ];
        let b = [
            self.q.mul(&s[0]) + h.mul(&s[2]),
            self.z.mul(&s[0]),
            self.tau.mul(&(s[0] + s[1])),
            self.q.mul(&s[1]),
            self.q.mul(&s[3]),
            self.minus.mul(&s[4]),
        ];
        ProjectiveImage { g1: a, g2: b }
    }
}
pub(crate) fn input_base(h: G2Affine, uses: usize) -> Fixed<G2> {
    Fixed::for_uses(h.into_group(), uses)
}
