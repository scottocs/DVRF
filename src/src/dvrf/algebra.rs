use super::{encoding, setup::ValidatedSetup};
use ark_bls12_381::{
    Bls12_381 as E, Fr, G1Affine, G1Projective as G1, G2Affine, G2Projective as G2,
};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup, VariableBaseMSM,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use ark_std::Zero;

/// Matrix/image columns 1,6 in G1; columns 2,3,4,5,7,8 in G2.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Image {
    pub g1: [G1Affine; 2],
    pub g2: [G2Affine; 6],
}
impl Image {
    pub(crate) fn zero() -> Self {
        Self {
            g1: [G1Affine::zero(); 2],
            g2: [G2Affine::zero(); 6],
        }
    }
    pub(crate) fn add(&mut self, other: &Self) {
        for (i, p) in self.g1.iter_mut().enumerate() {
            *p = (*p + other.g1[i]).into_affine();
        }
        for (i, p) in self.g2.iter_mut().enumerate() {
            *p = (*p + other.g2[i]).into_affine();
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ImageProof {
    pub commitment: Image,
    pub responses: [Fr; 5],
}
/// G1 coordinates w2,w3,w4,w5,w7,w8; G2 coordinates w1,w6.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Witness {
    pub g1: [G1Affine; 6],
    pub g2: [G2Affine; 2],
}

pub(crate) fn msm1(b: &[G1Affine], s: &[Fr]) -> G1 {
    G1::msm_unchecked(b, s)
}
pub(crate) fn msm2(b: &[G2Affine], s: &[Fr]) -> G2 {
    G2::msm_unchecked(b, s)
}
pub(crate) fn image(pp: &ValidatedSetup, h: G2Affine, s: &[Fr; 5]) -> Image {
    let data = pp.data();
    let crs = &data.crs;
    let g = crs.g1[0];
    let q = crs.g2[0];
    Image {
        g1: [
            msm1(
                &[data.aggregate, crs.g1[data.threshold as usize + 1], g],
                &[s[0], s[3], s[4]],
            )
            .into_affine(),
            (g * s[2]).into_affine(),
        ],
        g2: [
            msm2(&[q, h], &[s[0], s[2]]).into_affine(),
            ((crs.g2[pp.slots()] - q) * s[0]).into_affine(),
            (crs.g2[1] * (s[0] + s[1])).into_affine(),
            (q * s[1]).into_affine(),
            (q * s[3]).into_affine(),
            ((crs.g2[1] - q) * s[4]).into_affine(),
        ],
    }
}
pub(crate) fn image_challenge(context: &merlin::Transcript, id: u32, f: &Image, m: &Image) -> Fr {
    let mut t = context.clone();
    encoding::append(&mut t, b"member", &id);
    encoding::append(&mut t, b"image", f);
    encoding::append(&mut t, b"commitment", m);
    encoding::challenge(&mut t)
}
pub(crate) fn verify_image(
    pp: &ValidatedSetup,
    h: G2Affine,
    context: &merlin::Transcript,
    id: u32,
    f: &Image,
    p: &ImageProof,
) -> bool {
    let c = image_challenge(context, id, f, &p.commitment);
    let lhs = image(pp, h, &p.responses);
    (0..2).all(|i| lhs.g1[i] == (p.commitment.g1[i] + f.g1[i] * c).into_affine())
        && (0..6).all(|i| lhs.g2[i] == (p.commitment.g2[i] + f.g2[i] * c).into_affine())
}
pub(crate) fn project(image: &Image, w: &Witness) -> PairingOutput<E> {
    E::multi_pairing(
        [
            image.g1[0],
            w.g1[0],
            w.g1[1],
            w.g1[2],
            w.g1[3],
            image.g1[1],
            w.g1[4],
            w.g1[5],
        ],
        [
            w.g2[0],
            image.g2[0],
            image.g2[1],
            image.g2[2],
            image.g2[3],
            w.g2[1],
            image.g2[4],
            image.g2[5],
        ],
    )
}
pub(crate) fn relation(pp: &ValidatedSetup, h: G2Affine, w: &Witness) -> bool {
    if w.check().is_err() {
        return false;
    }
    let d = pp.data();
    let crs = &d.crs;
    let g = crs.g1[0];
    let q = crs.g2[0];
    // Separate row checks are essential: multiplying rows permits cancellation.
    E::multi_pairing(
        [d.aggregate, w.g1[0], w.g1[1], w.g1[2]],
        [
            w.g2[0],
            q,
            (crs.g2[pp.slots()] - q).into_affine(),
            crs.g2[1],
        ],
    )
    .is_zero()
        && E::multi_pairing([w.g1[2], w.g1[3]], [crs.g2[1], q]).is_zero()
        && E::multi_pairing([w.g1[0], g], [h, w.g2[1]]).is_zero()
        && E::multi_pairing([crs.g1[d.threshold as usize + 1], w.g1[4]], [w.g2[0], q]).is_zero()
        && E::multi_pairing([g, w.g1[5]], [w.g2[0], (crs.g2[1] - q).into_affine()])
            == pp.parameters.target
}
