use super::{
    algebra::{msm1, msm2, project, relation},
    encoding, Error, Result, SecretKey, ValidatedRecord, Witness,
};
use ark_bls12_381::{Bls12_381 as E, Fr, G2Affine};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup,
};
use ark_ff::{Field, One};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use ark_std::Zero;
use sha2::Digest;

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Share {
    pub id: u32,
    pub tag: [u8; 32],
    pub value: G2Affine,
}
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Evaluation {
    pub tag: [u8; 32],
    pub output: [u8; 32],
    pub proof: Witness,
}
pub fn partial_eval(record: &ValidatedRecord, input: usize, key: &SecretKey) -> Result<Share> {
    let context = record.input(input)?;
    let pp = record.setup();
    let id = key.id as usize;
    if id == 0
        || id >= pp.slots()
        || key.parameters != pp.parameters.id
        || key.x != pp.data().registrations[id].x
    {
        return Err(Error("secret key not registered"));
    }
    Ok(Share {
        id: key.id,
        tag: context.tag,
        value: (context.h * key.scalar).into_affine(),
    })
}
pub fn partial_verify(record: &ValidatedRecord, input: usize, share: &Share) -> bool {
    let Ok(context) = record.input(input) else {
        return false;
    };
    let pp = record.setup();
    let id = share.id as usize;
    if id == 0 || id >= pp.slots() || share.tag != context.tag || share.value.check().is_err() {
        return false;
    }
    E::multi_pairing(
        [
            pp.data().registrations[id].x,
            (-pp.data().crs.g1[0].into_group()).into_affine(),
        ],
        [context.h, share.value],
    )
    .is_zero()
}
fn output(record: &ValidatedRecord, index: usize, y: &PairingOutput<E>) -> Result<[u8; 32]> {
    let mut t = record.input(index)?.output_prefix.clone();
    let mut encoded = Vec::new();
    encoding::field(&mut encoded, b"target", &encoding::bytes(y));
    t.update(encoded);
    Ok(t.finalize().into())
}
pub fn combine(record: &ValidatedRecord, input: usize, shares: &[Share]) -> Result<Evaluation> {
    let context = record.input(input)?;
    let pp = record.setup();
    let n = pp.slots();
    let threshold = pp.threshold();
    if shares.len() != threshold {
        return Err(Error("exactly T shares required"));
    }
    let mut selected = vec![false; n];
    for s in shares {
        let i = s.id as usize;
        if i == 0 || i >= n || selected[i] || !partial_verify(record, input, s) {
            return Err(Error("invalid or duplicate share"));
        }
        selected[i] = true;
    }
    let domain = &pp.parameters.domain;
    let roots: Vec<_> = domain.elements().collect();
    let mut b = DensePolynomial::from_coefficients_vec(vec![Fr::one()]);
    for i in 1..n {
        if !selected[i] {
            b = b.naive_mul(&DensePolynomial::from_coefficients_vec(vec![
                -roots[i],
                Fr::one(),
            ]));
        }
    }
    let normalization = b
        .evaluate(&Fr::one())
        .inverse()
        .ok_or(Error("invalid selector"))?;
    for c in &mut b.coeffs {
        *c *= normalization;
    }
    let beta = domain.fft(&b.coeffs);
    let inv = Fr::from(n as u64).inverse().unwrap();
    let mut indices = Vec::with_capacity(threshold + 1);
    indices.push(0);
    indices.extend(shares.iter().map(|s| s.id as usize));
    let weights: Vec<_> = indices.iter().map(|i| beta[*i]).collect();
    let registrations = &pp.data().registrations;
    let xs: Vec<_> = indices.iter().map(|i| registrations[*i].x).collect();
    let mut sigmas = vec![context.h];
    sigmas.extend(shares.iter().map(|s| s.value));
    let p = msm1(&xs, &weights) * inv;
    let sigma = msm2(&sigmas, &weights) * inv;
    let qz = msm1(
        &indices
            .iter()
            .map(|i| pp.data().cache[*i])
            .collect::<Vec<_>>(),
        &weights,
    );
    let qx = msm1(
        &indices
            .iter()
            .map(|i| registrations[*i].h4)
            .collect::<Vec<_>>(),
        &weights,
    );
    let qhat = msm1(
        &indices
            .iter()
            .map(|i| registrations[*i].h2)
            .collect::<Vec<_>>(),
        &weights,
    );
    let mut numerator = b.clone();
    numerator.coeffs[0] -= Fr::one();
    let divisor = DensePolynomial::from_coefficients_vec(vec![-Fr::one(), Fr::one()]);
    let q0 = &numerator / &divisor;
    if !(&(&q0 * &divisor) - &numerator).is_zero() {
        return Err(Error("inexact normalization quotient"));
    }
    let mut shifted = vec![Fr::zero(); threshold + 1];
    shifted.extend_from_slice(&b.coeffs);
    let proof = Witness {
        g1: [
            (-p).into_affine(),
            (-qz).into_affine(),
            (-qx).into_affine(),
            qhat.into_affine(),
            (-pp.commit1(&shifted)?.into_group()).into_affine(),
            (-pp.commit1(&q0.coeffs)?.into_group()).into_affine(),
        ],
        g2: [pp.commit2(&b.coeffs)?, sigma.into_affine()],
    };
    let y = project(&record.data().images[input], &proof);
    Ok(Evaluation {
        tag: context.tag,
        output: output(record, input, &y)?,
        proof,
    })
}
pub fn verify(record: &ValidatedRecord, input: usize, evaluation: &Evaluation) -> bool {
    let Ok(context) = record.input(input) else {
        return false;
    };
    if context.tag != evaluation.tag || !relation(record.setup(), context.h, &evaluation.proof) {
        return false;
    }
    output(
        record,
        input,
        &project(&record.data().images[input], &evaluation.proof),
    )
    .is_ok_and(|y| y == evaluation.output)
}
