//! Independent registrations, public polynomial hints and deterministic validation.
//! The cross-term identity avoids cubic coefficient-by-coefficient encodings:
//! J_ij=(omega^j L_i-omega^i L_j)/(N(omega^i-omega^j)), i != j.
use super::{
    algebra::{msm1, msm2},
    crs::Crs,
    encoding, Error, Result,
};
use ark_bls12_381::{Bls12_381 as E, Fr, G1Affine, G1Projective as G1, G2Affine};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup, PrimeGroup,
};
use ark_ff::{Field, One};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use ark_std::{UniformRand, Zero};
use rand::{CryptoRng, RngCore};
use std::sync::Arc;
use zeroize::Zeroize;

pub(crate) struct Bases {
    pub li1: Vec<G1Affine>,
    pub r1: Vec<G1Affine>,
    pub s1: Vec<G1Affine>,
    pub cross1: Vec<Vec<G1Affine>>,
    li2: Vec<G2Affine>,
    r2: Vec<G2Affine>,
    s2: Vec<G2Affine>,
    pub(crate) cross2: Vec<Vec<G2Affine>>,
}
#[derive(Clone)]
pub struct Parameters {
    pub(crate) target: PairingOutput<E>,
    pub(crate) crs: Crs,
    pub(crate) threshold: usize,
    pub(crate) domain: Radix2EvaluationDomain<Fr>,
    pub(crate) bases: Arc<Bases>,
    pub(crate) id: [u8; 32],
}
pub struct SecretKey {
    pub(crate) id: u32,
    pub(crate) scalar: Fr,
    pub(crate) x: G1Affine,
    pub(crate) parameters: [u8; 32],
}
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.scalar.zeroize();
    }
}
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Registration {
    pub id: u32,
    pub x: G1Affine,
    pub h1: G1Affine,
    pub h2: G1Affine,
    pub h4: G1Affine,
    pub cross: Vec<G1Affine>,
}
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SetupData {
    pub version: u32,
    pub threshold: u32,
    pub crs: Crs,
    pub registrations: Vec<Registration>,
    pub aggregate: G1Affine,
    pub cache: Vec<G1Affine>,
}
pub struct ValidatedSetup {
    pub(crate) parameters: Arc<Parameters>,
    pub(crate) public: SetupData,
    pub(crate) encoded: Vec<u8>,
    pub(crate) id: [u8; 32],
}
impl Parameters {
    pub fn new(crs: Crs, threshold: usize) -> Result<Self> {
        crs.validate()?;
        let n = crs.slots();
        if threshold == 0 || threshold >= n {
            return Err(Error("invalid threshold"));
        }
        let domain = Radix2EvaluationDomain::<Fr>::new(n).ok_or(Error("unsupported domain"))?;
        if domain.size() != n {
            return Err(Error("domain padding forbidden"));
        }
        let roots: Vec<_> = domain.elements().collect();
        let inv = Fr::from(n as u64).inverse().unwrap();
        let mut b = Bases {
            li1: Vec::new(),
            r1: Vec::new(),
            s1: Vec::new(),
            li2: Vec::new(),
            r2: Vec::new(),
            s2: Vec::new(),
            cross1: vec![vec![G1Affine::zero(); n]; n],
            cross2: vec![vec![G2Affine::zero(); n]; n],
        };
        for (i, root) in roots.iter().enumerate() {
            let mut coeff = Vec::with_capacity(n);
            let mut p = inv;
            let root_inv = root.inverse().unwrap();
            for _ in 0..n {
                coeff.push(p);
                p *= root_inv;
            }
            let l1 = msm1(&crs.g1[..n], &coeff).into_affine();
            let l2 = msm2(&crs.g2[..n], &coeff).into_affine();
            b.li1.push(l1);
            b.li2.push(l2);
            b.r1.push((l1 - crs.g1[0] * inv).into_affine());
            b.r2.push((l2 - crs.g2[0] * inv).into_affine());
            b.s1.push(msm1(&crs.g1[..n - 1], &coeff[1..]).into_affine());
            b.s2.push(msm2(&crs.g2[..n - 1], &coeff[1..]).into_affine());
            let mut diagonal = Vec::with_capacity(n - 1);
            let mut a = Fr::one();
            for d in 0..n - 1 {
                diagonal.push(Fr::from((n - 1 - d) as u64) * inv * inv * a);
                a *= root_inv;
            }
            b.cross1[i][i] = msm1(&crs.g1[..n - 1], &diagonal).into_affine();
            b.cross2[i][i] = msm2(&crs.g2[..n - 1], &diagonal).into_affine();
        }
        let fixed1: Vec<_> = b
            .li1
            .iter()
            .map(|g| super::fixed::Fixed::new(g.into_group()))
            .collect();
        let fixed2: Vec<_> = b
            .li2
            .iter()
            .map(|g| super::fixed::Fixed::new(g.into_group()))
            .collect();
        for i in 0..n {
            for j in i + 1..n {
                let c = inv * (roots[i] - roots[j]).inverse().unwrap();
                let s = [roots[j] * c, -roots[i] * c];
                let p = (fixed1[i].mul(&s[0]) + fixed1[j].mul(&s[1])).into_affine();
                let q = (fixed2[i].mul(&s[0]) + fixed2[j].mul(&s[1])).into_affine();
                b.cross1[i][j] = p;
                b.cross1[j][i] = p;
                b.cross2[i][j] = q;
                b.cross2[j][i] = q;
            }
        }
        let mut common = encoding::bytes(&crs);
        common.extend_from_slice(&(threshold as u64).to_le_bytes());
        let id = encoding::digest(b"SDVRF-PARAMETERS-v1", &common);
        Ok(Self {
            target: E::pairing(crs.g1[0], crs.g2[0]),
            crs,
            threshold,
            domain,
            bases: Arc::new(b),
            id,
        })
    }
    pub fn slots(&self) -> usize {
        self.crs.slots()
    }
    pub fn basis_bytes(&self) -> usize {
        let n = self.slots();
        (n * n + 3 * n) * (48 + 96)
    }
}
fn registration(p: &Parameters, id: usize, alpha: Fr) -> Registration {
    Registration {
        id: id as u32,
        x: (G1::generator() * alpha).into_affine(),
        h1: (p.bases.li1[id] * alpha).into_affine(),
        h2: (p.bases.r1[id] * alpha).into_affine(),
        h4: (p.bases.s1[id] * alpha).into_affine(),
        cross: p.bases.cross1[id]
            .iter()
            .map(|g| (*g * alpha).into_affine())
            .collect(),
    }
}
pub fn generate_key<R: RngCore + CryptoRng>(
    p: &Parameters,
    id: usize,
    rng: &mut R,
) -> Result<(SecretKey, Registration)> {
    if id == 0 || id >= p.slots() {
        return Err(Error("invalid real-party index"));
    }
    let alpha = loop {
        let a = Fr::rand(rng);
        if !a.is_zero() {
            break a;
        }
    };
    let reg = registration(p, id, alpha);
    Ok((
        SecretKey {
            id: id as u32,
            scalar: alpha,
            x: reg.x,
            parameters: p.id,
        },
        reg,
    ))
}
fn verify_registration(p: &Parameters, r: &Registration) -> bool {
    let i = r.id as usize;
    if i == 0 || i >= p.slots() || r.cross.len() != p.slots() || r.x.is_zero() || r.check().is_err()
    {
        return false;
    }
    let minus_x = (-r.x.into_group()).into_affine();
    let q = p.crs.g2[0];
    let check =
        |hint: G1Affine, base: G2Affine| E::multi_pairing([hint, minus_x], [q, base]).is_zero();
    check(r.h1, p.bases.li2[i])
        && check(r.h2, p.bases.r2[i])
        && check(r.h4, p.bases.s2[i])
        && r.cross
            .iter()
            .zip(&p.bases.cross2[i])
            .all(|(a, b)| check(*a, *b))
}
pub fn finalize_setup(
    p: Parameters,
    mut registrations: Vec<Registration>,
) -> Result<ValidatedSetup> {
    let n = p.slots();
    if registrations.len() != n - 1 {
        return Err(Error("exact registry required"));
    }
    registrations.sort_by_key(|r| r.id);
    for (i, r) in registrations.iter().enumerate() {
        if r.id as usize != i + 1 || !verify_registration(&p, r) {
            return Err(Error("registration validation failed"));
        }
    }
    registrations.insert(0, registration(&p, 0, Fr::one()));
    let aggregate = registrations
        .iter()
        .fold(G1::zero(), |a, r| a + r.h1)
        .into_affine();
    let cache = (0..n)
        .map(|i| {
            registrations
                .iter()
                .fold(G1::zero(), |a, r| a + r.cross[i])
                .into_affine()
        })
        .collect();
    let public = SetupData {
        version: 1,
        threshold: p.threshold as u32,
        crs: p.crs.clone(),
        registrations,
        aggregate,
        cache,
    };
    let encoded = encoding::bytes(&public);
    let id = encoding::digest(b"SDVRF-SETUP-v1", &encoded);
    Ok(ValidatedSetup {
        parameters: Arc::new(p),
        public,
        encoded,
        id,
    })
}
pub fn validate_setup(data: SetupData) -> Result<ValidatedSetup> {
    if data.version != 1 {
        return Err(Error("unsupported setup version"));
    }
    let p = Parameters::new(data.crs.clone(), data.threshold as usize)?;
    if data.registrations.len() != p.slots() {
        return Err(Error("invalid registry length"));
    }
    let checked = finalize_setup(p, data.registrations[1..].to_vec())?;
    if checked.public != data {
        return Err(Error("invalid auxiliary key or cache"));
    }
    Ok(checked)
}
impl ValidatedSetup {
    /// A new Setup instance with the same validated CRS and registrations.
    /// The new threshold changes PP, its identifier, and every input context.
    /// Hint equations and auxiliary data are independent of the threshold.
    pub fn with_threshold(&self, threshold: usize) -> Result<Self> {
        if threshold == 0 || threshold >= self.slots() {
            return Err(Error("invalid threshold"));
        }
        let mut parameters = (*self.parameters).clone();
        parameters.threshold = threshold;
        let mut common = encoding::bytes(&parameters.crs);
        common.extend_from_slice(&(threshold as u64).to_le_bytes());
        parameters.id = encoding::digest(b"SDVRF-PARAMETERS-v1", &common);
        let mut public = self.public.clone();
        public.threshold = threshold as u32;
        let encoded = encoding::bytes(&public);
        let id = encoding::digest(b"SDVRF-SETUP-v1", &encoded);
        Ok(Self {
            parameters: Arc::new(parameters),
            public,
            encoded,
            id,
        })
    }
    pub fn data(&self) -> &SetupData {
        &self.public
    }
    pub fn slots(&self) -> usize {
        self.parameters.slots()
    }
    pub fn parties(&self) -> usize {
        self.slots() - 1
    }
    pub fn threshold(&self) -> usize {
        self.parameters.threshold
    }
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }
    pub fn id(&self) -> [u8; 32] {
        self.id
    }
    pub fn basis_bytes(&self) -> usize {
        self.parameters.basis_bytes()
    }
    pub(crate) fn commit1(&self, c: &[Fr]) -> Result<G1Affine> {
        if c.len() > self.slots() + 1 {
            return Err(Error("polynomial exceeds CRS degree"));
        }
        Ok(msm1(&self.public.crs.g1[..c.len()], c).into_affine())
    }
    pub(crate) fn commit2(&self, c: &[Fr]) -> Result<G2Affine> {
        if c.len() > self.slots() + 1 {
            return Err(Error("polynomial exceeds CRS degree"));
        }
        Ok(msm2(&self.public.crs.g2[..c.len()], c).into_affine())
    }
}

impl SecretKey {
    /// Re-register this private key for an already validated matching public key.
    pub fn for_setup(&self, pp: &ValidatedSetup) -> Result<Self> {
        if self.id == 0
            || self.id as usize >= pp.slots()
            || pp.data().registrations[self.id as usize].x != self.x
        {
            return Err(Error("secret key not registered"));
        }
        Ok(Self {
            id: self.id,
            scalar: self.scalar,
            x: self.x,
            parameters: pp.parameters.id,
        })
    }
}
