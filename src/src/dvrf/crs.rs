//! Public, degree-capped powers of tau and a local update/audit model adapted
//! from the supplied STE ceremony. This is not a network implementation of NRBB24.
use super::{encoding, Error, Result};
use ark_bls12_381::{
    Bls12_381 as E, Fr, G1Affine, G1Projective as G1, G2Affine, G2Projective as G2,
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::One;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use ark_std::{UniformRand, Zero};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Crs {
    pub g1: Vec<G1Affine>,
    pub g2: Vec<G2Affine>,
}
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Update {
    pub crs: Crs,
    pub beta_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub commitment: G1Affine,
    pub response: Fr,
}
impl Crs {
    /// The all-ones starting transcript is deliberately not a usable final CRS.
    pub fn initial(slots: usize) -> Result<Self> {
        if slots < 2 || !slots.is_power_of_two() {
            return Err(Error("exact radix-2 domain required"));
        }
        Ok(Self {
            g1: vec![G1::generator().into_affine(); slots + 1],
            g2: vec![G2::generator().into_affine(); slots + 1],
        })
    }
    pub fn slots(&self) -> usize {
        self.g1.len().saturating_sub(1)
    }
    pub fn validate(&self) -> Result<()> {
        let n = self.slots();
        if n < 2 || !n.is_power_of_two() || self.g2.len() != n + 1 {
            return Err(Error("invalid CRS degree cap"));
        }
        if self.check().is_err()
            || self.g1[0] != G1::generator().into_affine()
            || self.g2[0] != G2::generator().into_affine()
            || self.g1[1].is_zero()
            || self.g2[1].is_zero()
            || self.g2[n] == self.g2[0]
        {
            return Err(Error("invalid CRS generators or trapdoor domain"));
        }
        for i in 1..=n {
            if E::pairing(self.g1[i], self.g2[0]) != E::pairing(self.g1[0], self.g2[i])
                || E::pairing(self.g1[i - 1], self.g2[1]) != E::pairing(self.g1[i], self.g2[0])
            {
                return Err(Error("inconsistent CRS powers"));
            }
        }
        Ok(())
    }
}
fn transcript(old: &Crs, u: &Update) -> merlin::Transcript {
    let mut t = merlin::Transcript::new(b"SDVRF-CRS-UPDATE-v1");
    encoding::append(&mut t, b"old", old);
    encoding::append(&mut t, b"new", &u.crs);
    encoding::append(&mut t, b"beta-g1", &u.beta_g1);
    encoding::append(&mut t, b"beta-g2", &u.beta_g2);
    encoding::append(&mut t, b"commitment", &u.commitment);
    t
}
/// Fresh independent update coins are zeroized before this function returns.
pub fn contribute<R: RngCore + CryptoRng>(old: &Crs, rng: &mut R) -> Result<Update> {
    let n = old.slots();
    if n < 2 || !n.is_power_of_two() || old.g2.len() != n + 1 || old.check().is_err() {
        return Err(Error("invalid previous CRS"));
    }
    loop {
        let mut beta = Fr::rand(rng);
        if beta.is_zero() {
            continue;
        }
        let mut power = Fr::one();
        let mut crs = Crs {
            g1: Vec::with_capacity(n + 1),
            g2: Vec::with_capacity(n + 1),
        };
        for i in 0..=n {
            crs.g1.push((old.g1[i] * power).into_affine());
            crs.g2.push((old.g2[i] * power).into_affine());
            power *= beta;
        }
        power.zeroize();
        if crs.g2[n] == crs.g2[0] {
            beta.zeroize();
            continue;
        }
        let mut nonce = Fr::rand(rng);
        let mut u = Update {
            crs,
            beta_g1: (G1::generator() * beta).into_affine(),
            beta_g2: (G2::generator() * beta).into_affine(),
            commitment: (G1::generator() * nonce).into_affine(),
            response: Fr::zero(),
        };
        u.response = nonce + encoding::challenge(&mut transcript(old, &u)) * beta;
        beta.zeroize();
        nonce.zeroize();
        return Ok(u);
    }
}
pub fn verify_update(old: &Crs, u: &Update) -> Result<()> {
    u.crs.validate()?;
    if old.slots() != u.crs.slots()
        || old.g2.len() != u.crs.g2.len()
        || u.check().is_err()
        || u.beta_g1.is_zero()
        || u.beta_g2.is_zero()
    {
        return Err(Error("invalid update"));
    }
    let c = encoding::challenge(&mut transcript(old, u));
    if G1::generator() * u.response != u.commitment + u.beta_g1 * c
        || E::pairing(u.beta_g1, old.g2[0]) != E::pairing(old.g1[0], u.beta_g2)
        || E::pairing(u.crs.g1[1], old.g2[0]) != E::pairing(old.g1[1], u.beta_g2)
    {
        return Err(Error("CRS update proof failed"));
    }
    Ok(())
}
/// Local experiment helper: retains public updates, never aggregate trapdoor scalars.
pub fn local_ceremony<R: RngCore + CryptoRng>(
    slots: usize,
    count: usize,
    rng: &mut R,
) -> Result<(Crs, Vec<Update>)> {
    if count == 0 {
        return Err(Error("at least one retained update required"));
    }
    let mut current = Crs::initial(slots)?;
    let mut updates = Vec::with_capacity(count);
    for _ in 0..count {
        let u = contribute(&current, rng)?;
        verify_update(&current, &u)?;
        current = u.crs.clone();
        updates.push(u);
    }
    Ok((current, updates))
}
