use super::{Error, Result};
use ark_bls12_381::{g2, Fr, G2Affine, G2Projective};
use ark_ec::hashing::{
    curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve,
};
use ark_ec::AffineRepr;
use ark_ff::{field_hashers::DefaultFieldHasher, PrimeField};
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};

pub(crate) fn bytes<T: CanonicalSerialize>(v: &T) -> Vec<u8> {
    let mut b = Vec::with_capacity(v.compressed_size());
    v.serialize_compressed(&mut b)
        .expect("Vec writes do not fail");
    b
}
pub(crate) fn field(out: &mut Vec<u8>, name: &[u8], data: &[u8]) {
    out.extend_from_slice(&(name.len() as u64).to_le_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(data);
}
pub(crate) fn digest(domain: &[u8], data: &[u8]) -> [u8; 32] {
    let mut b = Vec::new();
    field(&mut b, b"domain", domain);
    field(&mut b, b"data", data);
    Sha256::digest(&b).into()
}
/// RFC-9380-style XMD:SHA-256, SSWU/isogeny and cofactor clearing. No known-log map.
pub(crate) fn hash_to_g2(message: &[u8], dst: &[u8]) -> Result<G2Affine> {
    type H =
        MapToCurveBasedHasher<G2Projective, DefaultFieldHasher<Sha256, 128>, WBMap<g2::Config>>;
    let hasher = H::new(dst).map_err(|_| Error("hash-to-curve initialization"))?;
    let point = hasher.hash(message).map_err(|_| Error("hash-to-curve"))?;
    if point.is_zero() {
        return Err(Error("identity hash-to-curve output"));
    }
    Ok(point)
}
pub(crate) fn append<T: CanonicalSerialize>(
    t: &mut merlin::Transcript,
    name: &'static [u8],
    v: &T,
) {
    t.append_message(name, &bytes(v));
}
pub(crate) fn challenge(t: &mut merlin::Transcript) -> Fr {
    let mut b = [0; 64];
    t.challenge_bytes(b"challenge", &mut b);
    Fr::from_le_bytes_mod_order(&b)
}
