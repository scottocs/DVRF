//! The scheduled DVRF in paper/DVRF.tex, using BLS12-381 and arkworks 0.5.
//!
//! PairingOutput uses additive notation: addition is multiplication in G_T.
//! Authenticated, consistent board delivery and honest erasure remain external
//! assumptions. Validated setup/record handles cannot be deserialized unchecked.
mod algebra;
#[cfg(test)]
mod basis_tests;
pub mod crs;
mod encoding;
mod evaluation;
mod fixed;
mod parallel;
mod preprocess;
mod setup;

pub use algebra::{Image, ImageProof, Witness};
pub use evaluation::{combine, partial_eval, partial_verify, verify, Evaluation, Share};
pub use preprocess::{
    contribute, finalize_record, validate_record, Bundle, CommitteeKey, CommitteePublic,
    Contribution, Header, PreparedBatch, RecordData, Schedule, ValidatedRecord,
};
pub use setup::{
    finalize_setup, generate_key, validate_setup, Parameters, Registration, SecretKey, SetupData,
    ValidatedSetup,
};

use std::fmt;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub &'static str);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Error {}
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Canonical, compressed encoding. Group membership is checked on decoding.
pub fn encode<T: ark_serialize::CanonicalSerialize>(value: &T) -> Vec<u8> {
    encoding::bytes(value)
}
pub fn decode<T: ark_serialize::CanonicalDeserialize>(bytes: &[u8]) -> Result<T> {
    let mut reader = bytes;
    let value = T::deserialize_compressed(&mut reader).map_err(|_| Error("invalid encoding"))?;
    if !reader.is_empty() {
        return Err(Error("trailing bytes"));
    }
    Ok(value)
}
