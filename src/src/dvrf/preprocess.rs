//! Certified randomized images, authenticated bundles and first-complete selection.
use super::{
    algebra, encoding, fixed::ProjectiveImage, parallel, Error, Image, ImageProof, Result,
    ValidatedSetup,
};
use ark_bls12_381::{Bls12_381 as E, Fr, G1Affine, G1Projective as G1, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use ark_std::{UniformRand, Zero};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, sync::Arc};
use zeroize::Zeroize;

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct CommitteePublic {
    pub id: u32,
    pub key: G1Affine,
}
pub struct CommitteeKey {
    id: u32,
    scalar: Fr,
    public: CommitteePublic,
}
impl Drop for CommitteeKey {
    fn drop(&mut self) {
        self.scalar.zeroize();
    }
}
impl CommitteeKey {
    pub fn generate<R: RngCore + CryptoRng>(id: u32, rng: &mut R) -> Result<Self> {
        if id == 0 {
            return Err(Error("invalid committee identity"));
        }
        let scalar = loop {
            let s = Fr::rand(rng);
            if !s.is_zero() {
                break s;
            }
        };
        let public = CommitteePublic {
            id,
            key: (G1::generator() * scalar).into_affine(),
        };
        Ok(Self { id, scalar, public })
    }
    pub fn public(&self) -> CommitteePublic {
        self.public.clone()
    }
    /// Authentication does not certify that the signed image proofs are valid.
    pub fn authenticate(
        &self,
        pp: &ValidatedSetup,
        schedule: &Schedule,
        bundle: &mut Bundle,
    ) -> Result<()> {
        if bundle.member != self.id || !schedule.header.committee.contains(&self.public) {
            return Err(Error("authentication identity mismatch"));
        }
        let h = encoding::hash_to_g2(
            &auth_message(pp, schedule, bundle),
            b"SDVRF_AUTH_BLS12381G2_XMD:SHA-256_SSWU_RO_V1",
        )?;
        bundle.signature = (h * self.scalar).into_affine();
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Header {
    pub application: Vec<u8>,
    pub release_policy: Vec<u8>,
    pub deadline: u64,
    pub committee: Vec<CommitteePublic>,
}
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Schedule {
    pub header: Header,
    pub labels: Vec<Vec<u8>>,
}
impl Schedule {
    pub fn validate(&self) -> Result<()> {
        if self.header.application.is_empty()
            || self.labels.is_empty()
            || self.header.committee.is_empty()
        {
            return Err(Error("empty schedule or committee"));
        }
        let mut labels = HashSet::new();
        for x in &self.labels {
            if !labels.insert(x) {
                return Err(Error("duplicate scheduled label"));
            }
        }
        let mut ids = HashSet::new();
        for c in &self.header.committee {
            if c.id == 0 || c.key.is_zero() || c.check().is_err() || !ids.insert(c.id) {
                return Err(Error("invalid committee registration"));
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Contribution {
    pub image: Image,
    pub proof: ImageProof,
}
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Bundle {
    pub member: u32,
    pub entries: Vec<Contribution>,
    pub signature: G2Affine,
}
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RecordData {
    pub setup_id: [u8; 32],
    pub schedule: Schedule,
    pub board: Vec<Bundle>,
    pub images: Vec<Image>,
}
pub(crate) struct InputContext {
    pub tag: [u8; 32],
    pub h: G2Affine,
    pub transcript: merlin::Transcript,
    pub output_prefix: Sha256,
}
pub struct ValidatedRecord {
    pub(crate) setup: Arc<ValidatedSetup>,
    pub(crate) public: RecordData,
    pub(crate) inputs: Vec<InputContext>,
    pub(crate) included: Vec<u32>,
}
fn contexts(pp: &ValidatedSetup, s: &Schedule) -> Result<Vec<InputContext>> {
    contexts_parallel(pp, s, 1)
}
fn contexts_parallel(
    pp: &ValidatedSetup,
    s: &Schedule,
    workers: usize,
) -> Result<Vec<InputContext>> {
    s.validate()?;
    let mut prefix = Vec::new();
    encoding::field(&mut prefix, b"profile", b"SDVRF-BLS12381-v1");
    encoding::field(&mut prefix, b"setup", pp.encoded());
    encoding::field(&mut prefix, b"schedule", &encoding::bytes(s));
    parallel::map(&s.labels, workers, |_, x| {
        let mut eta = prefix.clone();
        encoding::field(&mut eta, b"label", x);
        let tag = encoding::digest(b"SDVRF-INPUT-ID-v1", &eta);
        let h = encoding::hash_to_g2(&eta, b"SDVRF_GRP_BLS12381G2_XMD:SHA-256_SSWU_RO_V1")?;
        let mut transcript = merlin::Transcript::new(b"SDVRF-IMAGE-FS-v1");
        transcript.append_message(b"eta", &eta);
        let mut output_context = Vec::new();
        encoding::field(&mut output_context, b"domain", b"SDVRF-OUTPUT-v1");
        encoding::field(&mut output_context, b"eta", &eta);
        let mut output_prefix = Sha256::new();
        output_prefix.update(output_context);
        Ok(InputContext {
            tag,
            h,
            transcript,
            output_prefix,
        })
    })
    .into_iter()
    .collect()
}
fn auth_message(pp: &ValidatedSetup, s: &Schedule, b: &Bundle) -> Vec<u8> {
    let mut message = Vec::new();
    encoding::field(&mut message, b"setup", pp.encoded());
    encoding::field(&mut message, b"schedule", &encoding::bytes(s));
    encoding::field(&mut message, b"member", &b.member.to_le_bytes());
    encoding::field(&mut message, b"entries", &encoding::bytes(&b.entries));
    message
}
pub fn contribute<R: RngCore + CryptoRng>(
    pp: &ValidatedSetup,
    schedule: &Schedule,
    key: &CommitteeKey,
    rng: &mut R,
) -> Result<Bundle> {
    if !schedule.header.committee.contains(&key.public) {
        return Err(Error("undesignated contributor"));
    }
    let inputs = contexts(pp, schedule)?;
    let mut entries = Vec::with_capacity(inputs.len());
    for input in &inputs {
        let mut s = std::array::from_fn(|_| Fr::rand(rng));
        let mut nonce = std::array::from_fn(|_| Fr::rand(rng));
        let image = algebra::image(pp, input.h, &s);
        let commitment = algebra::image(pp, input.h, &nonce);
        let c = algebra::image_challenge(&input.transcript, key.id, &image, &commitment);
        let responses = std::array::from_fn(|i| nonce[i] + c * s[i]);
        s.zeroize();
        nonce.zeroize();
        entries.push(Contribution {
            image,
            proof: ImageProof {
                commitment,
                responses,
            },
        });
    }
    let mut bundle = Bundle {
        member: key.id,
        entries,
        signature: G2Affine::zero(),
    };
    key.authenticate(pp, schedule, &mut bundle)?;
    Ok(bundle)
}
fn construct(
    setup: Arc<ValidatedSetup>,
    schedule: Schedule,
    board: Vec<Bundle>,
) -> Result<ValidatedRecord> {
    let inputs = contexts(&setup, &schedule)?;
    let mut images = vec![Image::zero(); inputs.len()];
    let mut seen = HashSet::new();
    let mut included = Vec::new();
    for b in &board {
        if b.check().is_err() {
            return Err(Error("malformed board group element"));
        }
        let Some(member) = schedule.header.committee.iter().find(|m| m.id == b.member) else {
            continue;
        };
        let h = encoding::hash_to_g2(
            &auth_message(&setup, &schedule, b),
            b"SDVRF_AUTH_BLS12381G2_XMD:SHA-256_SSWU_RO_V1",
        )?;
        if E::pairing(member.key, h) != E::pairing(G1::generator(), b.signature) {
            continue;
        }
        // Unauthenticated entries cannot suppress a member's genuine submission.
        if b.entries.len() != inputs.len() || !seen.insert(b.member) {
            continue;
        }
        let valid = b.entries.iter().zip(&inputs).all(|(f, input)| {
            algebra::verify_image(
                &setup,
                input.h,
                &input.transcript,
                b.member,
                &f.image,
                &f.proof,
            )
        });
        if valid {
            included.push(b.member);
            for (i, c) in b.entries.iter().enumerate() {
                images[i].add(&c.image);
            }
        }
    }
    if included.is_empty() {
        return Err(Error("no accepted complete contribution"));
    }
    let public = RecordData {
        setup_id: setup.id(),
        schedule,
        board,
        images,
    };
    Ok(ValidatedRecord {
        setup,
        public,
        inputs,
        included,
    })
}
pub fn finalize_record(
    setup: Arc<ValidatedSetup>,
    schedule: Schedule,
    board: Vec<Bundle>,
) -> Result<ValidatedRecord> {
    construct(setup, schedule, board)
}
pub fn validate_record(setup: Arc<ValidatedSetup>, data: RecordData) -> Result<ValidatedRecord> {
    if data.setup_id != setup.id() {
        return Err(Error("record/setup mismatch"));
    }
    let record = construct(setup, data.schedule.clone(), data.board.clone())?;
    if record.public != data {
        return Err(Error("record differs from canonical board recomputation"));
    }
    Ok(record)
}
impl ValidatedRecord {
    pub fn data(&self) -> &RecordData {
        &self.public
    }
    pub fn setup(&self) -> &ValidatedSetup {
        &self.setup
    }
    pub fn included(&self) -> &[u32] {
        &self.included
    }
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }
    pub fn input_tag(&self, index: usize) -> Result<[u8; 32]> {
        Ok(self.input(index)?.tag)
    }
    pub fn hash_point(&self, index: usize) -> Result<G2Affine> {
        Ok(self.input(index)?.h)
    }
    pub(crate) fn input(&self, index: usize) -> Result<&InputContext> {
        self.inputs.get(index).ok_or(Error("unscheduled input"))
    }
}

/// Immutable public data for one (PP,D). Fixed-base tables can be shared by
/// contributors: they contain only public point multiples, never image coins.
pub struct PreparedBatch {
    setup: Arc<ValidatedSetup>,
    schedule: Schedule,
    inputs: Vec<InputContext>,
    bases: super::fixed::ImageBases,
    hashes: Vec<super::fixed::Fixed<ark_bls12_381::G2Projective>>,
}
// Limit the number of unnormalized points and live proof coins per task.
const IMAGE_CHUNK: usize = 16;
struct ProofCoins {
    s: [Fr; 5],
    nonce: [Fr; 5],
}
impl Drop for ProofCoins {
    fn drop(&mut self) {
        self.s.zeroize();
        self.nonce.zeroize();
    }
}
impl PreparedBatch {
    pub fn new(setup: Arc<ValidatedSetup>, schedule: Schedule) -> Result<Self> {
        Self::new_with_workers(setup, schedule, 1)
    }
    pub fn new_with_workers(
        setup: Arc<ValidatedSetup>,
        schedule: Schedule,
        workers: usize,
    ) -> Result<Self> {
        if workers == 0 {
            return Err(Error("at least one preparation worker required"));
        }
        let inputs = contexts_parallel(&setup, &schedule, workers)?;
        let input_uses = schedule.header.committee.len().saturating_mul(3);
        let bases = super::fixed::ImageBases::new(&setup, input_uses.saturating_mul(inputs.len()));
        let hashes = parallel::map(&inputs, workers, |_, i| {
            super::fixed::input_base(i.h, input_uses)
        });
        Ok(Self {
            setup,
            schedule,
            inputs,
            bases,
            hashes,
        })
    }
    pub fn contribute<R: RngCore + CryptoRng>(
        &self,
        key: &CommitteeKey,
        rng: &mut R,
    ) -> Result<Bundle> {
        self.contribute_parallel(key, rng, 1)
    }
    /// The RNG is consumed in input order before workers start, so proof
    /// bytes are independent of scheduling and worker count.
    pub fn contribute_parallel<R: RngCore + CryptoRng>(
        &self,
        key: &CommitteeKey,
        rng: &mut R,
        workers: usize,
    ) -> Result<Bundle> {
        if workers == 0 {
            return Err(Error("at least one contribution worker required"));
        }
        if !self.schedule.header.committee.contains(&key.public) {
            return Err(Error("undesignated contributor"));
        }
        let coins: Vec<_> = self
            .inputs
            .iter()
            .map(|_| ProofCoins {
                s: std::array::from_fn(|_| Fr::rand(rng)),
                nonce: std::array::from_fn(|_| Fr::rand(rng)),
            })
            .collect();
        let chunks: Vec<_> = coins.chunks(IMAGE_CHUNK).collect();
        let entries = parallel::map(&chunks, workers, |part, coins| {
            let start = part * IMAGE_CHUNK;
            let points: Vec<_> = coins
                .iter()
                .enumerate()
                .flat_map(|(i, coin)| {
                    let h = &self.hashes[start + i];
                    [
                        self.bases.image(h, &coin.s),
                        self.bases.image(h, &coin.nonce),
                    ]
                })
                .collect();
            let normalized = ProjectiveImage::normalize(&points);
            coins
                .iter()
                .enumerate()
                .map(|(i, coin)| {
                    let image = normalized[2 * i].clone();
                    let commitment = normalized[2 * i + 1].clone();
                    let c = algebra::image_challenge(
                        &self.inputs[start + i].transcript,
                        key.id,
                        &image,
                        &commitment,
                    );
                    Contribution {
                        image,
                        proof: ImageProof {
                            commitment,
                            responses: std::array::from_fn(|k| coin.nonce[k] + c * coin.s[k]),
                        },
                    }
                })
                .collect::<Vec<_>>()
        })
        .into_iter()
        .flatten()
        .collect();
        // ProofCoins zeroizes every per-input secret vector on drop.
        drop(coins);
        let mut bundle = Bundle {
            member: key.id,
            entries,
            signature: G2Affine::zero(),
        };
        key.authenticate(&self.setup, &self.schedule, &mut bundle)?;
        Ok(bundle)
    }
    fn authenticate_bundle(&self, b: &Bundle) -> Result<bool> {
        if b.signature.check().is_err() {
            return Err(Error("malformed board group element"));
        }
        let Some(member) = self
            .schedule
            .header
            .committee
            .iter()
            .find(|m| m.id == b.member)
        else {
            return Ok(false);
        };
        let h = encoding::hash_to_g2(
            &auth_message(&self.setup, &self.schedule, b),
            b"SDVRF_AUTH_BLS12381G2_XMD:SHA-256_SSWU_RO_V1",
        )?;
        Ok(E::multi_pairing(
            [member.key, (-G1::generator()).into_affine()],
            [h, b.signature],
        )
        .is_zero())
    }
    fn verify_contribution(&self, member: u32, index: usize, f: &Contribution) -> bool {
        let c = algebra::image_challenge(
            &self.inputs[index].transcript,
            member,
            &f.image,
            &f.proof.commitment,
        );
        let lhs = self.bases.image(&self.hashes[index], &f.proof.responses);
        // Exact projective equality avoids affine inversions. Each of the
        // eight equations is still checked separately; no batch acceptance.
        (0..2).all(|i| lhs.g1[i] == f.proof.commitment.g1[i] + f.image.g1[i] * c)
            && (0..6).all(|i| lhs.g2[i] == f.proof.commitment.g2[i] + f.image.g2[i] * c)
    }
    /// Checks are parallel; first-complete selection follows board order.
    pub fn finalize(self, board: Vec<Bundle>, workers: usize) -> Result<ValidatedRecord> {
        if workers == 0 {
            return Err(Error("at least one verification worker required"));
        }
        let authenticated: Vec<_> =
            parallel::map(&board, workers, |_, b| self.authenticate_bundle(b));
        let authenticated: Vec<_> = authenticated.into_iter().collect::<Result<_>>()?;
        let tasks: Vec<_> = board
            .iter()
            .enumerate()
            .flat_map(|(member, b)| {
                (0..b.entries.len())
                    .step_by(IMAGE_CHUNK)
                    .map(move |start| (member, start))
            })
            .collect();
        let checked = parallel::map(&tasks, workers, |_, &(member, start)| {
            let b = &board[member];
            let end = (start + IMAGE_CHUNK).min(b.entries.len());
            let entries = &b.entries[start..end];
            // Check every submitted group element even for unauthenticated,
            // incomplete, or duplicate bundles, preserving the serial API.
            if entries.iter().any(|f| f.check().is_err()) {
                return Err(Error("malformed board group element"));
            }
            let valid = authenticated[member]
                && b.entries.len() == self.inputs.len()
                && entries
                    .iter()
                    .enumerate()
                    .all(|(i, f)| self.verify_contribution(b.member, start + i, f));
            Ok((member, valid))
        });
        let mut valid = vec![true; board.len()];
        for result in checked {
            let (member, ok) = result?;
            valid[member] &= ok;
        }
        let mut seen = HashSet::new();
        let mut included = Vec::new();
        let mut selected = Vec::new();
        for (i, b) in board.iter().enumerate() {
            if !authenticated[i] || b.entries.len() != self.inputs.len() || !seen.insert(b.member) {
                continue;
            }
            if valid[i] {
                included.push(b.member);
                selected.push(i);
            }
        }
        if included.is_empty() {
            return Err(Error("no accepted complete contribution"));
        }
        let sums = parallel::map(&self.inputs, workers, |i, _| {
            let mut sum = ProjectiveImage {
                g1: [G1::zero(); 2],
                g2: [ark_bls12_381::G2Projective::zero(); 6],
            };
            for &member in &selected {
                let f = &board[member].entries[i].image;
                for (s, p) in sum.g1.iter_mut().zip(f.g1) {
                    *s += p;
                }
                for (s, p) in sum.g2.iter_mut().zip(f.g2) {
                    *s += p;
                }
            }
            sum
        });
        let images = ProjectiveImage::normalize(&sums);
        Ok(ValidatedRecord {
            public: RecordData {
                setup_id: self.setup.id(),
                schedule: self.schedule,
                board,
                images,
            },
            setup: self.setup,
            inputs: self.inputs,
            included,
        })
    }
}
