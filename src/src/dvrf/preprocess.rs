//! Certified randomized images and first-complete selection.
//! Submission identities and the frozen board order are authenticated externally.
use super::{
    algebra, encoding, fixed::ProjectiveImage, parallel, Error, Image, ImageProof, Result,
    ValidatedSetup,
};
use ark_bls12_381::{Fr, G1Projective as G1, G2Affine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{UniformRand, Zero};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use zeroize::Zeroize;

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Header {
    pub application: Vec<u8>,
    pub release_policy: Vec<u8>,
    pub deadline: u64,
    pub committee: Vec<u32>,
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
        for &member in &self.header.committee {
            if member == 0 || !ids.insert(member) {
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
    encoding::field(&mut prefix, b"profile", b"SDVRF-BLS12381-v2");
    encoding::field(&mut prefix, b"setup", pp.encoded());
    encoding::field(&mut prefix, b"schedule", &encoding::bytes(s));
    // SHA-256 prefixes include the full field length. Cache by label length
    // so variable-length labels preserve the original framing byte for byte.
    let mut states = HashMap::new();
    for x in &s.labels {
        states.entry(x.len()).or_insert_with(|| {
            let len = prefix.len() + 8 + b"label".len() + 8 + x.len();
            let mut tag = Sha256::new();
            encoding::hash_field_header(&mut tag, b"domain", b"SDVRF-INPUT-ID-v1".len());
            tag.update(b"SDVRF-INPUT-ID-v1");
            encoding::hash_field_header(&mut tag, b"data", len);
            tag.update(&prefix);
            let mut output = Sha256::new();
            encoding::hash_field_header(&mut output, b"domain", b"SDVRF-OUTPUT-v1".len());
            output.update(b"SDVRF-OUTPUT-v1");
            encoding::hash_field_header(&mut output, b"eta", len);
            output.update(&prefix);
            (tag, output)
        });
    }
    let chunks: Vec<_> = s.labels.chunks(s.labels.len().div_ceil(workers)).collect();
    parallel::map(&chunks, workers, |_, labels| {
        // Hash-to-group and Merlin retain their original complete-message API.
        // Reuse one buffer per worker rather than copying PP for every input.
        let mut eta = prefix.clone();
        labels
            .iter()
            .map(|x| {
                eta.truncate(prefix.len());
                encoding::field(&mut eta, b"label", x);
                let suffix = &eta[prefix.len()..];
                let (tag_state, output_state) = &states[&x.len()];
                let mut tag = tag_state.clone();
                tag.update(suffix);
                let tag = tag.finalize().into();
                let h = encoding::hash_to_g2(&eta, b"SDVRF_GRP_BLS12381G2_XMD:SHA-256_SSWU_RO_V1")?;
                let mut transcript = merlin::Transcript::new(b"SDVRF-IMAGE-FS-v1");
                transcript.append_message(b"eta", &eta);
                let mut output_prefix = output_state.clone();
                output_prefix.update(suffix);
                Ok(InputContext {
                    tag,
                    h,
                    transcript,
                    output_prefix,
                })
            })
            .collect::<Vec<_>>()
    })
    .into_iter()
    .flatten()
    .collect()
}
pub fn contribute<R: RngCore + CryptoRng>(
    pp: &ValidatedSetup,
    schedule: &Schedule,
    member: u32,
    rng: &mut R,
) -> Result<Bundle> {
    if !schedule.header.committee.contains(&member) {
        return Err(Error("undesignated contributor"));
    }
    let inputs = contexts(pp, schedule)?;
    let mut entries = Vec::with_capacity(inputs.len());
    for input in &inputs {
        let mut s = std::array::from_fn(|_| Fr::rand(rng));
        let mut nonce = std::array::from_fn(|_| Fr::rand(rng));
        let image = algebra::image(pp, input.h, &s);
        let commitment = algebra::image(pp, input.h, &nonce);
        let c = algebra::image_challenge(&input.transcript, member, &image, &commitment);
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
    Ok(Bundle { member, entries })
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
        // Bundle identities are authenticated by the external delivery layer.
        if !schedule.header.committee.contains(&b.member) {
            continue;
        }
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
/// The caller supplies externally authenticated submissions in finalized board order.
/// Points must be generated by the group API or obtained through checked decoding;
/// finalization does not repeat point-membership checks.
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
    bases: Arc<super::fixed::ImageBases>,
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
        let bases = setup.image_bases(input_uses.saturating_mul(inputs.len()));
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
    pub fn contribute<R: RngCore + CryptoRng>(&self, member: u32, rng: &mut R) -> Result<Bundle> {
        self.contribute_parallel(member, rng, 1)
    }
    /// The RNG is consumed in input order before workers start, so proof
    /// bytes are independent of scheduling and worker count.
    pub fn contribute_parallel<R: RngCore + CryptoRng>(
        &self,
        member: u32,
        rng: &mut R,
        workers: usize,
    ) -> Result<Bundle> {
        if workers == 0 {
            return Err(Error("at least one contribution worker required"));
        }
        if !self.schedule.header.committee.contains(&member) {
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
                        member,
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
        Ok(Bundle { member, entries })
    }
    fn verify_contribution(&self, member: u32, index: usize, f: &Contribution) -> bool {
        let c = algebra::image_challenge(
            &self.inputs[index].transcript,
            member,
            &f.image,
            &f.proof.commitment,
        );
        let lhs = self.bases.image(&self.hashes[index], &f.proof.responses);
        let g1 = super::fixed::ChallengeMul::<ark_bls12_381::g1::Config>::new(c);
        let g2 = super::fixed::ChallengeMul::<ark_bls12_381::g2::Config>::new(c);
        // Exact projective equality avoids affine inversions. Each of the
        // eight equations is still checked separately; no batch acceptance.
        (0..2).all(|i| lhs.g1[i] == f.proof.commitment.g1[i] + g1.mul(f.image.g1[i]))
            && (0..6).all(|i| lhs.g2[i] == f.proof.commitment.g2[i] + g2.mul(f.image.g2[i]))
    }
    /// The caller authenticates submission identities and finalizes the board order.
    /// Points must be generated by the group API or obtained through checked decoding;
    /// finalization does not repeat point-membership checks.
    /// Checks are parallel; first-complete selection follows that order.
    pub fn finalize(self, board: Vec<Bundle>, workers: usize) -> Result<ValidatedRecord> {
        if workers == 0 {
            return Err(Error("at least one verification worker required"));
        }
        let designated: Vec<_> = board
            .iter()
            .map(|b| self.schedule.header.committee.contains(&b.member))
            .collect();
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
            let valid = designated[member]
                && b.entries.len() == self.inputs.len()
                && entries
                    .iter()
                    .enumerate()
                    .all(|(i, f)| self.verify_contribution(b.member, start + i, f));
            (member, valid)
        });
        let mut valid = vec![true; board.len()];
        for (member, ok) in checked {
            valid[member] &= ok;
        }
        let mut seen = HashSet::new();
        let mut included = Vec::new();
        let mut selected = Vec::new();
        for (i, b) in board.iter().enumerate() {
            if !designated[i] || b.entries.len() != self.inputs.len() || !seen.insert(b.member) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dvrf::{crs, finalize_setup, generate_key, Parameters};
    use rand::{rngs::StdRng, SeedableRng};

    fn setup() -> Arc<ValidatedSetup> {
        let mut rng = StdRng::seed_from_u64(44017);
        let (crs, _) = crs::local_ceremony(4, 2, &mut rng).unwrap();
        let p = Parameters::new(crs, 2).unwrap();
        let regs = (1..4)
            .map(|i| generate_key(&p, i, &mut rng).unwrap().1)
            .collect();
        Arc::new(finalize_setup(p, regs).unwrap())
    }

    #[test]
    fn cached_contexts_preserve_original_framing_hashes_and_challenges() {
        let pp = setup();
        let schedule = Schedule {
            header: Header {
                application: b"prefix-equivalence".to_vec(),
                release_policy: vec![1, 2, 3],
                deadline: 31,
                committee: vec![1, 2],
            },
            labels: vec![
                vec![],
                vec![0],
                vec![1],
                vec![3; 63],
                vec![4; 64],
                vec![5; 65],
                vec![6; 1000],
            ],
        };
        for workers in [1, 2, 8] {
            let inputs = contexts_parallel(&pp, &schedule, workers).unwrap();
            for (x, input) in schedule.labels.iter().zip(inputs) {
                // Independent original construction; do not reuse the optimized
                // header helper or any cached SHA state in this reference.
                let mut eta = Vec::new();
                encoding::field(&mut eta, b"profile", b"SDVRF-BLS12381-v2");
                encoding::field(&mut eta, b"setup", pp.encoded());
                encoding::field(&mut eta, b"schedule", &encoding::bytes(&schedule));
                encoding::field(&mut eta, b"label", x);
                assert_eq!(input.tag, encoding::digest(b"SDVRF-INPUT-ID-v1", &eta));
                assert_eq!(
                    input.h,
                    encoding::hash_to_g2(&eta, b"SDVRF_GRP_BLS12381G2_XMD:SHA-256_SSWU_RO_V1")
                        .unwrap()
                );
                let mut reference = merlin::Transcript::new(b"SDVRF-IMAGE-FS-v1");
                reference.append_message(b"eta", &eta);
                let mut actual = input.transcript.clone();
                assert_eq!(
                    encoding::challenge(&mut actual),
                    encoding::challenge(&mut reference)
                );
                let mut output = Vec::new();
                encoding::field(&mut output, b"domain", b"SDVRF-OUTPUT-v1");
                encoding::field(&mut output, b"eta", &eta);
                let mut reference = Sha256::new();
                reference.update(output);
                // Verify the cached state remains equivalent after more data.
                reference.update(b"synthetic-output");
                let mut actual = input.output_prefix;
                actual.update(b"synthetic-output");
                assert_eq!(actual.finalize(), reference.finalize());
            }
        }
    }

    #[test]
    fn public_table_cache_is_shared_only_within_the_same_setup_and_window() {
        let pp = setup();
        let first = pp.image_bases(128);
        let same = pp.image_bases(128);
        assert!(Arc::ptr_eq(&first, &same));
        let different_window = pp.image_bases(4096);
        assert!(!Arc::ptr_eq(&first, &different_window));
        let changed = pp.with_threshold(1).unwrap();
        let different_setup = changed.image_bases(128);
        assert!(!Arc::ptr_eq(&first, &different_setup));
        let h = encoding::hash_to_g2(b"cache-test", b"test-domain").unwrap();
        let h = super::super::fixed::input_base(h, 128);
        let s = [Fr::from(1u64); 5];
        let image = first.image(&h, &s);
        let other = different_window.image(&h, &s);
        assert_eq!(image.g1, other.g1);
        assert_eq!(image.g2, other.g2);
        // Changing T changes a matrix base; the new setup must not reuse it.
        assert_ne!(image.g1, different_setup.image(&h, &s).g1);
    }
}
