use ark_bls12_381::{Fr, G1Projective as G1, G2Projective as G2};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::One;
use rand::{rngs::StdRng, SeedableRng};
use sdvrf::dvrf::*;
use std::sync::Arc;

fn fixture(
    n: usize,
    t: usize,
    batch: usize,
) -> (
    Arc<ValidatedSetup>,
    Vec<SecretKey>,
    Schedule,
    Vec<u32>,
    ValidatedRecord,
) {
    let mut rng = StdRng::seed_from_u64(8823 + n as u64 + t as u64);
    let (crs, _) = crs::local_ceremony(n + 1, 2, &mut rng).unwrap();
    let p = Parameters::new(crs, t).unwrap();
    let mut keys = Vec::new();
    let mut regs = Vec::new();
    for i in 1..=n {
        let (sk, pk) = generate_key(&p, i, &mut rng).unwrap();
        keys.push(sk);
        regs.push(pk);
    }
    let pp = Arc::new(finalize_setup(p, regs).unwrap());
    let committee: Vec<_> = (1..=2).collect();
    let schedule = Schedule {
        header: Header {
            application: b"test-dvrf".to_vec(),
            release_policy: b"round schedule".to_vec(),
            deadline: 42,
            committee: committee.clone(),
        },
        labels: (0..batch)
            .map(|i| (i as u64).to_le_bytes().to_vec())
            .collect(),
    };
    let board = committee
        .iter()
        .map(|key| contribute(&pp, &schedule, *key, &mut rng).unwrap())
        .collect();
    let record = finalize_record(pp.clone(), schedule.clone(), board).unwrap();
    (pp, keys, schedule, committee, record)
}

#[test]
fn every_qualified_subset_and_permutation_has_the_same_output() {
    for t in [1, 2, 3] {
        let (_, keys, _, _, record) = fixture(3, t, 2);
        for input in 0..2 {
            let all: Vec<_> = keys
                .iter()
                .map(|k| partial_eval(&record, input, k).unwrap())
                .collect();
            let mut expected = None;
            let mut proofs = Vec::new();
            for mask in 0u32..8 {
                if mask.count_ones() as usize != t {
                    continue;
                }
                let mut selected: Vec<_> = all
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| mask & (1 << i) != 0)
                    .map(|(_, s)| s.clone())
                    .collect();
                assert!(selected.iter().all(|s| partial_verify(&record, input, s)));
                let evaluation = combine(&record, input, &selected).unwrap();
                assert!(verify(&record, input, &evaluation));
                if let Some(y) = expected {
                    assert_eq!(y, evaluation.output);
                } else {
                    expected = Some(evaluation.output);
                }
                selected.reverse();
                assert_eq!(combine(&record, input, &selected).unwrap(), evaluation);
                proofs.push(evaluation.proof);
            }
            if t < 3 {
                assert!(
                    proofs.windows(2).any(|p| p[0] != p[1]),
                    "authorization witnesses need not be unique"
                );
            }
        }
    }
}
#[test]
fn all_eight_coordinates_output_and_input_binding_are_checked() {
    let (_, keys, _, _, record) = fixture(7, 3, 2);
    let shares: Vec<_> = keys[..3]
        .iter()
        .map(|k| partial_eval(&record, 0, k).unwrap())
        .collect();
    let e = combine(&record, 0, &shares).unwrap();
    assert!(verify(&record, 0, &e));
    assert!(!verify(&record, 1, &e));
    assert!(!verify(&record, 2, &e));
    for i in 0..6 {
        let mut bad = e.clone();
        bad.proof.g1[i] = (bad.proof.g1[i] + G1::generator()).into_affine();
        assert!(!verify(&record, 0, &bad));
    }
    for i in 0..2 {
        let mut bad = e.clone();
        bad.proof.g2[i] = (bad.proof.g2[i] + G2::generator()).into_affine();
        assert!(!verify(&record, 0, &bad));
    }
    let mut bad = e.clone();
    bad.output[0] ^= 1;
    assert!(!verify(&record, 0, &bad));
    let mut bad = shares[0].clone();
    bad.value = (bad.value + G2::generator()).into_affine();
    assert!(!partial_verify(&record, 0, &bad));
    bad = shares[0].clone();
    bad.id = 0;
    assert!(!partial_verify(&record, 0, &bad));
    bad = shares[0].clone();
    bad.id = 8;
    assert!(!partial_verify(&record, 0, &bad));
    bad = shares[0].clone();
    bad.tag[0] ^= 1;
    assert!(!partial_verify(&record, 0, &bad));
    assert!(combine(&record, 0, &shares[..2]).is_err());
    assert!(combine(&record, 0, &vec![shares[0].clone(); 3]).is_err());
    assert!(!partial_verify(&record, 1, &shares[0]));
}
#[test]
fn public_setup_and_degree_cap_are_validated() {
    let (pp, _, _, _, _) = fixture(3, 2, 1);
    let original = pp.data().clone();
    assert!(validate_setup(decode(&encode(&original)).unwrap()).is_ok());
    for field in 0..5 {
        let mut bad = original.clone();
        let pk = &mut bad.registrations[1];
        match field {
            0 => pk.x = (pk.x + G1::generator()).into_affine(),
            1 => pk.h1 = (pk.h1 + G1::generator()).into_affine(),
            2 => pk.h2 = (pk.h2 + G1::generator()).into_affine(),
            3 => pk.h4 = (pk.h4 + G1::generator()).into_affine(),
            _ => pk.cross[2] = (pk.cross[2] + G1::generator()).into_affine(),
        };
        assert!(validate_setup(bad).is_err());
    }
    let mut bad = original.clone();
    bad.cache[0] = (bad.cache[0] + G1::generator()).into_affine();
    assert!(validate_setup(bad).is_err());
    let mut bad = original.clone();
    bad.registrations[0].x = (bad.registrations[0].x + G1::generator()).into_affine();
    assert!(validate_setup(bad).is_err());
    let mut crs = original.crs.clone();
    crs.g1.push(G1::generator().into_affine());
    assert!(crs.validate().is_err());
    crs = original.crs.clone();
    crs.g2.push(G2::generator().into_affine());
    assert!(crs.validate().is_err());
    crs = original.crs.clone();
    crs.g1[4] = (crs.g1[4] + G1::generator()).into_affine();
    assert!(crs.validate().is_err());
    assert!(crs::Crs::initial(4).unwrap().validate().is_err());
    assert!(crs::Crs::initial(5).is_err());
}
#[test]
fn authenticated_image_proofs_selection_and_record_pinning() {
    let (pp, _, schedule, _, record) = fixture(3, 2, 2);
    let original = record.data().clone();
    assert!(validate_record(pp.clone(), decode(&encode(&original)).unwrap()).is_ok());
    let mut bad = original.clone();
    bad.images[0].g1[0] = (bad.images[0].g1[0] + G1::generator()).into_affine();
    assert!(validate_record(pp.clone(), bad).is_err());
    let mut bad = original.clone();
    bad.board.reverse();
    assert!(validate_record(pp.clone(), bad).is_ok()); // order changes are different authenticated board instances, not output choices
    let mut tampered = original.board[0].clone();
    tampered.entries[0].proof.responses[4] += Fr::one();

    assert!(finalize_record(pp.clone(), schedule.clone(), vec![tampered.clone()]).is_err());
    let record = finalize_record(
        pp.clone(),
        schedule.clone(),
        vec![
            tampered,
            original.board[0].clone(),
            original.board[1].clone(),
        ],
    )
    .unwrap();
    assert_eq!(
        record.included(),
        &[2],
        "first complete invalid submission cannot be replaced after the deadline"
    );
    let mut changed = schedule.clone();
    changed.header.deadline += 1;
    assert!(finalize_record(pp.clone(), changed, original.board.clone()).is_err());
    changed = schedule.clone();
    changed.labels.push(changed.labels[0].clone());
    assert!(changed.validate().is_err());
    assert!(finalize_record(pp.clone(), schedule, vec![]).is_err());
    let mut raw = encode(&original);
    raw.push(0);
    assert!(decode::<RecordData>(&raw).is_err());
    assert!(decode::<RecordData>(&raw[..15]).is_err());
}
#[test]
fn tiny_boundary_and_independent_setup_keys() {
    let (_, keys, _, _, record) = fixture(1, 1, 1);
    let s = partial_eval(&record, 0, &keys[0]).unwrap();
    let e = combine(&record, 0, &[s]).unwrap();
    assert!(verify(&record, 0, &e));
    assert_eq!(encode(&e.proof).len(), 480); // six G1 and two G2 elements
    let (_, foreign, _, _, _) = fixture(3, 2, 1);
    assert!(partial_eval(&record, 0, &foreign[0]).is_err());
    let mut rng = StdRng::seed_from_u64(91);
    let old = crs::Crs::initial(4).unwrap();
    let mut update = crs::contribute(&old, &mut rng).unwrap();
    assert!(crs::verify_update(&old, &update).is_ok());
    update.response += Fr::one();
    assert!(crs::verify_update(&old, &update).is_err());
}

#[test]
fn cached_parallel_preprocessing_matches_the_original_checks() {
    let (pp, _, schedule, committee, original) = fixture(3, 2, 3);
    let plan = PreparedBatch::new(pp.clone(), schedule.clone()).unwrap();
    for key in &committee {
        let mut r1 = StdRng::seed_from_u64(700);
        let mut r2 = StdRng::seed_from_u64(700);
        assert_eq!(
            contribute(&pp, &schedule, *key, &mut r1).unwrap(),
            plan.contribute(*key, &mut r2).unwrap()
        );
    }
    let a = plan.finalize(original.data().board.clone(), 3).unwrap();
    assert_eq!(a.data(), original.data());
    let mut bad = original.data().board[0].clone();
    bad.entries[0].proof.responses[0] += Fr::one();

    let board = vec![
        bad,
        original.data().board[0].clone(),
        original.data().board[1].clone(),
    ];
    let slow = finalize_record(pp.clone(), schedule.clone(), board.clone()).unwrap();
    let fast = PreparedBatch::new(pp.clone(), schedule.clone())
        .unwrap()
        .finalize(board, 2)
        .unwrap();
    assert_eq!(slow.data(), fast.data());
    assert_eq!(fast.included(), &[2]);
    // Malformed external points are rejected at the decoding boundary, before
    // either finalization path accepts typed group elements.
    let mut malformed = original.data().board[0].clone();
    malformed.entries[0].image.g1[0] = ark_bls12_381::G1Affine::new_unchecked(
        ark_bls12_381::Fq::from(0u64),
        ark_bls12_381::Fq::from(0u64),
    );
    let mut raw = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_uncompressed(&malformed, &mut raw).unwrap();
    assert!(
        <Bundle as ark_serialize::CanonicalDeserialize>::deserialize_uncompressed(&raw[..])
            .is_err()
    );
    assert!(PreparedBatch::new(pp, schedule)
        .unwrap()
        .finalize(vec![], 1)
        .is_err());
}

#[test]
fn preprocessing_chunks_workers_and_all_proof_coordinates_match_serial() {
    let (pp, keys, schedule, committee, original) = fixture(3, 2, 35);
    for workers in [1, 2, 8, 64] {
        let plan = PreparedBatch::new_with_workers(pp.clone(), schedule.clone(), workers).unwrap();
        for key in &committee {
            let mut expected_rng = StdRng::seed_from_u64(916);
            let mut actual_rng = StdRng::seed_from_u64(916);
            let expected = contribute(&pp, &schedule, *key, &mut expected_rng).unwrap();
            let actual = plan
                .contribute_parallel(*key, &mut actual_rng, workers)
                .unwrap();
            assert_eq!(encode(&expected), encode(&actual));
        }
        let record = plan
            .finalize(original.data().board.clone(), workers)
            .unwrap();
        assert_eq!(record.data(), original.data());
        for index in [0, 16, 34] {
            let shares: Vec<_> = keys
                .iter()
                .take(2)
                .map(|key| partial_eval(&record, index, key).unwrap())
                .collect();
            assert!(verify(
                &record,
                index,
                &combine(&record, index, &shares).unwrap()
            ));
        }
    }
    // Each commitment coordinate must remain checked, including after a chunk boundary.
    for coordinate in 0..8 {
        let mut bad = original.data().board[0].clone();
        let proof = &mut bad.entries[17].proof;
        if coordinate < 2 {
            proof.commitment.g1[coordinate] =
                (proof.commitment.g1[coordinate] + G1::generator()).into_affine();
        } else {
            proof.commitment.g2[coordinate - 2] =
                (proof.commitment.g2[coordinate - 2] + G2::generator()).into_affine();
        }

        let board = vec![
            bad,
            original.data().board[0].clone(),
            original.data().board[1].clone(),
        ];
        let expected = finalize_record(pp.clone(), schedule.clone(), board.clone()).unwrap();
        let actual = PreparedBatch::new(pp.clone(), schedule.clone())
            .unwrap()
            .finalize(board, 8)
            .unwrap();
        assert_eq!(actual.data(), expected.data());
        assert_eq!(actual.included(), &[2]);
    }
    let mut incomplete = original.data().board[0].clone();
    incomplete.entries.pop();

    let board = vec![
        incomplete,
        original.data().board[0].clone(),
        original.data().board[1].clone(),
    ];
    let expected = finalize_record(pp.clone(), schedule.clone(), board.clone()).unwrap();
    let actual = PreparedBatch::new(pp.clone(), schedule.clone())
        .unwrap()
        .finalize(board, 8)
        .unwrap();
    assert_eq!(actual.data(), expected.data());
    assert_eq!(actual.included(), &[1, 2]);
    let mut unknown = original.data().board[0].clone();
    unknown.member = 777;
    unknown.entries[34].image.g1[0].x = ark_bls12_381::Fq::from(0u64);
    assert!(PreparedBatch::new(pp.clone(), schedule.clone())
        .unwrap()
        .finalize(vec![unknown], 8)
        .is_err());
    assert!(PreparedBatch::new_with_workers(pp.clone(), schedule.clone(), 0).is_err());
    let plan = PreparedBatch::new(pp, schedule).unwrap();
    assert!(plan
        .contribute_parallel(committee[0], &mut StdRng::seed_from_u64(1), 0)
        .is_err());
    assert!(plan.finalize(vec![], 0).is_err());
}

#[test]
fn changed_threshold_is_a_new_validated_setup_and_input_instance() {
    let (pp, keys, schedule, committee, record) = fixture(3, 2, 1);
    for t in [1, 2, 3] {
        let changed = Arc::new(pp.with_threshold(t).unwrap());
        assert_eq!(
            validate_setup(changed.data().clone()).unwrap().data(),
            changed.data()
        );
        let mut rng = StdRng::seed_from_u64(813);
        let board = committee
            .iter()
            .map(|key| contribute(&changed, &schedule, *key, &mut rng).unwrap())
            .collect();
        let r = finalize_record(changed.clone(), schedule.clone(), board).unwrap();
        let shares: Vec<_> = keys[..t]
            .iter()
            .map(|key| partial_eval(&r, 0, &key.for_setup(&changed).unwrap()).unwrap())
            .collect();
        let e = combine(&r, 0, &shares).unwrap();
        assert!(verify(&r, 0, &e));
        if t != 2 {
            assert_ne!(pp.id(), changed.id());
            assert_ne!(record.input_tag(0).unwrap(), r.input_tag(0).unwrap());
            assert!(!verify(&record, 0, &e));
        }
    }
    assert!(pp.with_threshold(0).is_err());
    assert!(pp.with_threshold(4).is_err());
    let (_, foreign, _, _, _) = fixture(7, 3, 1);
    assert!(foreign[0].for_setup(&pp).is_err());
}

#[test]
fn signature_free_bundles_keep_membership_and_proof_identity_binding() {
    let (pp, _, schedule, _, record) = fixture(3, 2, 2);
    assert_eq!(encode(&record.data().board[0]).len(), 12 + 2 * 1504);
    let mut relabeled = record.data().board[0].clone();
    relabeled.member = 2;
    assert!(finalize_record(pp.clone(), schedule.clone(), vec![relabeled]).is_err());
    let mut unknown = record.data().board[0].clone();
    unknown.member = 777;
    let mut board = vec![unknown];
    board.extend(record.data().board.clone());
    assert_eq!(
        finalize_record(pp.clone(), schedule.clone(), board)
            .unwrap()
            .included(),
        &[1, 2]
    );
    for members in [vec![0, 1], vec![1, 1]] {
        let mut invalid = schedule.clone();
        invalid.header.committee = members;
        assert!(PreparedBatch::new(pp.clone(), invalid).is_err());
    }
}
