use super::*;
use ark_bls12_381::{Fr, G1Projective, G2Projective};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{Field, One};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Polynomial};

#[test]
fn fixed_scalar_windows_match_native_multiplication_at_boundaries() {
    let g = G1Projective::generator();
    let h = G2Projective::generator();
    for uses in [1, 32, 64, 128, 256, 512, 1024, 4096, usize::MAX] {
        let a = super::fixed::Fixed::for_uses(g, uses);
        let b = super::fixed::Fixed::for_uses(h, uses);
        for s in [
            Fr::from(0u64),
            Fr::one(),
            -Fr::one(),
            Fr::from(2u64).pow([254]),
        ] {
            assert_eq!(a.mul(&s), g * s);
            assert_eq!(b.mul(&s), h * s);
        }
    }
}

#[test]
fn shared_public_challenge_multiplication_matches_native_on_both_groups() {
    use super::fixed::ChallengeMul;
    use ark_bls12_381::{g1, g2};
    use ark_std::UniformRand;
    use rand::{rngs::StdRng, SeedableRng};
    let mut rng = StdRng::seed_from_u64(98131);
    let mut scalars = vec![
        Fr::from(0u64),
        Fr::one(),
        -Fr::one(),
        Fr::from(2u64).pow([254]),
    ];
    scalars.extend((0..64).map(|_| Fr::rand(&mut rng)));
    let g = G1Projective::rand(&mut rng).into_affine();
    let h = G2Projective::rand(&mut rng).into_affine();
    for c in scalars {
        let a = ChallengeMul::<g1::Config>::new(c);
        let b = ChallengeMul::<g2::Config>::new(c);
        for base in [g, -g, ark_bls12_381::G1Affine::identity()] {
            assert_eq!(a.mul(base), base * c);
        }
        for base in [h, -h, ark_bls12_381::G2Affine::identity()] {
            assert_eq!(b.mul(base), base * c);
        }
    }
}

// A known tau is confined to this independent polynomial-identity test.
#[test]
fn optimized_bases_equal_exact_polynomial_quotients() {
    for n in [2, 4, 8, 16] {
        let tau = Fr::from(19u64);
        let crs = crs::Crs {
            g1: (0..=n)
                .map(|d| (G1Projective::generator() * tau.pow([d as u64])).into_affine())
                .collect(),
            g2: (0..=n)
                .map(|d| (G2Projective::generator() * tau.pow([d as u64])).into_affine())
                .collect(),
        };
        let p = Parameters::new(crs, 1).unwrap();
        let mut zc = vec![Fr::from(0u64); n + 1];
        zc[0] = -Fr::one();
        zc[n] = Fr::one();
        let z = DensePolynomial::from_coefficients_vec(zc);
        let roots: Vec<_> = p.domain.elements().collect();
        let polys: Vec<_> = (0..n)
            .map(|i| {
                let mut l = DensePolynomial::from_coefficients_vec(vec![Fr::one()]);
                for (j, root) in roots.iter().enumerate() {
                    if i != j {
                        l = l.naive_mul(&DensePolynomial::from_coefficients_vec(vec![
                            -*root,
                            Fr::one(),
                        ]));
                    }
                }
                let scale = l.evaluate(&roots[i]).inverse().unwrap();
                for c in &mut l.coeffs {
                    *c *= scale;
                }
                l
            })
            .collect();
        for i in 0..n {
            assert_eq!(
                p.bases.li1[i],
                (G1Projective::generator() * polys[i].evaluate(&tau)).into_affine()
            );
            for j in 0..n {
                let product = polys[i].naive_mul(&polys[j]);
                let numerator = if i == j {
                    &product - &polys[i]
                } else {
                    product
                };
                let quotient = &numerator / &z;
                assert_eq!(&quotient * &z, numerator);
                let v = quotient.evaluate(&tau);
                assert_eq!(
                    p.bases.cross1[i][j],
                    (G1Projective::generator() * v).into_affine()
                );
                assert_eq!(
                    p.bases.cross2[i][j],
                    (G2Projective::generator() * v).into_affine()
                );
            }
        }
    }
}

#[test]
fn projection_recovers_the_independently_known_target() {
    use super::algebra::{image, image_challenge, project};
    use ark_bls12_381::Bls12_381 as E;
    use ark_ec::pairing::Pairing;
    use ark_std::UniformRand;
    use rand::{rngs::StdRng, SeedableRng};
    use std::sync::Arc;
    let mut rng = StdRng::seed_from_u64(2981);
    let (crs, _) = crs::local_ceremony(8, 2, &mut rng).unwrap();
    let params = Parameters::new(crs, 4).unwrap();
    let (keys, registrations): (Vec<_>, Vec<_>) = (1..8)
        .map(|i| generate_key(&params, i, &mut rng).unwrap())
        .unzip();
    let pp = Arc::new(finalize_setup(params, registrations).unwrap());
    let key = 1u32;
    let schedule = Schedule {
        header: Header {
            application: b"target-oracle-test".to_vec(),
            release_policy: vec![],
            deadline: 17,
            committee: vec![key],
        },
        labels: vec![b"input".to_vec()],
    };
    let mut bundles = Vec::new();
    // Known coins are test-only. Two accepted images must add their fifth coins.
    for _ in 0..2 {
        let member = (bundles.len() + 1) as u32;
        bundles.push((
            member,
            std::array::from_fn::<_, 5, _>(|_| Fr::rand(&mut rng)),
        ));
    }
    let mut schedule = schedule;
    schedule.header.committee = bundles.iter().map(|(k, _)| *k).collect();
    // Rebuild the context because the committee identities are part of eta.
    let seed_bundle = contribute(&pp, &schedule, bundles[0].0, &mut rng).unwrap();
    let seed_record = finalize_record(pp.clone(), schedule.clone(), vec![seed_bundle]).unwrap();
    let context = seed_record.input(0).unwrap();
    for identity_output in [false, true] {
        let mut target_exponent = Fr::from(0u64);
        let mut board = Vec::new();
        for (member, mut s) in bundles.iter().copied() {
            if identity_output {
                s[4] = Fr::from(0u64);
            }
            let nonce = std::array::from_fn(|_| Fr::rand(&mut rng));
            let f = image(&pp, context.h, &s);
            let commitment = image(&pp, context.h, &nonce);
            let id = member;
            let c = image_challenge(&context.transcript, id, &f, &commitment);
            let b = Bundle {
                member: id,
                entries: vec![Contribution {
                    image: f,
                    proof: ImageProof {
                        commitment,
                        responses: std::array::from_fn(|i| nonce[i] + c * s[i]),
                    },
                }],
            };
            target_exponent += s[4];
            board.push(b);
        }
        let record = finalize_record(pp.clone(), schedule.clone(), board).unwrap();
        let expected = E::pairing(pp.data().crs.g1[0], pp.data().crs.g2[0]) * target_exponent;
        for indices in [[0, 1, 2, 3], [3, 4, 5, 6], [0, 2, 4, 6]] {
            let shares: Vec<_> = indices
                .iter()
                .map(|i| partial_eval(&record, 0, &keys[*i]).unwrap())
                .collect();
            let e = combine(&record, 0, &shares).unwrap();
            assert!(verify(&record, 0, &e));
            assert_eq!(project(&record.data().images[0], &e.proof), expected);
            assert_eq!(e.output, expected);
        }
    }
}
