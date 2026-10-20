use super::*;
use ark_bls12_381::{Fr, G1Projective, G2Projective};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{Field, One};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Polynomial};

#[test]
fn fixed_scalar_windows_match_native_multiplication_at_boundaries() {
    let g = G1Projective::generator();
    let h = G2Projective::generator();
    for uses in [1, 128, 384, 4096, usize::MAX] {
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
    let key = CommitteeKey::generate(1, &mut rng).unwrap();
    let schedule = Schedule {
        header: Header {
            application: b"target-oracle-test".to_vec(),
            release_policy: vec![],
            deadline: 17,
            committee: vec![key.public()],
        },
        labels: vec![b"input".to_vec()],
    };
    let mut target_exponent = Fr::from(0u64);
    let mut bundles = Vec::new();
    // Known coins are test-only. Two accepted images must add their fifth coins.
    for _ in 0..2 {
        let member = CommitteeKey::generate((bundles.len() + 1) as u32, &mut rng).unwrap();
        bundles.push((
            member,
            std::array::from_fn::<_, 5, _>(|_| Fr::rand(&mut rng)),
        ));
    }
    let mut schedule = schedule;
    schedule.header.committee = bundles.iter().map(|(k, _)| k.public()).collect();
    // Rebuild the context because the committee credentials are part of eta.
    let seed_bundle = contribute(&pp, &schedule, &bundles[0].0, &mut rng).unwrap();
    let seed_record = finalize_record(pp.clone(), schedule.clone(), vec![seed_bundle]).unwrap();
    let context = seed_record.input(0).unwrap();
    let mut board = Vec::new();
    for (member, s) in bundles {
        let nonce = std::array::from_fn(|_| Fr::rand(&mut rng));
        let f = image(&pp, context.h, &s);
        let commitment = image(&pp, context.h, &nonce);
        let id = member.public().id;
        let c = image_challenge(&context.transcript, id, &f, &commitment);
        let mut b = Bundle {
            member: id,
            entries: vec![Contribution {
                image: f,
                proof: ImageProof {
                    commitment,
                    responses: std::array::from_fn(|i| nonce[i] + c * s[i]),
                },
            }],
            signature: G2Projective::default().into_affine(),
        };
        member.authenticate(&pp, &schedule, &mut b).unwrap();
        target_exponent += s[4];
        board.push(b);
    }
    let record = finalize_record(pp.clone(), schedule, board).unwrap();
    let expected = E::pairing(pp.data().crs.g1[0], pp.data().crs.g2[0]) * target_exponent;
    for indices in [[0, 1, 2, 3], [3, 4, 5, 6], [0, 2, 4, 6]] {
        let shares: Vec<_> = indices
            .iter()
            .map(|i| partial_eval(&record, 0, &keys[*i]).unwrap())
            .collect();
        let e = combine(&record, 0, &shares).unwrap();
        assert!(verify(&record, 0, &e));
        assert_eq!(project(&record.data().images[0], &e.proof), expected);
    }
}
