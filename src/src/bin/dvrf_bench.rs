//! Core DVRF measurements. Public setup is checked once per process; threshold
//! variants create distinct PP/input instances from the same validated hints.
use ark_serialize::CanonicalSerialize;
use rand::{rngs::StdRng, seq::SliceRandom, RngCore, SeedableRng};
use sdvrf::dvrf::{
    self, crs, CommitteeKey, Header, Parameters, PreparedBatch, Schedule, SecretKey,
    ValidatedRecord, ValidatedSetup,
};
use sha2::{Digest, Sha256};
use std::{hint::black_box, io::Write, sync::Arc, time::Instant};

#[derive(Clone)]
struct Reporter {
    experiment: String,
    n: usize,
    t: usize,
    batch: usize,
    m: usize,
    workers: usize,
    run: usize,
    seed: String,
}
impl Reporter {
    fn row(&self, metric: &str, sample: usize, value: f64, unit: &str) {
        println!(
            "{},{},{},{},{},{},{},{},{},{},{:.9},{}",
            self.experiment,
            self.n,
            self.t,
            self.batch,
            self.m,
            self.workers,
            self.run,
            self.seed,
            metric,
            sample,
            value,
            unit
        );
    }
    fn time<T>(&self, metric: &str, f: impl FnOnce() -> T) -> T {
        let start = Instant::now();
        let result = f();
        self.row(metric, 0, start.elapsed().as_secs_f64() * 1000., "ms");
        result
    }
    fn repeat<T>(&self, metric: &str, count: usize, mut f: impl FnMut() -> T) {
        for _ in 0..3 {
            black_box(f());
        }
        for i in 0..count {
            let start = Instant::now();
            black_box(f());
            self.row(metric, i, start.elapsed().as_secs_f64() * 1000., "ms");
        }
    }
    fn bytes(&self, metric: &str, value: usize) {
        self.row(metric, 0, value as f64, "bytes");
    }
}
fn encoded_len<T: CanonicalSerialize>(value: &T) -> usize {
    struct Counter(usize);
    impl Write for Counter {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0 += b.len();
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    value.serialize_compressed(&mut counter).unwrap();
    assert_eq!(counter.0, value.compressed_size());
    counter.0
}
fn rss() -> usize {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage receives a valid, exclusively owned output pointer.
    assert_eq!(
        unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
        0
    );
    // SAFETY: the successful call initialized usage.
    let raw = unsafe { usage.assume_init() }.ru_maxrss as usize;
    if cfg!(target_os = "macos") {
        raw
    } else {
        raw * 1024
    }
}
fn prepare(pp: Arc<ValidatedSetup>, r: &Reporter, rng: &mut StdRng) -> ValidatedRecord {
    let committee: Vec<_> = (1..=r.m)
        .map(|i| CommitteeKey::generate(i as u32, rng).unwrap())
        .collect();
    let schedule = Schedule {
        header: Header {
            application: b"DVRF-core-benchmark-v2".to_vec(),
            release_policy: b"externally-authenticated-release".to_vec(),
            deadline: 1_800_000_000,
            committee: committee.iter().map(CommitteeKey::public).collect(),
        },
        labels: (0..r.batch)
            .map(|i| (i as u64).to_le_bytes().to_vec())
            .collect(),
    };
    // The Contribute time includes all shared public context/table preparation.
    let (plan, board) = r.time("contribute", || {
        let plan = PreparedBatch::new_with_workers(pp.clone(), schedule, r.workers).unwrap();
        let seeds: Vec<[u8; 32]> = (0..r.m)
            .map(|_| {
                let mut seed = [0; 32];
                rng.fill_bytes(&mut seed);
                seed
            })
            .collect();
        let member_workers = r.workers.min(r.m);
        let input_workers = (r.workers / member_workers).max(1);
        let chunk = r.m.div_ceil(member_workers);
        let board = std::thread::scope(|scope| {
            let jobs: Vec<_> = committee
                .chunks(chunk)
                .zip(seeds.chunks(chunk))
                .map(|(members, seeds)| {
                    let plan = &plan;
                    scope.spawn(move || {
                        members
                            .iter()
                            .zip(seeds)
                            .map(|(key, seed)| {
                                plan.contribute_parallel(
                                    key,
                                    &mut StdRng::from_seed(*seed),
                                    input_workers,
                                )
                                .unwrap()
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            jobs.into_iter()
                .flat_map(|job| job.join().expect("contribution worker panicked"))
                .collect::<Vec<_>>()
        });
        (plan, board)
    });
    r.bytes("bundle_one_bytes", encoded_len(&board[0]));
    r.bytes("board_bytes", encoded_len(&board));
    let record = r.time("check_aggregate", || {
        plan.finalize(board, r.workers).unwrap()
    });
    assert_eq!(record.included().len(), r.m);
    r.bytes("record_bytes", encoded_len(record.data()));
    r.bytes("image_bytes", encoded_len(&record.data().images[0]));
    record
}
fn online(record: &ValidatedRecord, keys: &[SecretKey], r: &Reporter, samples: usize) {
    let shares: Vec<_> = keys[..r.t]
        .iter()
        .map(|key| dvrf::partial_eval(record, 0, key).unwrap())
        .collect();
    let evaluation = dvrf::combine(record, 0, &shares).unwrap();
    assert!(dvrf::verify(record, 0, &evaluation));
    r.bytes("share_bytes", encoded_len(&shares[0].value));
    r.bytes("share_wire_bytes", encoded_len(&shares[0]));
    r.bytes("proof_bytes", encoded_len(&evaluation.proof));
    r.bytes("evaluation_wire_bytes", encoded_len(&evaluation));
    r.repeat("partial_eval", samples, || {
        dvrf::partial_eval(black_box(record), 0, black_box(&keys[0])).unwrap()
    });
    r.repeat("partial_verify", samples, || {
        assert!(dvrf::partial_verify(
            black_box(record),
            0,
            black_box(&shares[0])
        ))
    });
    r.repeat("verify_t_shares", samples, || {
        assert!(shares
            .iter()
            .all(|s| dvrf::partial_verify(black_box(record), 0, black_box(s))))
    });
    r.repeat("combine", samples, || {
        dvrf::combine(black_box(record), 0, black_box(&shares)).unwrap()
    });
    r.repeat("verify", samples, || {
        assert!(dvrf::verify(black_box(record), 0, black_box(&evaluation)))
    });
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 9 {
        eprintln!(
            "usage: dvrf_bench N T BATCH COMMITTEE RUN SAMPLES WORKERS MODE(scale|preprocess|preprocess-sweep)"
        );
        std::process::exit(2);
    }
    let num = |i: usize| args[i].parse::<usize>().expect("positive integer");
    let (n, t, batch, m, run, samples, workers) =
        (num(1), num(2), num(3), num(4), num(5), num(6), num(7));
    assert!(
        n >= 1
            && (n + 1).is_power_of_two()
            && t >= 1
            && t <= n
            && batch > 0
            && m > 0
            && samples > 0
            && workers > 0
            && ["scale", "preprocess", "preprocess-sweep"].contains(&args[8].as_str())
    );
    let mut hash = Sha256::new();
    hash.update(b"SDVRF-experiment-v2");
    hash.update(args[8].as_bytes());
    for x in [n, t, batch, m, run] {
        hash.update((x as u64).to_le_bytes());
    }
    let seed: [u8; 32] = hash.finalize().into();
    let r = Reporter {
        experiment: args[8].clone(),
        n,
        t,
        batch,
        m,
        workers,
        run,
        seed: seed.iter().map(|v| format!("{v:02x}")).collect(),
    };
    let mut rng = StdRng::from_seed(seed);
    println!("experiment,n,t,batch,committee,workers,run,seed,metric,sample,value,unit");
    let (crs, _updates) = r.time("crs_local_updates", || {
        crs::local_ceremony(n + 1, 2, &mut rng).unwrap()
    });
    r.bytes("crs_bytes", encoded_len(&crs));
    let p = r.time("polynomial_encodings", || Parameters::new(crs, t).unwrap());
    let (keys, registrations): (Vec<_>, Vec<_>) = r.time("registration", || {
        (1..=n)
            .map(|i| dvrf::generate_key(&p, i, &mut rng).unwrap())
            .unzip()
    });
    r.bytes("registration_one_bytes", encoded_len(&registrations[0]));
    let pp = Arc::new(r.time("validation", || {
        dvrf::finalize_setup(p, registrations).unwrap()
    }));
    r.bytes("setup_bytes", pp.encoded().len());
    r.bytes("setup_peak_rss_bytes", rss());
    if r.experiment == "scale" {
        assert!(n >= 3);
        assert_eq!(t, n.div_ceil(2));
        assert_eq!((batch, m, workers), (1, 4, 1));
        for threshold in [
            (n + 1).div_ceil(3),
            n.div_ceil(2),
            (2 * (n + 1)).div_ceil(3),
        ] {
            let mut row = r.clone();
            row.t = threshold;
            let changed = Arc::new(row.time("threshold_instance", || {
                pp.with_threshold(threshold).unwrap()
            }));
            let bound: Vec<_> = keys
                .iter()
                .map(|key| key.for_setup(&changed).unwrap())
                .collect();
            let record = prepare(changed, &row, &mut rng);
            online(&record, &bound, &row, samples);
        }
    } else if r.experiment == "preprocess-sweep" {
        assert_eq!((batch, m), (128, 128));
        let sizes = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];
        let mut configurations: Vec<_> = sizes.iter().map(|&b| (b, 128)).collect();
        configurations.extend(sizes.iter().filter(|&&m| m != 128).map(|&m| (128, m)));
        // Reduce confounding by drift across the sweep. Only validated reusable
        // setup is shared: prepare() rebuilds every batch-specific context and
        // table inside its original timed path.
        configurations.shuffle(&mut rng);
        for (batch, committee) in configurations {
            let mut row = r.clone();
            row.experiment = "preprocess".into();
            row.batch = batch;
            row.m = committee;
            let mut hash = Sha256::new();
            hash.update(b"SDVRF-preprocessing-sweep-v1");
            for x in [n, t, batch, committee, run] {
                hash.update((x as u64).to_le_bytes());
            }
            let seed: [u8; 32] = hash.finalize().into();
            row.seed = seed.iter().map(|v| format!("{v:02x}")).collect();
            let mut input_rng = StdRng::from_seed(seed);
            let record = prepare(pp.clone(), &row, &mut input_rng);
            for input in [0, batch / 2, batch - 1] {
                let shares: Vec<_> = keys[..t]
                    .iter()
                    .map(|key| dvrf::partial_eval(&record, input, key).unwrap())
                    .collect();
                let e = dvrf::combine(&record, input, &shares).unwrap();
                assert!(dvrf::verify(&record, input, &e));
            }
            row.row("correctness_checks", 0, 3., "count");
        }
    } else {
        let record = prepare(pp, &r, &mut rng);
        for input in [0, batch / 2, batch - 1] {
            let shares: Vec<_> = keys[..t]
                .iter()
                .map(|key| dvrf::partial_eval(&record, input, key).unwrap())
                .collect();
            let e = dvrf::combine(&record, input, &shares).unwrap();
            assert!(dvrf::verify(&record, input, &e));
        }
    }
    r.bytes("process_peak_rss_bytes", rss());
}
