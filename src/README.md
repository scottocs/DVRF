# Core scheduled DVRF

Rust/arkworks implementation of `../paper/DVRF.tex` on BLS12-381. The crate contains the DVRF, correctness/rejection tests, and its benchmark executable. The former PVSS, threshold-encryption and literature-comparison implementations have been removed.

## Build and checks

From `src`:

```sh
cargo test --offline --locked --release
cargo clippy --offline --locked --release --all-targets -- -D warnings
```

Measurements use Rust/Cargo 1.98.0. `Cargo.lock` pins dependencies. Omit `--offline` when fetching dependencies for the first time.

## Paper interfaces

| Paper stage | Library API |
| --- | --- |
| CRS checks and public polynomial encodings | `crs::Crs::validate`, `Parameters::new` |
| Independent party keys and hints | `generate_key` |
| Setup validation and auxiliary data | `finalize_setup`, `validate_setup` |
| Derive + Publish | `PreparedBatch::new_with_workers`, `PreparedBatch::contribute_parallel` (serial reference: `contribute`) |
| Select + Finalize | `PreparedBatch::finalize` (serial reference: `finalize_record`, `validate_record`) |
| Online algorithms | `partial_eval`, `partial_verify`, `combine`, `verify` |

Real deployments must generate each party key independently with an operating-system CSPRNG, such as `rand::rngs::OsRng`. Recorded deterministic seeds in tests/benchmarks are synthetic performance fixtures and do not provide secret keys or protected preprocessing randomness.

The interpolation domain has **exactly** `N=n+1=2^k` positions. Registered party indices are `1..=n`; public auxiliary index `0` has scalar `1` and never counts toward `T`. Both CRS sequences end at degree `N`, the matrix shift is `T+1`, and trapdoors in the interpolation domain are rejected. There is no zero-key padding. A 512-point domain therefore supports `n=511`, **not `n=512`**. The latter requires `N=513`; for the BLS12-381 scalar modulus p, `(p-1) mod 513 = 228`, so no element of order 513 exists. This is also a field constraint, not merely a missing FFT implementation. Truncating a larger published CRS also does not establish the required degree restriction.

All public encodings are derived from CRS group points without knowing the trapdoor. For `i != j`:

```
J_ij = (omega^j L_i - omega^i L_j) / (N (omega^i - omega^j)).
```

Public fixed-base tables accelerate repeated point multiplication in these encodings and input matrices. Preprocessing tables choose windows from the public schedule/committee sizes, capped at eight bits; this trades bounded additional table memory for fewer point additions. Scalar windows are extracted directly from fixed-size integer limbs without allocating bit vectors. They contain public scalar multiples of already public points, not trapdoor scalars or higher-degree CRS powers. `Registration.cross` stores the diagonal `h_{i,3}` and off-diagonal `h_{i,5,j}`. The internal auxiliary cache stores `h_{i,3}K_i`, the product required in Combine.

`PreparedBatch::new_with_workers` binds one immutable validated setup and schedule, checks the schedule, derives full input contexts and public multiplication tables in bounded parallel tasks, and shares only these public data. `new` selects one worker. `contribute_parallel` independently generates each input's image/proof coins in input order, then processes 16-input blocks; each block batch-normalizes images and commitments together. Recorded seeds produce exactly the same bundle bytes as the serial reference, regardless of worker count. Per-input private coins are zeroized on drop before the bundle is authenticated. `PreparedBatch::finalize(board, workers)` checks every submitted group element and every accepted image proof. Eight coordinate equations are compared individually in projective form without affine inversions; no random batching replaces individual proof checks. Verification tasks span bundle/input blocks. Ordered first-complete selection remains sequential, and aggregation is parallel across inputs; workers do not change board order or selection. In particular, an authenticated invalid first complete bundle cannot be replaced by a later valid one. Aggregation uses projective accumulators and one final batch normalization per source group. The original serial routines remain as a compatibility path and independent differential-test reference.

`ValidatedSetup::with_threshold(T)` creates a **new Setup instance** from the same validated threshold-independent CRS, registrations and auxiliary data. It changes the full PP encoding, identifier and input contexts, and never mutates a pinned record. `SecretKey::for_setup` rebinds a key only when the matching public key is already registered in that validated instance. These APIs do not preserve old DVRF outputs or update an existing authenticated instance. The benchmark uses them to avoid redundantly deriving/checking the same public hints for each threshold; it still generates and checks fresh preprocessing for each new PP.

Input hashing binds the complete typed encoding of PP, schedule and input. SHA-256 XMD/SSWU maps directly to G2; a public scalar hash times the generator is not substituted. Merlin transcripts bind the Fiat–Shamir statement, identity, image and commitment. Output hashing binds the full context and pairing target. Bundle BLS authentication has independent committee keys and a separate hash domain. Canonical decoding checks membership and rejects trailing data. Transport data must pass `validate_setup` / `validate_record` before entering the online API. Combine checks exactly T distinct registered shares; Verify checks all five rows separately and then the eight-coordinate image projection.

## Trust boundary

The local CRS update helper performs real public point/proof checks and retains the public transcript without an aggregate trapdoor scalar. It is not a distributed implementation of NRBB communication, agreement or transcript authentication. Audit its updates from the trusted `Crs::initial` transcript in order. A final consistency check alone does not establish an honest update or erasure.

Authenticated registrations, schedule, frozen complete board order and deadline/release policy are supplied externally. Bundle signatures establish neither board completeness nor consensus. Online callers must pin authenticated PP/record identifiers. Transport size/resource bounds and production secret storage/side-channel protection remain outside the prototype. Sensitive stored scalars and contribution vectors are zeroized, but no verified physical-erasure environment is implemented. Tests and timings do not establish the paper's conditional hiding/proof-composition assumptions. Application extensions and network/chain execution are not part of this artifact.

## Reproduce the expanded experiments

From the repository root:

```sh
python3 src/experiments/preprocess_sweep.py
python3 src/experiments/analyze.py
```

On a different host, archive the provided raw measurements first. Hardware is detected with `sysctl` on macOS. Where unavailable, supply `--host-info` with independently verified host JSON; `src/experiments/measurement-host.json` describes the recorded M4 host. The runner checks source/binary fingerprints, toolchain, hardware and configurations before resuming, and rejects incompatible data. Independent experiment processes run serially.

Figures 4--5 retain the original scale measurements from `experiments/raw`: `n=15,31,63,127,255,511`, with three independent processes per scale. Each process performs a complete one-thread Setup, then measures three distinct threshold instances: `T=ceil((n+1)/3), (n+1)/2, ceil(2(n+1)/3)`. Preprocessing has one input/four members/one worker; every online operation uses one thread, three untimed calls and 30 timed calls. Threshold instances reuse validated registrations, not preprocessing images or output contexts. Their original driver is preserved byte-for-byte at `experiments/archive/dvrf_bench-v2.rs` and checked against the original metadata fingerprint. The original `experiments/run.py` runner is retained with that campaign.

Figure 6 is fully remeasured at **n=255, T=128**, using `experiments/preprocess_sweep.py`. Results, source/executable fingerprints and metadata are stored separately in `experiments/preprocess255`. Three fresh independently seeded processes run serially. Each validates reusable setup once and then measures all 21 distinct configurations in seeded shuffled order:

- Inputs: `|J|=128`, varying `|D|=1,2,4,8,16,32,64,128,256,512,1024`.
- Committee: `|D|=128`, varying `|J|=1,2,4,8,16,32,64,128,256,512,1024`. The shared `(128,128)` case is measured once per process.

Only validated reusable setup is shared across configurations. Every configuration rebuilds its own batch-specific contexts and public multiplication tables within the original timed `prepare()` path, and generates fresh committee keys, image randomness and proofs. Setup and the three post-measurement reconstruction checks are excluded from preprocessing times. Each point therefore has three process observations (63 configuration measurements in total), with median and min/max range. No earlier single-point supplemental timing or n=31 preprocessing sample is reused for Figure 6. Historical n=31 files remain available for provenance but are not plotted.

Both preprocessing sweeps use up to eight contribution/checking workers and measure the **entire batch**. The largest points each generate and check 131072 distinct image contributions and knowledge proofs. **Derive + Publish** includes shared public context/table construction, fresh coins/proofs, authentication and worker creation/joining. **Select + Finalize** includes complete membership/proof/authentication checks, deterministic ordered selection, and all aggregate images. The raw CSV metric names remain `contribute` and `check_aggregate`, respectively. A fixed worker budget is divided across members and input blocks; there are at most eight active computation workers. Small committees can therefore use input-level parallelism, while large committees distribute members across workers. All designated contributions are valid in the workload; malformed behavior is covered by tests. No batch is replaced by extrapolation or by repeated copies of one proof. Representative online reconstructions at first/middle/last input also check the resulting record.

Manual invocation (n, initial T, inputs, committee, run, online samples, workers, mode):

```sh
src/target/release/dvrf_bench 511 256 1 4 0 30 1 scale
src/target/release/dvrf_bench 255 128 128 1024 0 30 8 preprocess
src/target/release/dvrf_bench 255 128 128 128 0 30 8 preprocess-sweep
```

`scale` requires initial `T=(n+1)/2` and measures all three thresholds after one complete Setup; `preprocess` measures one fixed (T,D,J) and verifies representative resulting evaluations. `preprocess-sweep` requires initial inputs/committee `(128,128)` and measures all 21 Figure 6 configurations after one validated Setup. Long-form CSV goes to stdout. All timings use `std::time::Instant`, excluding CSV output, and are elapsed times rather than OS CPU accounting. Peak RSS is a process-wide high-water mark from `getrusage`. Compressed serialization is streamed into a counting writer and checked against the serializer's exact size, avoiding a second full-record memory copy.

The analysis uses only the Python standard library and validates all sample sequences, metric sets, source hashes, file identities, repetition counts and invariant encoding sizes. It first takes each process's online median, then the median over three processes. Ranges/error bars are the extrema of those three process medians, not confidence intervals. It retains raw observations, produces `summary.csv` and a SHA-256 data manifest, and embeds full-precision PGFPlots tables and numeric macros in the delimited experiment-data block in `paper/DVRF.tex`. All plot definitions, styles and data are inline in that main file. The paper draws every experimental figure natively with `pgfplots` (TeX Live); no external data table, plot image, included plotting `.tex` file, or Python plotting package is needed. Plot text uses the document's normal font size, and subfigures have cross-reference labels. Compile with `latexmk -pdf DVRF.tex` from `paper/` after regenerating the data. Figure 5 contains Combine, its separately measured T PartialVerify calls (already included in Combine), and bars for individual PartialEval/PartialVerify/Verify at n=511,T=256. Figure 6 gives full-batch elapsed times, not per-input-normalized times. There are no literature baselines, lifecycle heatmaps, success-rate figures, or application-overhead benchmarks.

Compressed sizes: G1=48, G2=96, Fr=32 bytes. A share is 96 bytes (132 with index/context ID); a witness is six G1 and two G2 elements, 480 bytes (544 including context ID and output). An image is 672 bytes and an image proof 832 bytes. Full retained records include schedule/credentials, every authenticated bundle and proof, and the aggregate image table, excluding only the separately stored PP.

The previous measured implementation and its 81 CSV files, source snapshot, paper and executable are retained in `experiments/archive/pre-optimization-20261015.tar.gz`. The raw directory retains the subsequent original full campaign. The new `preprocess255` directory contains the replacement Figure 6 campaign, with its own fingerprints. Archived measurements are excluded from analysis; the archived v2 driver only authenticates the provenance of the retained Figures 4--5 data.
