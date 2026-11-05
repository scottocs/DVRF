# DVRF

Research implementation of **Distributed VRF with Silent Key Generation and Any-Trust Preprocessing**.

**Authors:** Liang Zhang, Xingyu Wu, Haibin Kan, Jiheng Zhang, Moti Yung.

## Construction

The construction adapts the common-value recovery mechanism of Garg et al.'s silent threshold encryption (CRYPTO 2024) to a distributed verifiable random function:

1. **Silent key generation.** Given a reusable powers-of-tau CRS, parties independently generate keys and publish public keys and hints, without receiving shares of a common secret key.
2. **Any-trust preprocessing.** Contributors publish encoded blinding vectors with proofs of knowledge for a fixed public input batch. Public aggregation produces projection data. Pseudorandomness requires one accepted honest contributor to remain uncorrupted until securely erasing its contribution secrets; contributors need not join online evaluation.
3. **Online evaluation.** Parties independently produce evaluation shares. Any threshold-sized set of valid shares yields a witness. A pairing projection maps different valid witnesses to the same output for the fixed input and finalized preprocessing record.

The prototype uses BLS12-381 and arkworks 0.5, with outputs in `G_T` and no output hash. Shares contain one group element; final proofs contain eight.

## Build and test

Requires Rust 1.98.0 and Python 3. Dependencies are pinned in `src/Cargo.lock`.

```sh
cargo test --manifest-path src/Cargo.toml --locked --release
cargo clippy --manifest-path src/Cargo.toml --locked --release --all-targets -- -D warnings
```

Add `--offline` when dependencies are already cached.

## Experiments

Run commands from the repository root. Fetch dependencies first because the experiment runner builds offline. For a fresh campaign, preserve the bundled results before running:

```sh
cargo fetch --manifest-path src/Cargo.toml --locked
mv src/experiments/results "src/experiments/results.saved-$(date +%Y%m%d-%H%M%S)"
python3 src/experiments/run.py
python3 src/experiments/analyze.py
```

To resume, rerun the Python commands without moving results; source, scripts, binary, toolchain, and hardware must match. The bundled results retain an earlier `analyze.py` fingerprint, so the current strict validator rejects that campaign. The commands above start fresh without changing its provenance.

On systems without macOS `sysctl`, run `python3 src/experiments/run.py --host-info path/to/host.json`, supplying verified `cpu`, `memory_bytes`, `physical_cores`, and `logical_cores` fields.

The campaign covers 15–511 parties and up to 1024 inputs or preprocessing contributors. Configurations use three independently seeded processes; online calls use three warmups and 30 samples. Results report medians across processes with minimum–maximum ranges.

## Recorded results

Measurements use an Apple M4 (10 CPU cores, 16 GiB RAM), macOS 26.5.2, and Rust 1.98.0 release builds with thin LTO. Setup and online calls use one thread; preprocessing uses up to eight workers. Values below are from the bundled [summary](src/experiments/results/summary.csv) and [preprocessing results](src/experiments/results/reported-values.json).

Online evaluation at **511 parties, threshold 256**:

| Operation | Median time |
| --- | ---: |
| Generate one share | 0.22 ms |
| Verify one share | 0.69 ms |
| Combine 256 shares, including share verification | 261.76 ms |
| Verify final output and proof | 6.34 ms |

Preprocessing at **255 parties, threshold 128**:

| Inputs | Contributors | Contribute, whole batch | Finalize, whole batch |
| ---: | ---: | ---: | ---: |
| 128 | 256 | 5.43 s | 12.98 s |
| 1024 | 128 | 24.66 s | 53.83 s |
| 128 | 1024 | 20.00 s | 53.10 s |

For 128 inputs and 256 contributors, amortized costs are **42.40 ms** for contribution generation and **101.37 ms** for finalization per input. Contribute includes **all contributors**, context/table preparation, and proof generation; Finalize checks proofs and aggregates vectors. Timings include worker creation/joining and exclude reusable setup, authentication, decoding, network delays, and deadline waiting.

Serialized messages occupy **132 bytes per evaluation share** and **1,088 bytes per final output and proof**, including the 32-byte input tag. Public registration data grow quadratically with the party count.

## Layout

- `src/src/dvrf/`: setup, preprocessing, and online algorithms.
- `src/tests/`: correctness, rejection, and input-binding tests.
- `src/src/bin/dvrf_bench.rs`: benchmark executable.
- `src/experiments/run.py`: complete measurement campaign.
- `src/experiments/analyze.py`: observation validation and statistics generation.
- `src/experiments/results/`: recorded raw data, metadata, summary, and checksums.

## Scope

This is a research prototype. Authentication, checked external decoding, production randomness, and network transport are supplied by callers. The paper's output-privacy, beacon, and anonymous-credential applications are outside this implementation.
