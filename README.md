# SDVRF

Rust implementation of a distributed VRF with silent key generation and any-trust preprocessing, using BLS12-381 and arkworks 0.5.

## Build and test

Requires Rust 1.98.0 and Python 3. Dependencies are pinned in `src/Cargo.lock`.

```sh
cargo test --manifest-path src/Cargo.toml --locked --release
cargo clippy --manifest-path src/Cargo.toml --locked --release --all-targets -- -D warnings
```

Add `--offline` when dependencies are already cached.

## Layout

- `src/src/dvrf/`: setup, preprocessing and online algorithms.
- `src/tests/`: correctness, rejection and input-binding tests.
- `src/src/bin/dvrf_bench.rs`: benchmark executable.
- `src/experiments/run.py`: complete measurement campaign.
- `src/experiments/analyze.py`: validates raw observations and generates statistics.
- `src/experiments/results/`: current raw data, metadata, summary and checksums.

## Reproduce measurements

```sh
python3 src/experiments/run.py
python3 src/experiments/analyze.py
```

On systems without macOS `sysctl`, pass `--host-info path/to/host.json` with verified `cpu`, `memory_bytes`, `physical_cores` and `logical_cores` fields. Results resume only when source, scripts, binary, toolchain and hardware fingerprints match. A fresh implementation requires a fresh results directory.

The campaign uses three independent processes per configuration: Setup and online evaluation at 15–511 parties, and preprocessing at 255 parties with up to 1024 inputs or contributors. Processes run serially. Setup and online algorithms use one thread; preprocessing uses up to eight. Every measured batch includes fresh public context/table preparation and all contributions and proofs. Finalize verifies each proof coordinate separately and aggregates accepted contributions. Online calls use three warmups and 30 timed samples. Reported values are process medians with min/max ranges.

Contribute timings cover **all contributors**, not one contributor. Per-input figures divide total phase wall time by the number of inputs. Setup, network transmission, submission authentication, decoding and deadline waiting are excluded from preprocessing times.

To update the existing paper's inline tables and numeric values:

```sh
python3 src/experiments/analyze.py --paper path/to/DVRF.tex
```

## Scope

This is a research prototype. Callers provide authenticated registrations, contributor identities and finalized submission order. External bytes must pass checked canonical decoding before protocol validation; finalization does not repeat point-membership checks. Production key generation requires an operating-system CSPRNG; benchmark seeds are synthetic fixtures. Distributed communication, chain execution and the application extensions are outside this implementation.
