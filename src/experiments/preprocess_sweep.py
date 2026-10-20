#!/usr/bin/env python3
"""Rerun Figure 6 at n=255, T=128 with three serial, independent sweeps."""
import argparse
from collections import defaultdict
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import time

from run import fingerprint, host_info

ROOT = Path(__file__).resolve().parents[1]
CAMPAIGN = ROOT / 'experiments/preprocess255'
SIZES = (1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024)
PAIRS = {(b, 128) for b in SIZES} | {(128, m) for m in SIZES}
PHASE_METRICS = {'contribute', 'check_aggregate', 'bundle_one_bytes',
                 'board_bytes', 'record_bytes', 'image_bytes'}


def read_run(path, run):
    with path.open() as f:
        rows = list(csv.DictReader(f))
    if not rows or rows[-1]['metric'] != 'process_peak_rss_bytes':
        raise ValueError(f'incomplete process: {path}')
    groups = defaultdict(list)
    for row in rows:
        if (int(row['n']), int(row['t']), int(row['workers']), int(row['run'])) != (255, 128, 8, run):
            raise ValueError(f'configuration mismatch: {path}')
        value = float(row['value'])
        if not math.isfinite(value) or value < 0 or int(row['sample']) != 0:
            raise ValueError(f'invalid observation: {path}')
        groups[(row['experiment'], int(row['batch']), int(row['committee']))].append(row)
    expected = {('preprocess', b, m) for b, m in PAIRS} | {('preprocess-sweep', 128, 128)}
    if set(groups) != expected:
        raise ValueError(f'missing or unexpected configurations: {path}')
    setup = groups[('preprocess-sweep', 128, 128)]
    setup_metrics = {'crs_local_updates', 'crs_bytes', 'polynomial_encodings',
                     'registration', 'registration_one_bytes', 'validation',
                     'setup_bytes', 'setup_peak_rss_bytes', 'process_peak_rss_bytes'}
    if len(setup) != len(setup_metrics) or {r['metric'] for r in setup} != setup_metrics:
        raise ValueError(f'incomplete reusable setup: {path}')
    values = {}
    for b, m in PAIRS:
        observations = groups[('preprocess', b, m)]
        if len(observations) != 7 or {r['metric'] for r in observations} != PHASE_METRICS | {'correctness_checks'}:
            raise ValueError(f'incomplete phase measurements: {path}, {(b, m)}')
        seed = hashlib.sha256(b'SDVRF-preprocessing-sweep-v1' + b''.join(
            x.to_bytes(8, 'little') for x in (255, 128, b, m, run))).hexdigest()
        sizes = {'bundle_one_bytes': 108 + 1504*b,
                 'board_bytes': 8 + m*(108 + 1504*b),
                 'record_bytes': 142 + 160*m + 688*b + 1504*m*b,
                 'image_bytes': 672}
        for row in observations:
            metric, value = row['metric'], float(row['value'])
            unit = 'count' if metric == 'correctness_checks' else ('bytes' if metric.endswith('bytes') else 'ms')
            if row['unit'] != unit or row['seed'] != seed:
                raise ValueError(f'incorrect unit or seed: {path}, {metric}')
            if metric == 'correctness_checks':
                if value != 3:
                    raise ValueError(f'correctness checks missing: {path}')
            elif metric in sizes and value != sizes[metric]:
                raise ValueError(f'canonical encoding size mismatch: {path}, {metric}')
            if metric in PHASE_METRICS:
                values[('preprocess', 255, 128, b, m, 8, metric, unit)] = value
    return values


def load_campaign():
    metadata = json.loads((CAMPAIGN / 'metadata.json').read_text())
    if metadata['source_sha256'] != fingerprint():
        raise ValueError('source changed since Figure 6 measurement')
    observations = defaultdict(list)
    files = []
    for run in range(3):
        path = CAMPAIGN / 'raw' / f'sweep-r{run}.csv'
        for key, value in read_run(path, run).items():
            observations[key].append(value)
        files.append(path)
    data = {key: (statistics.median(v), min(v), max(v), len(v))
            for key, v in observations.items()}
    return metadata, data, files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host-info', default=str(ROOT / 'experiments/measurement-host.json'))
    args = parser.parse_args()
    rustc = Path.home() / '.cargo/bin/rustc'
    cargo = Path.home() / '.cargo/bin/cargo'
    env = dict(os.environ, RUSTC=str(rustc))
    subprocess.run([str(cargo), 'build', '--offline', '--release', '--locked',
                    '--manifest-path', str(ROOT / 'Cargo.toml'), '--bin', 'dvrf_bench'],
                   check=True, env=env)
    binary = ROOT / 'target/release/dvrf_bench'
    metadata = dict(
        utc_started=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        platform=platform.platform(), machine=platform.machine(),
        **host_info(args.host_info), runs=3, n=255, t=128, workers=8,
        rustc=subprocess.check_output([str(rustc), '-Vv'], text=True),
        binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        source_sha256=fingerprint(), configurations=[dict(batch=b, committee=m) for b, m in sorted(PAIRS)],
        execution='Three serial independently seeded processes; each validates reusable setup once, '
                  'then measures all 21 batch/committee configurations in seeded shuffled order. '
                  'Each configuration has fresh randomness and rebuilt batch-specific contexts/tables. '
                  'Setup single-threaded; preprocessing at most eight workers. No network.',
        timing='Original prepare() timed paths retained, including shared public context/table preparation, '
               'worker creation/joining, authentication, proof checks and finalization. '
               'Reusable setup and three post-measurement output checks excluded.',
        aggregation='Median of three process observations per phase; min/max ranges; no samples reused from earlier campaigns.')
    (CAMPAIGN / 'raw').mkdir(parents=True, exist_ok=True)
    metadata_path = CAMPAIGN / 'metadata.json'
    if metadata_path.exists():
        previous = json.loads(metadata_path.read_text())
        for key in metadata:
            if key != 'utc_started' and metadata[key] != previous[key]:
                raise ValueError(f'campaign changed: {key}; preserve previous results first')
    else:
        metadata_path.write_text(json.dumps(metadata, indent=2) + '\n')
    for run in range(3):
        final = CAMPAIGN / 'raw' / f'sweep-r{run}.csv'
        if final.exists():
            read_run(final, run)
            print(f'Resuming after completed run {run + 1}/3', flush=True)
            continue
        pending = final.with_suffix('.pending')
        started = time.monotonic()
        with pending.open('w') as output:
            process = subprocess.Popen([str(binary), '255', '128', '128', '128',
                                        str(run), '30', '8', 'preprocess-sweep'], stdout=output)
            previous_count = -1
            while True:
                try:
                    returncode = process.wait(timeout=15)
                    if returncode:
                        raise subprocess.CalledProcessError(returncode, process.args)
                    break
                except subprocess.TimeoutExpired:
                    with pending.open() as progress:
                        completed = sum(r.get('metric') == 'correctness_checks' for r in csv.DictReader(progress))
                    if completed != previous_count:
                        print(f'Run {run + 1}/3: {completed}/21 configurations complete '
                              f'({time.monotonic() - started:.0f}s)', flush=True)
                        previous_count = completed
        read_run(pending, run)
        pending.rename(final)
        print(f'Completed run {run + 1}/3 in {time.monotonic() - started:.1f}s', flush=True)
    _, data, files = load_campaign()
    with (CAMPAIGN / 'summary.csv').open('w') as f:
        writer = csv.writer(f)
        writer.writerow(['experiment', 'n', 't', 'batch', 'committee', 'workers', 'metric',
                         'unit', 'median', 'min_process_median', 'max_process_median', 'processes'])
        for key, values in sorted(data.items()):
            writer.writerow([*key, *values])
    (CAMPAIGN / 'data-manifest.json').write_text(json.dumps(
        {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files}, indent=2) + '\n')
    print('Figure 6 campaign complete: 63 configuration measurements and 189 output checks.', flush=True)


if __name__ == '__main__':
    main()
