#!/usr/bin/env python3
"""Supplement the paper's preprocessing measurements at n=255, T=128."""
import csv
import hashlib
import json
from pathlib import Path
import platform
import statistics
import subprocess
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BINARY = ROOT / 'target/release/dvrf_bench'
CONFIG = dict(experiment='preprocess', n=255, t=128, batch=128,
              committee=256, workers=8)


def main():
    original = json.loads((ROOT / 'experiments/raw/metadata.json').read_text())
    binary_hash = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    if binary_hash != original['binary_sha256']:
        raise ValueError('benchmark binary differs from original campaign')
    for name, expected in original['source_sha256'].items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != expected:
            raise ValueError(f'benchmark source changed: {name}')
    metadata_path = HERE / 'metadata.json'
    if metadata_path.exists():
        metadata = json.loads(metadata_path.read_text())
        if metadata['configuration'] != CONFIG or metadata['binary_sha256'] != binary_hash:
            raise ValueError('supplemental campaign changed')
    else:
        metadata = dict(
            utc_started=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            platform=platform.platform(), configuration=CONFIG, runs=3,
            binary_sha256=binary_hash, source_sha256=original['source_sha256'],
            hardware={key: original[key] for key in
                      ('cpu', 'memory_bytes', 'physical_cores', 'logical_cores')},
            hardware_verification='Rechecked using sysctl before this campaign.',
            execution=original['execution'],
            timing='Same contribute and check_aggregate paths as original campaign; '
                   'shared preparation, worker creation/joining, authentication and '
                   'finalization included; reusable setup excluded from preprocessing.',
            aggregation='Median across three independently seeded fresh processes; '
                        'per-input costs are batch phase medians divided by 128.')
        metadata_path.write_text(json.dumps(metadata, indent=2) + '\n')
    files = []
    for run in range(3):
        final = HERE / f'preprocess-n255-t128-b128-m256-w8-r{run}.csv'
        if not final.exists():
            pending = final.with_suffix('.pending')
            started = time.monotonic()
            with pending.open('w') as output:
                subprocess.run([str(BINARY), '255', '128', '128', '256',
                                str(run), '30', '8', 'preprocess'],
                               stdout=output, check=True)
            with pending.open() as f:
                rows = list(csv.DictReader(f))
            if not rows or rows[-1]['metric'] != 'process_peak_rss_bytes':
                raise ValueError(f'incomplete measurement: {pending}')
            pending.rename(final)
            print(f'Completed run {run + 1}/3 in {time.monotonic() - started:.1f}s', flush=True)
        files.append(final)
    summary = []
    for metric in ('contribute', 'check_aggregate'):
        values = []
        for run, path in enumerate(files):
            with path.open() as f:
                rows = list(csv.DictReader(f))
            if any((r['experiment'], int(r['n']), int(r['t']), int(r['batch']),
                    int(r['committee']), int(r['workers']), int(r['run'])) !=
                   ('preprocess', 255, 128, 128, 256, 8, run) for r in rows):
                raise ValueError(f'configuration mismatch: {path}')
            measurements = [r for r in rows if r['metric'] == metric]
            if len(measurements) != 1 or measurements[0]['unit'] != 'ms':
                raise ValueError(f'missing phase timing: {path}')
            values.append(float(measurements[0]['value']))
        summary.append(dict(metric=metric, unit='ms', processes=3,
                            median=statistics.median(values), minimum=min(values),
                            maximum=max(values),
                            per_input_median=statistics.median(values) / 128))
    with (HERE / 'summary.csv').open('w') as f:
        writer = csv.DictWriter(f, fieldnames=list(summary[0]))
        writer.writeheader()
        writer.writerows(summary)
    (HERE / 'data-manifest.json').write_text(json.dumps(
        {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
        indent=2) + '\n')
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == '__main__':
    main()
