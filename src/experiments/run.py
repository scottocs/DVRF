#!/usr/bin/env python3
"""Measure the current implementation in serial, independently seeded processes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import time

from analyze import RESULTS, configurations, fingerprint, read_process, script_fingerprint

ROOT = Path(__file__).resolve().parents[1]


def host_info(path):
    if path:
        info = json.loads(path.read_text())
    else:
        names = ['machdep.cpu.brand_string', 'hw.memsize', 'hw.physicalcpu', 'hw.logicalcpu']
        output = subprocess.check_output(['sysctl', '-n', *names], text=True).splitlines()
        info = dict(zip(('cpu', 'memory_bytes', 'physical_cores', 'logical_cores'), output))
    for name in ['memory_bytes', 'physical_cores', 'logical_cores']:
        info[name] = int(info[name])
        if info[name] <= 0:
            raise ValueError(f'invalid hardware field: {name}')
    if not info['cpu']:
        raise ValueError('missing CPU description')
    return info


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host-info', type=Path, help='verified hardware JSON if sysctl is unavailable')
    args = parser.parse_args()
    env = dict(os.environ)
    rustup = Path.home() / '.cargo/bin'
    if (rustup / 'rustc').exists():
        env['PATH'] = str(rustup) + os.pathsep + env['PATH']
    subprocess.run(['cargo', 'build', '--offline', '--locked', '--release', '--bin', 'dvrf_bench'],
                   cwd=ROOT, env=env, check=True)
    binary = ROOT / 'target/release/dvrf_bench'
    metadata = dict(
        utc_started=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        platform=platform.platform(), **host_info(args.host_info), runs=3, samples=30, warmups=3,
        rustc=subprocess.check_output(['rustc', '-Vv'], env=env, text=True),
        binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        source_sha256=fingerprint(), scripts_sha256=script_fingerprint(),
        configurations=configurations(), bundle_signatures=False, repeated_point_checks=False,
        dvrf_output='G_T pairing projection, without an output hash',
        execution='Serial fresh processes; Setup and online calls use one thread. '
                  'Preprocessing uses at most eight workers. Each sweep validates Setup once '
                  'and visits all 21 configurations in seeded shuffled order. Every measured '
                  'batch starts with empty PP-table caches and includes all public context/table '
                  'preparation, fresh contributions/proofs, and worker creation/joining. '
                  'Finalize checks all eight proof equations independently and aggregates all '
                  'accepted contributions. Authentication, decoding, network and deadline waiting '
                  'are excluded. Three representative online outputs are checked after every '
                  'preprocessing configuration, outside its timers.',
        aggregation='Median across three process observations. Online observations are process '
                    'medians of 30 calls after three warmups. Error ranges are process extrema.')
    raw = RESULTS / 'raw'
    raw.mkdir(parents=True, exist_ok=True)
    meta_path = RESULTS / 'metadata.json'
    if meta_path.exists():
        previous = json.loads(meta_path.read_text())
        if {k: v for k, v in previous.items() if k != 'utc_started'} != {
                k: v for k, v in metadata.items() if k != 'utc_started'}:
            raise ValueError('measurement inputs changed; use a fresh results directory')
    else:
        meta_path.write_text(json.dumps(metadata, indent=2) + '\n')
    for index, config in enumerate(configurations()):
        mode, n, t, b, m, workers = (config[k] for k in
                                   ['mode', 'n', 't', 'inputs', 'members', 'workers'])
        for run in range(3):
            stem = f'{mode}-n{n}-r{run}'
            final = raw / f'{stem}.csv'
            if final.exists():
                read_process(final, config, run, metadata)
                print(f'Resume: {stem}', flush=True)
                continue
            if fingerprint() != metadata['source_sha256'] or script_fingerprint() != metadata['scripts_sha256']:
                raise ValueError('source or measurement scripts changed during the campaign')
            pending = final.with_suffix('.pending')
            started = time.monotonic()
            print(f'Configuration {index + 1}/{len(configurations())}, run {run + 1}/3: {mode}, n={n}', flush=True)
            with pending.open('w') as output:
                process = subprocess.Popen([str(binary), str(n), str(t), str(b), str(m),
                                            str(run), '30', str(workers), mode], stdout=output)
                while True:
                    try:
                        code = process.wait(timeout=30)
                        if code:
                            raise subprocess.CalledProcessError(code, process.args)
                        break
                    except subprocess.TimeoutExpired:
                        print(f'  {stem}: running ({time.monotonic() - started:.0f}s)', flush=True)
            read_process(pending, config, run, metadata)
            pending.rename(final)
            print(f'Completed {stem} in {time.monotonic() - started:.1f}s', flush=True)
    if fingerprint() != metadata['source_sha256'] or script_fingerprint() != metadata['scripts_sha256']:
        raise ValueError('source or measurement scripts changed during the campaign')
    print('Complete: 18 Setup/online processes and 3 preprocessing sweeps.', flush=True)


if __name__ == '__main__':
    main()
