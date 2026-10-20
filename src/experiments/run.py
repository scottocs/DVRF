#!/usr/bin/env python3
"""Reproduce serial, fresh-process measurements; resume completed configurations."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / 'experiments' / 'raw'

def configurations():
    configs = [dict(experiment='scale', n=n, t=(n+1)//2, batch=1, committee=4, workers=1)
               for n in (15,31,63,127,255,511)]
    pairs = {(b,128) for b in (1,2,4,8,16,32,64,128,256,512,1024)}
    pairs.update((128,m) for m in (1,2,4,8,16,32,64,128,256,512,1024))
    configs += [dict(experiment='preprocess',n=31,t=16,batch=b,committee=m,workers=8) for b,m in sorted(pairs)]
    return configs

def fingerprint():
    paths = sorted((ROOT / 'src').rglob('*.rs')) + sorted((ROOT / 'tests').rglob('*.rs')) + [ROOT / 'Cargo.toml', ROOT / 'Cargo.lock']
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}

def host_info(path):
    if path:
        info = json.loads(Path(path).read_text())
    elif platform.system() == 'Darwin':
        try:
            output = subprocess.check_output(['sysctl', '-n', 'machdep.cpu.brand_string', 'hw.memsize', 'hw.physicalcpu', 'hw.logicalcpu'], text=True, stderr=subprocess.DEVNULL).splitlines()
            info = dict(zip(('cpu', 'memory_bytes', 'physical_cores', 'logical_cores'), output))
            info['hardware_source'] = 'sysctl -n machdep.cpu.brand_string hw.memsize hw.physicalcpu hw.logicalcpu'
        except subprocess.CalledProcessError as error:
            raise SystemExit('Cannot inspect host hardware; supply --host-info with verified host JSON.') from error
    else:
        raise SystemExit('Supply --host-info JSON containing verified cpu, memory_bytes, physical_cores and logical_cores.')
    for key in ('memory_bytes', 'physical_cores', 'logical_cores'):
        info[key] = int(info[key])
        if info[key] <= 0:
            raise ValueError(f'invalid host description: {key}')
    if not isinstance(info['cpu'], str) or not info['cpu']:
        raise ValueError('invalid host description: cpu')
    return info

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runs', type=int, default=3)
    parser.add_argument('--samples', type=int, default=30)
    parser.add_argument('--pilot', action='store_true')
    parser.add_argument('--host-info', help='verified hardware JSON, if sysctl is unavailable')
    args = parser.parse_args()
    if args.runs < 1 or args.samples < 1:
        parser.error('runs and samples must be positive')
    hardware = host_info(args.host_info)
    subprocess.run(['cargo', 'build', '--offline', '--release', '--locked', '--manifest-path', str(ROOT / 'Cargo.toml'), '--bin', 'dvrf_bench'], check=True)
    binary = ROOT / 'target' / 'release' / 'dvrf_bench'
    RAW.mkdir(parents=True, exist_ok=True)
    configs = [dict(experiment='scale',n=31,t=16,batch=1,committee=4,workers=1),dict(experiment='preprocess',n=31,t=16,batch=128,committee=128,workers=8)] if args.pilot else configurations()
    metadata = {'utc_started': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'platform': platform.platform(),
        'machine': platform.machine(), **hardware,
        'rustc': subprocess.check_output(['rustc', '-Vv'], text=True), 'cargo': subprocess.check_output(['cargo', '-V'], text=True).strip(),
        'runs': args.runs, 'online_samples_per_process': args.samples, 'warmups': 3,
        'execution': 'serial processes; Setup/online: 1 thread; Preprocess sweeps: 8 workers; release thin LTO, codegen-units=1; no network',
        'thresholds': 'ceil((n+1)/3), (n+1)/2, ceil(2*(n+1)/3)',
        'setup_reuse': 'one validated registry per scale process; distinct immutable PP instances per threshold',
        'preprocessing_implementation': 'bounded member/input parallelism, exact projective proof equations, 16-input block normalization, parallel public context/table preparation and per-input aggregation, public-workload-adaptive multiplication windows capped at 8 bits; board-order selection remains sequential',
        'preprocessing_worker_budget': 'at most 8 active computation workers; member workers min(8,J), input workers floor(8/member_workers); worker creation/joining included',
        'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'source_sha256': fingerprint(), 'configurations': configs}
    metadata_path = RAW / ('pilot-metadata.json' if args.pilot else 'metadata.json')
    if metadata_path.exists():
        previous = json.loads(metadata_path.read_text())
        for key in ('binary_sha256', 'source_sha256', 'runs', 'online_samples_per_process', 'configurations', 'platform', 'machine', 'cpu', 'memory_bytes', 'physical_cores', 'logical_cores', 'rustc', 'cargo'):
            if previous[key] != metadata[key]:
                raise SystemExit(f'{key} changed; archive old raw data before starting a new campaign')
    else:
        metadata_path.write_text(json.dumps(metadata, indent=2) + '\n')
    started = time.monotonic()
    for config in configs:
        mode,n,t,batch,committee,workers=(config[k] for k in ('experiment','n','t','batch','committee','workers'))
        for run in range(args.runs):
            stem = f'{mode}-n{n}-t{t}-b{batch}-m{committee}-w{workers}-r{run}'
            final = RAW / (('pilot-' if args.pilot else '') + stem + '.csv')
            if final.exists():
                print(f'resume: {final.name}', flush=True)
                continue
            pending = final.with_suffix('.pending')
            wall = time.monotonic()
            with pending.open('w') as output:
                subprocess.run([str(binary), str(n), str(t), str(batch), str(committee), str(run), str(args.samples), str(workers), mode], stdout=output, check=True)
            with pending.open() as f:
                rows = list(csv.DictReader(f))
            if not rows or rows[-1]['metric'] != 'process_peak_rss_bytes':
                raise RuntimeError(f'incomplete process output: {pending}')
            pending.rename(final)
            print(f'done: {final.name} ({time.monotonic()-wall:.1f}s; elapsed {time.monotonic()-started:.1f}s)', flush=True)
    print('Measurement campaign complete.', flush=True)

if __name__ == '__main__':
    main()
