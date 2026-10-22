#!/usr/bin/env python3
"""Validate current measurements and update only paper tables and numeric values."""
from collections import defaultdict
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import re
import statistics

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / 'experiments/results'
ONLINE = ('partial_eval', 'partial_verify', 'verify_t_shares', 'combine', 'verify')
SETUP = {'crs_local_updates', 'crs_bytes', 'polynomial_encodings', 'registration',
         'registration_one_bytes', 'validation', 'setup_bytes', 'setup_peak_rss_bytes',
         'process_peak_rss_bytes'}
PREPROCESS = {'contribute', 'finalize', 'bundle_one_bytes', 'board_bytes', 'record_bytes', 'image_bytes'}
EVALUATION = {'share_bytes', 'share_wire_bytes', 'proof_bytes', 'evaluation_wire_bytes'}
SIZES = (1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024)
PAIRS = {(b, 128) for b in SIZES} | {(128, m) for m in SIZES}


def configurations():
    return [dict(mode='scale', n=n, t=(n + 1) // 2, inputs=1, members=4, workers=1)
            for n in (15, 31, 63, 127, 255, 511)] + [
        dict(mode='preprocess-sweep', n=255, t=128, inputs=128, members=128, workers=8)]


def fingerprint():
    paths = sorted((ROOT / 'src').rglob('*.rs')) + sorted((ROOT / 'tests').rglob('*.rs'))
    paths += [ROOT / 'Cargo.toml', ROOT / 'Cargo.lock']
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def script_fingerprint():
    return {name: hashlib.sha256((ROOT / 'experiments' / name).read_bytes()).hexdigest()
            for name in ['run.py', 'analyze.py']}


def thresholds(n):
    return ((n + 3) // 3, (n + 1) // 2, (2 * (n + 1) + 2) // 3)


def seed(mode, n, t, b, m, run):
    prefix = b'SDVRF-preprocessing-sweep-v2' if mode == 'preprocess' else b'SDVRF-experiment-v3' + mode.encode()
    return hashlib.sha256(prefix + b''.join(x.to_bytes(8, 'little')
                                          for x in (n, t, b, m, run))).hexdigest()


def read_process(path, config, run, metadata):
    with path.open() as f:
        rows = list(csv.DictReader(f))
    if not rows or rows[-1]['metric'] != 'process_peak_rss_bytes':
        raise ValueError(f'incomplete process: {path}')
    n, t = config['n'], config['t']
    expected = {(config['mode'], t, config['inputs'], config['members'], metric) for metric in SETUP}
    if config['mode'] == 'scale':
        expected |= {('scale', threshold, 1, 4, metric) for threshold in thresholds(n)
                     for metric in PREPROCESS | EVALUATION | set(ONLINE) | {'threshold_instance'}}
    else:
        expected |= {('preprocess', t, b, m, metric) for b, m in PAIRS
                     for metric in PREPROCESS | {'correctness_checks'}}
    groups = defaultdict(list)
    for row in rows:
        mode = row['experiment']
        threshold, b, m = (int(row[k]) for k in ['t', 'batch', 'committee'])
        if (int(row['n']), int(row['run']), int(row['workers'])) != (n, run, config['workers']):
            raise ValueError(f'configuration mismatch: {path}')
        seed_t = t if mode == 'scale' else threshold
        if row['seed'] != seed(mode, n, seed_t, b, m, run):
            raise ValueError(f'seed mismatch: {path}')
        metric = row['metric']
        unit = 'count' if metric == 'correctness_checks' else ('bytes' if metric.endswith('bytes') else 'ms')
        value = float(row['value'])
        if row['unit'] != unit or not math.isfinite(value) or value < 0:
            raise ValueError(f'invalid observation: {path}')
        domain = n + 1
        sizes = {'crs_bytes': 16 + 144 * (domain + 1),
                 'registration_one_bytes': 204 + 48 * domain,
                 'setup_bytes': 48 * domain * domain + 396 * domain + 232,
                 'bundle_one_bytes': 12 + 1504 * b, 'board_bytes': 8 + m * (12 + 1504 * b),
                 'record_bytes': 142 + 16 * m + 688 * b + 1504 * m * b,
                 'image_bytes': 672, 'share_bytes': 96, 'share_wire_bytes': 132,
                 'proof_bytes': 480, 'evaluation_wire_bytes': 544, 'correctness_checks': 3}
        if metric in sizes and value != sizes[metric]:
            raise ValueError(f'size or correctness-check mismatch: {path}, {metric}')
        groups[(mode, threshold, b, m, metric)].append((int(row['sample']), value, unit))
    if set(groups) != expected:
        raise ValueError(f'missing or unexpected metrics: {path}')
    result = {}
    for (mode, threshold, b, m, metric), values in groups.items():
        count = metadata['samples'] if metric in ONLINE else 1
        if sorted(v[0] for v in values) != list(range(count)):
            raise ValueError(f'invalid sample sequence: {path}, {metric}')
        key = (mode, n, threshold, b, m, config['workers'], metric, values[0][2])
        result[key] = statistics.median(v[1] for v in values)
    return result


def load():
    metadata = json.loads((RESULTS / 'metadata.json').read_text())
    if metadata['source_sha256'] != fingerprint() or metadata['scripts_sha256'] != script_fingerprint():
        raise ValueError('working source or scripts differ from the measured version')
    if metadata['configurations'] != configurations() or metadata['runs'] != 3 or metadata['samples'] != 30:
        raise ValueError('unexpected measurement campaign')
    observations = defaultdict(list)
    files = []
    for config in configurations():
        for run in range(3):
            path = RESULTS / 'raw' / f"{config['mode']}-n{config['n']}-r{run}.csv"
            for key, value in read_process(path, config, run, metadata).items():
                observations[key].append(value)
            files.append(path)
    if set((RESULTS / 'raw').glob('*.csv')) != set(files):
        raise ValueError('unexpected raw files in campaign')
    data = {}
    for key, values in observations.items():
        if len(values) != 3 or (key[-1] == 'bytes' and 'rss' not in key[-2] and len(set(values)) != 1):
            raise ValueError(f'inconsistent repetitions: {key}')
        data[key] = (statistics.median(values), min(values), max(values))
    return metadata, data, files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--paper', type=Path, help='also update numeric slots in this paper source')
    args = parser.parse_args()
    metadata, data, files = load()
    with (RESULTS / 'summary.csv').open('w') as f:
        writer = csv.writer(f, lineterminator='\n')
        writer.writerow(['experiment', 'n', 't', 'inputs', 'members', 'workers', 'metric',
                         'unit', 'median', 'min_process_median', 'max_process_median'])
        for key, values in sorted(data.items()):
            writer.writerow([*key, *values])
    def scale(n, t, metric, unit='ms'):
        return data[('scale', n, t, 1, 4, 1, metric, unit)]
    def prep(b, m, metric):
        return data[('preprocess', 255, 128, b, m, 8, metric, 'ms')]
    tables = {}
    def table(name, xname, xs, series):
        columns = [xname]
        for label, _, _ in series:
            columns += [label, label + 'Minus', label + 'Plus']
        lines = [' '.join(columns)]
        for i, x in enumerate(xs):
            row = [str(x)]
            for _, values, divisor in series:
                median, low, high = values[i]
                row += [f'{v / divisor:.12g}' for v in (median, median - low, high - median)]
            lines.append(' '.join(row))
        tables[name] = lines
    ns = [c['n'] for c in configurations() if c['mode'] == 'scale']
    table('ExpSetupData', 'n', ns, [
        (name, [scale(n, (n + 1) // 2, metric, unit) for n in ns], divisor)
        for name, metric, unit, divisor in [
            ('encodings', 'polynomial_encodings', 'ms', 1000), ('registration', 'registration', 'ms', 1000),
            ('validation', 'validation', 'ms', 1000), ('parameters', 'setup_bytes', 'bytes', 1024),
            ('crs', 'crs_bytes', 'bytes', 1024)]])
    table('ExpOnlineData', 'n', ns, [
        (metric + name, [scale(n, thresholds(n)[i], metric) for n in ns], 1)
        for metric in ('combine', 'verify_t_shares')
        for i, name in enumerate(('Low', 'Half', 'High'))])
    table('ExpOnlineSingleData', 'operation', range(3), [
        ('elapsed', [scale(511, 256, metric) for metric in ('partial_eval', 'partial_verify', 'verify')], 1)])
    for name, pairs in [('ExpInputsData', [(b, 128) for b in SIZES]),
                        ('ExpCommitteeData', [(128, m) for m in SIZES])]:
        table(name, 'size', SIZES, [(label, [prep(b, m, metric) for b, m in pairs], 1000)
                                  for label, metric in [('contribute', 'contribute'), ('check', 'finalize')]])
    lines = ['% Generated from the current measurements by analyze.py.']
    for name, value in [('ExpMaxParties', 511), ('ExpBarThreshold', 256),
                        ('ExpPreprocessParties', 255), ('ExpPreprocessThreshold', 128)]:
        lines.append('\\newcommand{\\' + name + '}{' + str(value) + '}')
    for name, rows in tables.items():
        lines += ['', '\\pgfplotstableread[col sep=space,row sep=\\\\]{']
        lines += [row + ' \\\\' for row in rows]
        lines.append('}\\' + name)
    manifest = {str(p.relative_to(RESULTS)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    manifest['metadata.json'] = hashlib.sha256((RESULTS / 'metadata.json').read_bytes()).hexdigest()
    (RESULTS / 'data-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    points = []
    for b, m in [(1024, 128), (128, 1024), (128, 256)]:
        points.append(dict(inputs=b, contributors=m, contribute_seconds=prep(b, m, 'contribute')[0] / 1000,
                           finalize_seconds=prep(b, m, 'finalize')[0] / 1000,
                           contribute_ms_per_input=prep(b, m, 'contribute')[0] / b,
                           finalize_ms_per_input=prep(b, m, 'finalize')[0] / b))
    (RESULTS / 'reported-values.json').write_text(json.dumps(points, indent=2) + '\n')
    if args.paper is None:
        print(f'Validated {len(files)} processes; wrote current statistics and reported values.')
        return
    text = args.paper.read_text()
    begin, end = '% BEGIN GENERATED EXPERIMENT DATA', '% END GENERATED EXPERIMENT DATA'
    if text.count(begin) != 1 or text.count(end) != 1:
        raise ValueError('missing or ambiguous paper data block')
    prefix, rest = text.split(begin)
    _, suffix = rest.split(end)
    text = prefix + begin + '\n' + '\n'.join(lines) + '\n' + end + suffix
    generation = prep(128, 256, 'contribute')[0]
    finalization = prep(128, 256, 'finalize')[0]
    # Replace existing numeric slots only; preserve surrounding paper prose.
    slots = [
        (r'(amortized per-input costs of )[\d.]+(\\,ms for generation and )[\d.]+(\\,ms for finalization)',
         lambda m: f'{m[1]}{generation / 128:.2f}{m[2]}{finalization / 128:.2f}{m[3]}'),
        (r'(share generation and final verification take approximately )[\d.]+( and )[\d.]+( milliseconds)',
         lambda m: f'{m[1]}{scale(511, 256, "partial_eval")[0]:.2f}{m[2]}{scale(511, 256, "verify")[0]:.2f}{m[3]}'),
        (r'(With 1024 inputs and 128 contributors, .*?take )[\d.]+(\\,s and )[\d.]+(\\,s, respectively)',
         lambda m: f'{m[1]}{prep(1024, 128, "contribute")[0] / 1000:.2f}{m[2]}{prep(1024, 128, "finalize")[0] / 1000:.2f}{m[3]}'),
        (r'(With 128 inputs and 1024 contributors, they take )[\d.]+(\\,s and )[\d.]+(\\,s)',
         lambda m: f'{m[1]}{prep(128, 1024, "contribute")[0] / 1000:.2f}{m[2]}{prep(128, 1024, "finalize")[0] / 1000:.2f}{m[3]}'),
        (r'(With 128 inputs and 256 contributors, the median phase times are )[\d.]+(\\,s and )[\d.]+(\\,s, corresponding to amortized per-input costs of )[\d.]+(\\,ms and )[\d.]+(\\,ms, respectively)',
         lambda m: f'{m[1]}{generation / 1000:.2f}{m[2]}{finalization / 1000:.2f}{m[3]}{generation / 128:.2f}{m[4]}{finalization / 128:.2f}{m[5]}')]
    for pattern, replacement in slots:
        text, count = re.subn(pattern, replacement, text)
        if count != 1:
            raise ValueError(f'missing or ambiguous numeric slot: {pattern}')
    args.paper.write_text(text)
    print(f'Validated {len(files)} processes; updated paper tables and existing numeric values.')


if __name__ == '__main__':
    main()
