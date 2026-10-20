#!/usr/bin/env python3
"""Validate core-only measurements and update inline paper data and numbers."""
import argparse
from collections import defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path
import statistics

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / 'experiments' / 'raw'
PAPER = ROOT.parent / 'paper' / 'DVRF.tex'
TABLE_MACROS = {
    'setup': 'ExpSetupData',
    'online': 'ExpOnlineData',
    'online-single': 'ExpOnlineSingleData',
    'inputs': 'ExpInputsData',
    'committee': 'ExpCommitteeData',
}
ONLINE = ('partial_eval','partial_verify','verify_t_shares','combine','verify')
ROOT_METRICS = {'crs_local_updates','crs_bytes','polynomial_encodings','registration','registration_one_bytes','validation','setup_bytes','setup_peak_rss_bytes','process_peak_rss_bytes'}
PREP_METRICS = {'contribute','check_aggregate','bundle_one_bytes','board_bytes','record_bytes','image_bytes'}
EVAL_SIZES = {'share_bytes','share_wire_bytes','proof_bytes','evaluation_wire_bytes'}

def thresholds(n):
    return ((n+3)//3, (n+1)//2, (2*(n+1)+2)//3)

def load(partial):
    meta = json.loads((RAW/'metadata.json').read_text())
    for name, expected in meta['source_sha256'].items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest() != expected:
            # The archived v2 driver produced the original setup/online data.
            # The new driver only adds a sweep mode; all library sources must
            # still match their original fingerprints.
            archived = ROOT/'experiments/archive/dvrf_bench-v2.rs'
            if (name != 'src/bin/dvrf_bench.rs' or not archived.exists()
                    or hashlib.sha256(archived.read_bytes()).hexdigest() != expected):
                raise ValueError(f'source changed since measurement: {name}')
    samples = defaultdict(list)
    files = sorted([*RAW.glob('scale-*.csv'), *RAW.glob('preprocess-*.csv')])
    seen = set()
    for path in files:
        with path.open() as f:
            rows = list(csv.DictReader(f))
        if not rows or rows[-1]['metric'] != 'process_peak_rss_bytes':
            raise ValueError(f'incomplete file: {path}')
        identities = {(r['experiment'], *(int(r[k]) for k in ('n','batch','committee','workers','run')), r['seed']) for r in rows}
        if len(identities) != 1:
            raise ValueError(f'mixed process identifiers: {path}')
        mode,n,b,m,w,run,seed = identities.pop()
        identity = (mode,n,b,m,w,run)
        if identity in seen or not 0 <= run < meta['runs']:
            raise ValueError(f'duplicate or invalid run: {path}')
        seen.add(identity)
        configs = [c for c in meta['configurations'] if (c['experiment'],c['n'],c['batch'],c['committee'],c['workers']) == (mode,n,b,m,w)]
        if len(configs) != 1:
            raise ValueError(f'unexpected configuration: {path}')
        t = configs[0]['t']
        groups = defaultdict(list)
        for r in rows:
            value = float(r['value'])
            if not math.isfinite(value) or value < 0:
                raise ValueError(f'invalid measurement: {path}')
            groups[(int(r['t']),r['metric'],r['unit'])].append((int(r['sample']),value))
        expected = {(t,metric) for metric in ROOT_METRICS}
        if mode == 'scale':
            expected.update((threshold,metric) for threshold in thresholds(n) for metric in PREP_METRICS | EVAL_SIZES | set(ONLINE) | {'threshold_instance'})
        else:
            expected.update((t,metric) for metric in PREP_METRICS)
        if {(t,metric) for t,metric,unit in groups} != expected:
            raise ValueError(f'missing or extra metrics: {path}')
        for (t,metric,unit), values in groups.items():
            count = meta['online_samples_per_process'] if metric in ONLINE else 1
            if sorted(i for i,_ in values) != list(range(count)):
                raise ValueError(f'incorrect sample sequence: {path}, {metric}')
            required_unit = 'bytes' if metric.endswith('bytes') else 'ms'
            if unit != required_unit:
                raise ValueError(f'incorrect unit: {path}, {metric}')
            # Exact canonical sizes for the fixed v2 benchmark header and
            # 8-byte labels. Check observed streamed encodings against the
            # paper's point/scalar counts, including every retained bundle.
            domain = n+1
            exact_sizes = {
                'crs_bytes':16+144*(domain+1),
                'registration_one_bytes':204+48*domain,
                'setup_bytes':48*domain*domain+396*domain+232,
                'bundle_one_bytes':108+1504*b,
                'board_bytes':8+m*(108+1504*b),
                'record_bytes':142+160*m+688*b+1504*m*b,
                'image_bytes':672,'share_bytes':96,'share_wire_bytes':132,
                'proof_bytes':480,'evaluation_wire_bytes':544,
            }
            if metric in exact_sizes and any(v != exact_sizes[metric] for _,v in values):
                raise ValueError(f'canonical encoding size mismatch: {path}, {metric}')
            key = (mode,n,t,b,m,w,metric,unit)
            samples[key].append((run,statistics.median(v for _,v in values)))
    if not partial and len(files) != len(meta['configurations'])*meta['runs']:
        raise ValueError('campaign incomplete')
    result = {}
    for key,observations in samples.items():
        if not partial and sorted(r for r,_ in observations) != list(range(meta['runs'])):
            raise ValueError(f'missing process repetition: {key}')
        values = [v for _,v in observations]
        if key[-1] == 'bytes' and 'rss' not in key[-2] and len(set(values)) != 1:
            raise ValueError(f'encoding size varies between repetitions: {key}')
        result[key] = (statistics.median(values),min(values),max(values),len(values))
    from preprocess_sweep import CAMPAIGN, load_campaign
    if (CAMPAIGN/'metadata.json').exists():
        sweep_meta, sweep_data, sweep_files = load_campaign()
        result.update(sweep_data)
        files.extend(sweep_files)
        meta['preprocess_n'] = sweep_meta['n']
        meta['preprocess_t'] = sweep_meta['t']
    else:
        meta['preprocess_n'], meta['preprocess_t'] = 31,16
    return meta,result,files

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allow-partial',action='store_true')
    args=parser.parse_args()
    meta,data,files=load(args.allow_partial)
    prep_n,prep_t=meta['preprocess_n'],meta['preprocess_t']
    with (ROOT/'experiments'/'summary.csv').open('w') as f:
        writer=csv.writer(f)
        writer.writerow(['experiment','n','t','batch','committee','workers','metric','unit','median','min_process_median','max_process_median','processes'])
        for key,values in sorted(data.items()):writer.writerow([*key,*values])
    def get(mode,n,t,b,m,w,metric,unit='ms'):
        return data[(mode,n,t,b,m,w,metric,unit)]
    def scale(n,t,metric,unit='ms'):
        return get('scale',n,t,1,4,1,metric,unit)
    def prep(b,m,metric,unit='ms'):
        return get('preprocess',prep_n,prep_t,b,m,8,metric,unit)
    # Embed measured values and asymmetric ranges at full precision. PGFPlots
    # draws every experimental figure from tables in the main LaTeX file.
    tables = {}
    def table(name, xname, xs, series):
        columns = [xname]
        for label, _, _ in series:
            columns.extend((label, label+'Minus', label+'Plus'))
        lines = [' '.join(columns)]
        for index, x in enumerate(xs):
            row = [str(x)]
            for _, values, divisor in series:
                median, lower, upper, _ = values[index]
                row.extend(f'{v/divisor:.12g}' for v in
                           (median, median-lower, upper-median))
            lines.append(' '.join(row))
        tables[name] = lines

    ns=[c['n'] for c in meta['configurations'] if c['experiment']=='scale']
    if all(('scale',n,(n+1)//2,1,4,1,'validation','ms') in data for n in ns):
        table('setup', 'n', ns, [
            (name, [scale(n,(n+1)//2,metric,unit) for n in ns], divisor)
            for name,metric,unit,divisor in [
                ('encodings','polynomial_encodings','ms',1000),
                ('registration','registration','ms',1000),
                ('validation','validation','ms',1000),
                ('parameters','setup_bytes','bytes',1024),
                ('crs','crs_bytes','bytes',1024)]])
    if all(('scale',n,t,1,4,1,'verify','ms') in data for n in ns for t in thresholds(n)):
        table('online', 'n', ns, [
            (metric+name, [scale(n,thresholds(n)[i],metric) for n in ns], 1)
            for metric in ('combine','verify_t_shares')
            for i,name in enumerate(('Low','Half','High'))])
        n=max(ns);t=(n+1)//2
        table('online-single', 'operation', range(3), [
            ('elapsed', [scale(n,t,metric) for metric in
                         ('partial_eval','partial_verify','verify')], 1)])
    sizes=[1,2,4,8,16,32,64,128,256,512,1024]
    for name, pairs in [('inputs', [(b,128) for b in sizes]),
                        ('committee', [(128,m) for m in sizes])]:
        if all(('preprocess',prep_n,prep_t,b,m,8,'check_aggregate','ms') in data for b,m in pairs):
            table(name, 'size', sizes, [
                (label, [prep(b,m,metric) for b,m in pairs], 1000)
                for label,metric in [('contribute','contribute'),
                                     ('check','check_aggregate')]])
    required=[('scale',max(ns),(max(ns)+1)//2,1,4,1,'validation','ms'),('preprocess',prep_n,prep_t,1024,128,8,'check_aggregate','ms'),('preprocess',prep_n,prep_t,128,1024,8,'check_aggregate','ms'),('preprocess',prep_n,prep_t,1,128,8,'check_aggregate','ms'),('preprocess',prep_n,prep_t,128,1,8,'check_aggregate','ms')]
    paper_updated = False
    if all(k in data for k in required) and tables.keys() == TABLE_MACROS.keys():
        n=max(ns);t=(n+1)//2
        macros={'ExpMaxParties':n, 'ExpBarThreshold':t,
                'ExpPreprocessParties':prep_n, 'ExpPreprocessThreshold':prep_t}
        lines=['% Generated from the core-only raw measurements by analyze.py.']
        for name,value in macros.items():
            formatted=str(value)
            lines.append('\\newcommand{\\'+name+'}{'+formatted+'}')
        for name, macro in TABLE_MACROS.items():
            lines.extend(('', '\\pgfplotstableread[col sep=space,row sep=\\\\]{'))
            lines.extend(row+' \\\\' for row in tables[name])
            lines.append('}\\'+macro)
        begin = '% BEGIN GENERATED EXPERIMENT DATA'
        end = '% END GENERATED EXPERIMENT DATA'
        text = PAPER.read_text()
        if text.count(begin) != 1 or text.count(end) != 1:
            raise ValueError('missing or ambiguous experiment-data block in DVRF.tex')
        prefix, rest = text.split(begin)
        _, suffix = rest.split(end)
        PAPER.write_text(prefix+begin+'\n'+'\n'.join(lines)+'\n'+end+suffix)
        paper_updated = True
    manifest={str(p.relative_to(ROOT/'experiments')):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    (ROOT/'experiments'/'data-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    status = 'updated inline paper tables and numbers' if paper_updated else 'kept existing paper data (campaign incomplete)'
    print(f'Validated {len(files)} processes; wrote statistics and {status}.')

if __name__=='__main__':main()
