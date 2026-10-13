#!/usr/bin/env python3
"""Randomized paired, CPU-pinned original/control/GS microbenchmarks."""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shutil
import statistics as stats
import subprocess

ROOT=Path(__file__).resolve().parent
VARIANTS={'original':('original','native'),'reencoded':('reencoded','native'),
          'gs_zero':('rewritten','zero'),'gs_shift':('rewritten','shift')}

def run(variant,kernel,size,rounds,cpu):
    binary,mode=VARIANTS[variant]
    env=os.environ.copy()
    if kernel=='rep_movsb':
        env['GSFORK_REP_WRAPPED']='1' if variant in ('gs_zero','gs_shift') else '0'
    p=subprocess.run([str(ROOT/'build'/binary),kernel,mode,str(size),str(rounds),str(cpu)],capture_output=True,text=True,check=True,timeout=60,env=env)
    r=json.loads(p.stdout)
    if not r['verified']: raise RuntimeError(r)
    return dict(variant=variant,**r)

def read(path):
    try: return Path(path).read_text()
    except OSError: return None

def ci_median(values,rng):
    n=len(values)
    draws=sorted(stats.median(rng.choices(values,k=n)) for _ in range(5000))
    return [draws[125],draws[4874]]

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--samples',type=int,default=31)
    p.add_argument('--target-ms',type=float,default=80)
    p.add_argument('--cpu',type=int,default=None)
    p.add_argument('--output',type=Path,default=ROOT/'results')
    a=p.parse_args()
    if a.samples<5 or a.target_ms<10: p.error('need >=5 samples and >=10 ms')
    a.output.mkdir(parents=True,exist_ok=True)
    allowed=sorted(os.sched_getaffinity(0))
    cpu=allowed[len(allowed)//2] if a.cpu is None else a.cpu
    rng=random.Random(20261006)
    env={'date_utc':datetime.now(timezone.utc).isoformat(),'platform':platform.platform(),
         'cpuinfo':read('/proc/cpuinfo'),'lscpu':subprocess.check_output(['lscpu'],text=True),
         'compiler':subprocess.check_output(['gcc','--version'],text=True),
         'affinity_available':allowed,'cpu_used':cpu,'samples':a.samples,'target_ms':a.target_ms,
         'cgroup_cpu_max':read('/sys/fs/cgroup/cpu.max'),
         'cgroup_cpu_stat_before':read('/sys/fs/cgroup/cpu.stat'),
         'perf_available':shutil.which('perf') is not None,'hardware_counters_collected':False,'random_seed':20261006,
         'binary_sha256':{b:hashlib.sha256((ROOT/'build'/b).read_bytes()).hexdigest() for b in ('original','reencoded','rewritten')}}
    (a.output/'environment.json').write_text(json.dumps(env,indent=2)+'\n')
    cases=[(k,s) for k in ('sum','update','avx2','chase','rep_movsb') for s in (32768,8*1024*1024)]
    raw=[]; summary=[]
    with (a.output/'samples.jsonl').open('w') as log:
        for kernel,size in cases:
            rounds=1
            for _ in range(8):
                calibration=run('original',kernel,size,rounds,cpu)
                elapsed=calibration['thread_ns']
                if elapsed>=20_000_000: break
                rounds=max(rounds+1,min(rounds*100,round(rounds*30_000_000/max(1,elapsed))))
            rounds=max(1,round(rounds*a.target_ms*1e6/elapsed))
            paired=[]
            for sample in range(a.samples):
                names=list(VARIANTS); rng.shuffle(names)
                pair={}
                for order,variant in enumerate(names):
                    row=dict(sample=sample,order=order,**run(variant,kernel,size,rounds,cpu))
                    log.write(json.dumps(row)+'\n'); log.flush()
                    pair[variant]=row; raw.append(row)
                assert len({x['checksum'] for x in pair.values()})==1
                paired.append(pair)
            item={'kernel':kernel,'bytes':size,'rounds':rounds,'samples':a.samples,'variants':{}}
            for variant in VARIANTS:
                values=[pair[variant]['wall_ns'] for pair in paired]
                ratios=[pair[variant]['wall_ns']/pair['original']['wall_ns'] for pair in paired]
                cpu_ratios=[pair[variant]['thread_ns']/pair['original']['thread_ns'] for pair in paired]
                item['variants'][variant]={'median_wall_ns':stats.median(values),
                    'median_thread_ns':stats.median(pair[variant]['thread_ns'] for pair in paired),
                    'wall_ratio':stats.median(ratios),'wall_ratio_ci95':ci_median(ratios,rng),
                    'thread_ratio':stats.median(cpu_ratios),
                    'median_ns_per_element':stats.median(values)/(rounds*size/(2 if kernel=='rep_movsb' else (16 if kernel=='chase' else 8)))}
            summary.append(item)
            (a.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
            print(f"{kernel:8s} {size//1024:5d} KiB: zero {item['variants']['gs_zero']['wall_ratio']:.4f}x, shift {item['variants']['gs_shift']['wall_ratio']:.4f}x, control {item['variants']['reencoded']['wall_ratio']:.4f}x",flush=True)
    with (a.output/'samples.csv').open('w') as f:
        writer=csv.DictWriter(f,fieldnames=list(raw[0])); writer.writeheader(); writer.writerows(raw)
    env['cgroup_cpu_stat_after']=read('/sys/fs/cgroup/cpu.stat')
    (a.output/'environment.json').write_text(json.dumps(env,indent=2)+'\n')
    rows=['| Kernel | Data | Original ns/element (REP: ns/byte copied) | GS=0 overhead | GS=1 TiB overhead (95% CI) | Re-encode control |',
          '|---|---:|---:|---:|---:|---:|']
    for s in summary:
        v=s['variants']; lo,hi=v['gs_shift']['wall_ratio_ci95']
        rows.append(f"| {s['kernel']} | {s['bytes']//1024:,} KiB | {v['original']['median_ns_per_element']:.3f} | {(v['gs_zero']['wall_ratio']-1)*100:+.2f}% | {(v['gs_shift']['wall_ratio']-1)*100:+.2f}% [{(lo-1)*100:+.2f}%, {(hi-1)*100:+.2f}%] | {(v['reencoded']['wall_ratio']-1)*100:+.2f}% |")
    (a.output/'table.md').write_text('\n'.join(rows)+'\n')

if __name__=='__main__': main()
