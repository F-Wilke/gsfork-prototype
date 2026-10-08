#!/usr/bin/env python3
"""Kernel-region perf stat/record, calibrated paired comparisons, and size sweeps."""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import re
import shlex
import shutil
import statistics
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
VARIANTS = {
    'original': ('original', 'native'),
    'reencoded': ('reencoded', 'native'),
    'gs_zero': ('rewritten', 'zero'),
    'gs_shift': ('rewritten', 'shift'),
    'original_child': ('original', 'direct'),
    'gs_zero_child': ('rewritten', 'direct'),
}
DEFAULT_EVENTS = 'cycles:u,instructions:u,branches:u,branch-misses:u'
DEFAULT_SIZES = '8K,16K,32K,64K,256K,1M,8M,64M'


def size_bytes(text):
    m = re.fullmatch(r'(\d+)([KMGT]?)(?:i?B)?', text.strip(), re.I)
    if not m:
        raise argparse.ArgumentTypeError('use bytes or a size such as 32K, 8MiB')
    value = int(m[1]) * 1024 ** ('KMGT'.index(m[2].upper()) + 1 if m[2] else 0)
    if value < 4096 or value > 256 * 1024**2 or value % 4096:
        raise argparse.ArgumentTypeError('size must be a multiple of 4 KiB, between 4 KiB and 256 MiB')
    return value


def variants(text):
    names = text.split(',')
    if not names or len(set(names)) != len(names) or any(x not in VARIANTS for x in names):
        raise argparse.ArgumentTypeError('variants: ' + ','.join(VARIANTS))
    return names


def text_file(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def machine(cpu):
    caches = []
    for cache in sorted(Path(f'/sys/devices/system/cpu/cpu{cpu}/cache').glob('index*')):
        caches.append({k: text_file(cache / k) for k in ('level', 'type', 'size', 'shared_cpu_list')})
    return {'date_utc': datetime.now(timezone.utc).isoformat(), 'platform': platform.platform(),
            'cpuinfo': text_file('/proc/cpuinfo'), 'cpu': cpu,
            'affinity_available': sorted(os.sched_getaffinity(0)), 'cache_sysfs': caches,
            'perf_event_paranoid': text_file('/proc/sys/kernel/perf_event_paranoid'),
            'cgroup_cpu_max': text_file('/sys/fs/cgroup/cpu.max')}


def harness_cmd(binary, variant, kernel, size, rounds, cpu, mapping):
    return [str(binary), kernel, VARIANTS[variant][1], str(size), str(rounds), str(cpu), '--mapping', mapping]


def checked_harness(command, timeout):
    env = dict(os.environ)
    env.pop('GSFORK_PERF_CTL', None)
    env.pop('GSFORK_PERF_ACK', None)
    p = subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=env)
    if p.returncode:
        raise RuntimeError(f'harness failed ({p.returncode}): {p.stderr.strip()}')
    r = json.loads(p.stdout)
    if not r['verified']:
        raise RuntimeError('correctness verification failed')
    return r


def calibrate(kernel, size, cpu, mapping, seconds):
    rounds = 1
    for _ in range(8):
        r = checked_harness(harness_cmd(ROOT / 'build/original', 'original', kernel, size, rounds, cpu, mapping), 60)
        elapsed = r['thread_ns']
        if elapsed >= 20_000_000:
            break
        rounds = max(rounds + 1, min(rounds * 100, round(rounds * 30_000_000 / max(1, elapsed))))
    # Check a modest steady-state run before extrapolating to several seconds.
    # A single traversal can have very different timing from repeated traversals.
    probe_ns = min(200_000_000, max(30_000_000, int(seconds * 1e9)))
    probe_rounds = max(1, round(rounds * probe_ns / max(1, elapsed)))
    probe = checked_harness(harness_cmd(ROOT / 'build/original', 'original', kernel,
                            size, probe_rounds, cpu, mapping), 60)
    return max(1, round(probe_rounds * seconds * 1e9 / max(1, probe['thread_ns'])))


def parse_stat(path, elements):
    """Preserve unsupported/scaled counters; never turn them into zeros."""
    counters = {}
    with Path(path).open(newline='') as f:
        for row in csv.reader(f, delimiter=';'):
            if len(row) < 3 or row[0].lstrip().startswith('#'):
                continue
            count, unit, event = [x.strip() for x in row[:3]]
            if not event:
                continue
            try:
                value = float(count)
            except ValueError:
                value = None
            def number(index):
                try:
                    return float(row[index].strip().strip('%'))
                except (ValueError, IndexError):
                    return None
            counters[event] = {'raw_count': count, 'count': value, 'unit': unit,
                'per_element': value / elements if value is not None else None,
                'runtime_ns': number(3), 'running_percent': number(4), 'raw_columns': row}
    return counters


def one_perf(perf, action, command, stem, events, freq, seconds, whole_process):
    env = dict(os.environ, LC_ALL='C')
    env.pop('GSFORK_PERF_CTL', None)
    env.pop('GSFORK_PERF_ACK', None)
    with tempfile.TemporaryDirectory(prefix='gsfork-perf-') as temp:
        ctl, ack = Path(temp) / 'control.fifo', Path(temp) / 'ack.fifo'
        gating = []
        if not whole_process:
            os.mkfifo(ctl, 0o600); os.mkfifo(ack, 0o600)
            gating = ['--delay=-1', f'--control=fifo:{ctl},{ack}']
            env.update(GSFORK_PERF_CTL=str(ctl), GSFORK_PERF_ACK=str(ack))
        if action == 'record':
            options = ['record', '-e', events, '-F', str(freq), '--no-buildid', '-o', str(stem.with_suffix('.data'))]
        else:
            options = ['stat', '-e', events, '-x', ';', '--no-big-num', '-o', str(stem.with_suffix('.perf.csv'))]
        full = [perf, *options, *gating, '--', *command]
        p = subprocess.run(full, capture_output=True, text=True, env=env, timeout=max(60, seconds * 10 + 30))
        stem.with_suffix('.command.json').write_text(json.dumps({'argv': full,
            'kernel_region_gated': not whole_process, 'harness': command}, indent=2) + '\n')
        stem.with_suffix('.stdout').write_text(p.stdout)
        stem.with_suffix('.stderr').write_text(p.stderr)
        if p.returncode:
            raise RuntimeError(f'perf failed ({p.returncode}); see {stem.with_suffix(".stderr")}\n{p.stderr.strip()}')
        result = json.loads(p.stdout)
        if not result['verified'] or result['perf_gated'] == whole_process:
            raise RuntimeError('harness verification or perf-region gating mismatch')
        return result


def make_summary(rows, output, reference):
    summaries = []
    for kernel, size in sorted({(x['kernel'], x['bytes']) for x in rows}):
        case = [x for x in rows if x['kernel'] == kernel and x['bytes'] == size]
        refs = {x['sample']: x for x in case if x['variant'] == reference}
        for name in dict.fromkeys(x['variant'] for x in case):
            values = [x for x in case if x['variant'] == name]
            counters = {}
            names = {event for x in values for event in x.get('counters', {})}
            for event in sorted(names):
                measurements = [x['counters'][event] for x in values if event in x.get('counters', {})]
                valid = [x['per_element'] for x in measurements if x['count'] is not None]
                percentages = [x['running_percent'] for x in measurements if x['running_percent'] is not None]
                counters[event] = {'median_per_element': statistics.median(valid) if valid else None,
                    'valid_samples': len(valid), 'samples': len(values),
                    'minimum_running_percent': min(percentages) if percentages else None,
                    'statuses': sorted({x['raw_count'] for x in measurements if x['count'] is None})}
            ratios = [x['wall_ns'] / refs[x['sample']]['wall_ns'] for x in values if x['sample'] in refs]
            summaries.append({'kernel': kernel, 'bytes': size, 'variant': name, 'samples': len(values),
                'median_ns_per_element': statistics.median(x['wall_ns'] / x['elements'] for x in values),
                'median_thread_ns_per_element': statistics.median(x['thread_ns'] / x['elements'] for x in values),
                'median_paired_wall_ratio': statistics.median(ratios) if ratios else None,
                'reference_variant': reference, 'counters': counters})
    (output / 'summary.json').write_text(json.dumps(summaries, indent=2) + '\n')
    def event_value(item, name):
        v = next((v['median_per_element'] for k, v in item['counters'].items() if k.split(':')[0] == name), None)
        return '—' if v is None else f'{v:.3f}'
    lines = ['| Kernel | KiB | Variant | ns/element | Cycles/element | Instructions/element | Wall ratio |',
             '|---|---:|---|---:|---:|---:|---:|']
    for s in summaries:
        ratio = s['median_paired_wall_ratio']
        formatted = '—' if ratio is None else f'{ratio:.3f}x'
        lines.append(f"| {s['kernel']} | {s['bytes']//1024:,} | {s['variant']} | {s['median_ns_per_element']:.3f} | {event_value(s,'cycles')} | {event_value(s,'instructions')} | {formatted} |")
    (output / 'summary.md').write_text('\n'.join(lines) + '\n')
    return '\n'.join(lines)


def doctor(perf, cpu):
    report = machine(cpu)
    report['perf_executable'] = perf
    if perf:
        p = subprocess.run([perf, 'stat', '-e', 'cycles:u,instructions:u', '--', '/bin/true'], capture_output=True, text=True, timeout=10)
        report.update(hardware_probe_returncode=p.returncode, hardware_probe_stderr=p.stderr)
    else:
        report['hardware_probe_status'] = 'not attempted: perf is not installed'
    print(json.dumps(report, indent=2))
    return p.returncode if perf else 1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('stat', 'record', 'sweep', 'doctor'))
    p.add_argument('--kernel', choices=('sum', 'update', 'avx2', 'chase'), default='chase')
    p.add_argument('--size', type=size_bytes, default=32768)
    p.add_argument('--sizes', default=DEFAULT_SIZES, help='comma-separated working sets for sweep')
    p.add_argument('--seconds', type=float, default=3, help='calibrate common work to this many original thread-CPU seconds')
    p.add_argument('--rounds', type=int, help='skip calibration and use an exact shared round count')
    p.add_argument('--repeat', type=int, default=3, help='paired randomized blocks (stat/sweep)')
    p.add_argument('--variants', type=variants, help='comma-separated variants; first is summary reference')
    p.add_argument('--variant', choices=VARIANTS, help='select one variant, especially for record')
    p.add_argument('--cpu', type=int)
    p.add_argument('--mapping', choices=('copy', 'alias'), default='alias')
    p.add_argument('--events', help='perf -e string; default four stat counters or cycles:u for record')
    p.add_argument('--freq', type=int, default=999)
    p.add_argument('--perf', help='perf executable, e.g. a kernel-version-specific path')
    p.add_argument('--whole-process', action='store_true', help='compatibility fallback without region gating; includes startup/setup/checking')
    p.add_argument('--timing-only', action='store_true', help='stat/sweep without perf, for timing or smoke tests')
    p.add_argument('--dry-run', action='store_true', help='print perf commands without launching perf (calibration still runs unless --rounds is supplied)')
    p.add_argument('--output', type=Path)
    a = p.parse_args()
    affinity = sorted(os.sched_getaffinity(0))
    cpu = affinity[len(affinity)//2] if a.cpu is None else a.cpu
    if cpu not in affinity:
        p.error(f'CPU must belong to current affinity: {affinity}')
    perf = shutil.which(a.perf or 'perf')
    if a.action == 'doctor':
        return doctor(perf, cpu)
    if not 0.01 <= a.seconds <= 3600 or a.repeat < 1 or a.freq < 1 or (a.rounds is not None and a.rounds < 1):
        p.error('invalid duration/repetition/frequency/round count')
    if a.variant and a.variants:
        p.error('choose --variant or --variants')
    names = [a.variant] if a.variant else a.variants
    names = names or (['gs_shift'] if a.action == 'record' else ['original', 'gs_zero', 'gs_shift', 'original_child', 'gs_zero_child'])
    if a.action == 'record' and (len(names) != 1 or a.timing_only):
        p.error('record requires exactly one variant and perf')
    if not perf and not (a.dry_run or a.timing_only):
        p.error('perf is not installed; install the matching Linux perf package or pass --perf /path/to/perf; doctor reports the environment')
    sizes = [size_bytes(s) for s in a.sizes.split(',')] if a.action == 'sweep' else [a.size]
    for name in {VARIANTS[x][0] for x in names} | {'original'}:
        if not (ROOT / 'build' / name).is_file():
            p.error('build first with make all')
    events = a.events or ('cycles:u' if a.action == 'record' else DEFAULT_EVENTS)
    rounds_by_size = {s: a.rounds or calibrate(a.kernel, s, cpu, a.mapping, a.seconds) for s in sizes}
    if a.dry_run:
        for size in sizes:
            for name in names:
                command = harness_cmd(ROOT / 'build' / VARIANTS[name][0], name, a.kernel, size, rounds_by_size[size], cpu, a.mapping)
                options = ['record', '-e', events, '-F', str(a.freq)] if a.action == 'record' else ['stat', '-e', events, '-x', ';']
                gating = [] if a.whole_process else ['--delay=-1', '--control=fifo:CONTROL_FIFO,ACK_FIFO']
                print(shlex.join([perf or 'perf', *options, *gating, '--', *command]))
        if not a.whole_process:
            print('The runner creates CONTROL_FIFO/ACK_FIFO and passes GSFORK_PERF_CTL/GSFORK_PERF_ACK to the harness; invoke profile.py without --dry-run to execute these plans.')
        return 0
    output = (a.output or ROOT / 'profiles' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')).resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        p.error(f'output directory must be empty: {output}')
    binary_dir = output / 'binaries'; binary_dir.mkdir()
    snapshots = {}
    for binary in {VARIANTS[x][0] for x in names}:
        target = binary_dir / binary
        shutil.copy2(ROOT / 'build' / binary, target)
        snapshots[binary] = {'path': str(target), 'sha256': hashlib.sha256(target.read_bytes()).hexdigest()}
    metadata = dict(machine(cpu), action=a.action, mapping=a.mapping, variants=names, sizes=sizes,
                    rounds_by_size=rounds_by_size, perf=perf, events=events, frequency=a.freq,
                    repeat=1 if a.action == 'record' else a.repeat, requested_seconds=a.seconds,
                    kernel_region_gated=not a.whole_process and not a.timing_only,
                    timing_only=a.timing_only, binaries=snapshots)
    if perf:
        v = subprocess.run([perf,'--version'],capture_output=True,text=True,timeout=5)
        metadata['perf_version'] = v.stdout.strip() or v.stderr.strip()
    (output / 'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
    rows = []; rng = random.Random(20261006)
    with (output / 'runs.jsonl').open('w') as log:
        for size in sizes:
            for sample in range(metadata['repeat']):
                order = list(names); rng.shuffle(order)
                pair = []
                for sequence, name in enumerate(order):
                    binary = binary_dir / VARIANTS[name][0]
                    command = harness_cmd(binary,name,a.kernel,size,rounds_by_size[size],cpu,a.mapping)
                    stem = output / f'{a.kernel}-{size}-{name}-{sample}'
                    if a.timing_only:
                        result = checked_harness(command,max(60,a.seconds*10+30)); counters = {}
                        stem.with_suffix('.command.json').write_text(json.dumps({'harness':command,'timing_only':True},indent=2)+'\n')
                    else:
                        result = one_perf(perf,a.action,command,stem,events,a.freq,a.seconds,a.whole_process)
                        counters = {} if a.action == 'record' else parse_stat(stem.with_suffix('.perf.csv'), size//(16 if a.kernel=='chase' else 8)*rounds_by_size[size])
                        for event, counter in counters.items():
                            if counter['count'] is None:
                                print(f"Counter unavailable: {event}: {counter['raw_count']}", file=sys.stderr)
                            elif counter['running_percent'] is not None and counter['running_percent'] < 95:
                                print(f"Counter multiplexed: {event}: {counter['running_percent']:.1f}% running; consider fewer events", file=sys.stderr)
                    row = dict(result,variant=name,sample=sample,order=sequence,
                               elements=size//(16 if a.kernel=='chase' else 8)*rounds_by_size[size],counters=counters)
                    rows.append(row); pair.append(row)
                    log.write(json.dumps(row)+'\n'); log.flush()
                    print(f'{a.kernel} {size//1024:,} KiB {name}: {result["wall_ns"]/1e9:.3f}s, verified',flush=True)
                if len({x['checksum'] for x in pair}) != 1:
                    raise RuntimeError('variants disagree on result')
    print(make_summary(rows,output,names[0]))
    print(f'Results: {output}')
    if a.action == 'record':
        data = next(output.glob('*.data'))
        print(shlex.join([perf,'report','--stdio','-i',str(data)]))
        print(shlex.join([perf,'annotate','--stdio','--symbol',f'kernel_{a.kernel}','-i',str(data)]))
    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except (RuntimeError, subprocess.TimeoutExpired, OSError, ValueError) as error:
        sys.exit(str(error))
