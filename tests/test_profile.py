import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from profile import size_bytes, variants, parse_stat

ROOT=Path(__file__).resolve().parents[1]

class ProfileTests(unittest.TestCase):
    def test_sizes(self):
        self.assertEqual(size_bytes('32KiB'),32768)
        self.assertEqual(size_bytes('8M'),8388608)
        for text in ('3K','4097','0','257M','nonsense'):
            with self.subTest(text=text),self.assertRaises(argparse.ArgumentTypeError):
                size_bytes(text)

    def test_stat_parser_retains_missing_and_scaled(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/'stat.csv'
            p.write_text('# comment\n1200;;cycles:u;200;50.00;2.0;metric\n<not supported>;;L1-dcache-load-misses:u;0;0.00;;\n')
            r=parse_stat(p,100)
            self.assertEqual(r['cycles:u']['per_element'],12)
            self.assertEqual(r['cycles:u']['running_percent'],50)
            self.assertIsNone(r['L1-dcache-load-misses:u']['count'])
            self.assertEqual(r['L1-dcache-load-misses:u']['raw_count'],'<not supported>')

    def fake_run(self,action,*extra):
        with tempfile.TemporaryDirectory() as temp:
            t=Path(temp); perf=t/'fake-perf'
            perf.write_bytes((ROOT/'tests/fake_perf.py').read_bytes()); perf.chmod(0o755)
            output=t/'output'
            cpu=min(os.sched_getaffinity(0))
            command=[sys.executable,str(ROOT/'profile.py'),action,'--perf',str(perf),'--cpu',str(cpu),
                     '--rounds','2','--repeat','1','--output',str(output),*extra]
            p=subprocess.run(command,capture_output=True,text=True,timeout=20)
            self.assertEqual(p.returncode,0,p.stderr+p.stdout)
            rows=[json.loads(x) for x in (output/'runs.jsonl').read_text().splitlines()]
            for row in rows:
                self.assertTrue(row['verified'])
                self.assertEqual(row['perf_gated'],'--whole-process' not in extra)
            return rows,[(f.name,f.read_text()) for f in output.iterdir() if f.name.endswith(('.stderr','.command.json'))]

    def test_stat_gates_every_kernel(self):
        for kernel in ('sum','update','avx2','chase'):
            with self.subTest(kernel=kernel):
                rows,files=self.fake_run('stat','--kernel',kernel,'--variants','original,gs_zero,gs_shift,original_child,gs_zero_child')
                self.assertEqual(len(rows),5)
                self.assertEqual(len({x['checksum'] for x in rows}),1)
                self.assertTrue(all('enable,disable' in text for name,text in files if name.endswith('.stderr')))
                self.assertTrue(all(x['counters']['cycles:u']['count']==1000 for x in rows))

    def test_record_region_and_binary_snapshot(self):
        rows,files=self.fake_run('record','--variant','gs_shift')
        self.assertEqual(len(rows),1)
        self.assertTrue(any('binaries/rewritten' in text for name,text in files if name.endswith('.command.json')))
        self.assertTrue(any('enable,disable' in text for name,text in files if name.endswith('.stderr')))

    def test_whole_process_fallback(self):
        rows,files=self.fake_run('stat','--variant','original','--whole-process')
        self.assertFalse(rows[0]['perf_gated'])
        self.assertTrue(all('--delay=-1' not in text for name,text in files if name.endswith('.command.json')))

    def test_dry_run_without_perf_or_calibration(self):
        cpu=min(os.sched_getaffinity(0))
        p=subprocess.run([sys.executable,str(ROOT/'profile.py'),'stat','--perf','/does/not/exist',
            '--rounds','2','--cpu',str(cpu),'--dry-run'],capture_output=True,text=True,timeout=5)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('--delay=-1',p.stdout)
        self.assertIn('--control=fifo:',p.stdout)
        self.assertIn('direct',p.stdout)

    def test_missing_controller_fails_with_bounded_ack_wait(self):
        with tempfile.TemporaryDirectory() as temp:
            ctl=Path(temp)/'ctl'; ack=Path(temp)/'ack'
            os.mkfifo(ctl); os.mkfifo(ack)
            env=dict(os.environ,GSFORK_PERF_CTL=str(ctl),GSFORK_PERF_ACK=str(ack))
            p=subprocess.run([str(ROOT/'build/original'),'sum','native','4096','1',
                str(min(os.sched_getaffinity(0)))],env=env,capture_output=True,text=True,timeout=8)
            self.assertEqual(p.returncode,1)
            self.assertIn('acknowledgement timed out',p.stderr)
