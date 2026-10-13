#!/usr/bin/env python3
import json
import os
from pathlib import Path
import resource
import subprocess
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
os.chdir(Path(__file__).resolve().parent)
cpu=sorted(os.sched_getaffinity(0))[0]
variants=[('original','native'),('reencoded','native'),('rewritten','zero'),('rewritten','shift')]
variants += [('original','direct'), ('rewritten','direct')]
records=[]
for kernel in ('sum','update','avx2','chase','rep_movsb'):
    for size in (4096,32768,1048576):
        for rounds in (1,2,7):
            checks=[]
            for mapping in ('copy','alias'):
                for binary,mode in variants:
                    env=os.environ.copy()
                    if kernel=='rep_movsb':
                        env['GSFORK_REP_WRAPPED']='1' if binary=='rewritten' and mode in ('zero','shift') else '0'
                    p=subprocess.run([f'./build/{binary}',kernel,mode,str(size),str(rounds),str(cpu),'--mapping',mapping],capture_output=True,text=True,check=True,env=env)
                    item=json.loads(p.stdout)
                    assert item['verified']
                    checks.append(item['checksum'])
                    records.append(dict(binary=binary,**item))
            assert len(set(checks))==1,(kernel,size,rounds,checks)
# Demonstrate that the protected logical range really catches missing rewriting.
negative=[]
for kernel in ('sum','update','avx2','chase'):
    for mapping in ('copy','alias'):
        p=subprocess.run(['./build/original',kernel,'shift','4096','1',str(cpu),'--mapping',mapping],capture_output=True)
        assert p.returncode == -11,(kernel,p.returncode)
        negative.append({'kernel':kernel,'mapping':mapping,'returncode':p.returncode})
Path('results').mkdir(exist_ok=True)
Path('results/validation.json').write_text(json.dumps({'positive_cases':records,'unmodified_shift_must_fault':negative},indent=2)+'\n')
print(f'{len(records)} executions verified; {len(negative)} missing-rewrite controls correctly SIGSEGV')
