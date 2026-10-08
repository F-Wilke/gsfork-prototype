#!/usr/bin/env python3
"""TEST DOUBLE ONLY: validates perf's FIFO protocol; it has no hardware counters."""
import os
from pathlib import Path
import select
import subprocess
import sys
import time

args=sys.argv[1:]
if args==['--version']:
    print('FAKE PERF TEST DOUBLE, NOT HARDWARE PERF'); sys.exit(0)
mode=args[0]
control=next((x.split('fifo:',1)[1] for x in args if x.startswith('--control=fifo:')),None)
output=Path(args[args.index('-o')+1])
events=args[args.index('-e')+1]
child=subprocess.Popen(args[args.index('--')+1:])
seen=[]
if control:
    ctl,ack=control.split(',')
    c=os.open(ctl,os.O_RDWR|os.O_NONBLOCK); a=os.open(ack,os.O_RDWR|os.O_NONBLOCK)
    buf=b''; deadline=time.monotonic()+10
    while child.poll() is None and time.monotonic()<deadline:
        if select.select([c],[],[],0.05)[0]:
            buf+=os.read(c,4096)
            while b'\n' in buf:
                line,buf=buf.split(b'\n',1)
                seen.append(line.decode())
                os.write(a,b'ack\n\0')
    os.close(c); os.close(a)
    if child.poll() is None:
        child.kill(); sys.exit('TEST controller timeout')
    if seen!=['enable','disable']:
        sys.exit('Wrong FIFO protocol: '+repr(seen))
rc=child.wait()
print('FAKE_PERF_TEST_ONLY '+','.join(seen),file=sys.stderr)
if mode=='stat':
    output.write_text('# SYNTHETIC TEST DATA, NOT COUNTERS\n'+''.join(f'{1000+i};;{event};100000;100.00;;\n' for i,event in enumerate(events.split(','))))
else:
    output.write_text('SYNTHETIC TEST PLACEHOLDER, NOT A PERF DATA FILE\n')
sys.exit(rc)
