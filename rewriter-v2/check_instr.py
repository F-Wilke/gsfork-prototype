from collections import Counter, defaultdict
import sys

from gsfork_elf.elf import Image
from gsfork_elf.policy import classify, decode, Runtime
from gsfork_elf.errors import RewriteError

image = Image(sys.argv[1])
runtime = Runtime(scratch_rax=-16, sandbox_offset=-8)

missing = Counter()
examples = defaultdict(list)

for section in image.executable:
    # PLT code is handled separately by the rewriter.
    if section.name.startswith((".plt", ".iplt")):
        continue

    for ins in decode(section.data(), section["sh_addr"]):
        try:
            classify(ins, runtime)
        except RewriteError as error:
            key = (str(ins.mnemonic), str(error))
            missing[key] += 1
            if len(examples[key]) < 3:
                examples[key].append(
                    f"0x{ins.ip:x}: {ins}"
                )

for key, count in missing.most_common():
    print(f"{count:5d}  {key}")
    for example in examples[key]:
        print(f"       {example}")