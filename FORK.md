# Fork-oriented GS rewrite mode

`rewrite.py --fork-manifest` provides a broader rewriting policy for exploring
GS-based address-space selection across `fork`.

## Rewrite rule

For each function listed in the manifest:

- add a GS override to every explicit memory operand unless its effective
  address is RIP-relative or RSP-relative;
- leave LEA unchanged because it computes an address without accessing memory;
- leave direct branches and register-indirect branches unchanged because they
  do not contain a memory effective address;
- rewrite memory-indirect CALL and JMP operands, for example
  `call [rdi]` to `call gs:[rdi]`;
- leave implicit RSP-based PUSH, POP, CALL, RET, and ENTER stack traffic
  native;
- reject implicit RBP-based stack memory such as LEAVE, because it violates the
  RSP-only exception and has no explicit operand to prefix;
- reject instructions with multiple explicit memory operands, including string
  moves, because one x86 segment override cannot independently translate both
  addresses;
- reject a selected operand that already has a segment override.

Example:

```asm
mov [rdi+8], rdx       -> mov gs:[rdi+8], rdx
mov rax, [rbp]         -> mov rax, gs:[rbp]
mov rax, [rsp+8]       -> unchanged
mov rax, [rip+global]  -> unchanged
call [rdi]             -> call gs:[rdi]
jmp [rdi]              -> jmp gs:[rdi]
lea rax, [rdi+8]       -> unchanged
```

The CLI takes a JSON manifest so rewriting remains limited to reviewed,
dedicated growth slots:

```sh
python3 rewrite.py input output \
  --fork-manifest tests/fork_manifest.json \
  --report build/fork/rewrite.json
```

## Address-space model under test

The runtime test models:

- process-owned space `[s, s + d1)`;
- reserved child stacks `[s + d1, s + d1 + d2)`;
- a child GS delta of 1 TiB;
- each child-stack page mapped again at `GS + child_rsp`;
- the physical page containing the parent's pre-fork stack mapped at
  `GS + parent_rsp`;
- process data and indirect-control tables mapped at their logical address and
  at logical address plus GS.

The current constants are:

| Value | Address/size |
|---|---:|
| `s` | `0x2000000000` |
| `d1` | `0x40000000` (1 GiB) |
| `d2` | `0x02000000` (32 MiB) |
| GS delta | `0x10000000000` (1 TiB) |
| Parent stack tested | `0x203fff8000`–`0x2040000000` |
| RSP at raw fork | `0x203fffffd0` |
| Child stack tested | `0x2040002000`–`0x204000a000` |
| Observed child RSP | `0x2040009fd0` |

All aliases use shared `memfd` mappings, so the logical child stack and
`GS + child stack` reference the same physical pages.

## Evaluation

Run:

```sh
make fork-test
```

`fork_validate.py` builds a baseline executable and rewrites its four manifest
functions. The parent switches RSP into the mapped parent-stack range before a
raw `fork` syscall. An assembly trampoline moves the child to the reserved
child stack immediately on return from the syscall, before child-side C code or
a stack-based return. The child then sets GS and executes the probes. Baseline
and rewritten execution are each repeated 16 times.

| Invariant | Test |
|---|---|
| General data loads use GS | Protect the logical data mapping; `mov [rdi]` succeeds through its shifted alias. |
| General data stores use GS | Protect the logical data mapping; `mov [rdi+8]` updates the shifted/shared page. |
| Parent stack pointers use GS | Protect the logical parent-stack page; access it through `[rbp]` and its `GS + parent_rsp` alias. |
| Fork uses the modeled parent stack | Record RSP at the raw fork syscall and require it to lie inside the parent-stack mapping. |
| Current child stack stays native | Run with RSP in the reserved child-stack range; explicit `[rsp]` plus implicit CALL/RET/PUSH/POP remain unprefixed. |
| Child stack alias is physically shared | Compare the logical and shifted child-stack mappings after stack activity. |
| RIP-relative state stays native | Read and write native globals through RIP-relative operands with nonzero GS. |
| Memory-indirect calls use GS | Protect the logical function-pointer table and execute `call gs:[rdi]`. |
| Memory-indirect jumps use GS | Protect the logical function-pointer table and execute `jmp gs:[rdi]`. |
| Missing rewriting is detected | Run the unmodified binary with shifted/protected mappings; it must SIGSEGV. |
| Encoding selection is complete | Decode all rewritten manifest functions and audit every explicit memory operand against the RIP/RSP exclusion rule. |
| Unsupported two-address memory is rejected | Unit-test `rep movsb` rejection. |

Current result:

- 16/16 baseline forks verified;
- 16/16 shifted rewritten forks verified;
- unrewritten shifted control terminated with SIGSEGV;
- the raw fork occurred at parent RSP `0x203fffffd0`, inside the modeled parent
  stack, and child execution moved to `0x2040009fd0`;
- parent and child stack aliases both matched their logical mappings;
- 10 explicit memory operands audited;
- six operands rewritten: four data load/store operands, one memory-indirect
  CALL, and one memory-indirect JMP;
- code growth was one byte per rewritten operand:
  `fork_memory_probe` 44 to 48 bytes, indirect CALL 11 to 12 bytes, indirect
  JMP 2 to 3 bytes, and the RIP-relative probe remained 8 bytes.

The machine-readable results are generated as
`build/fork/validation.json` and `build/fork/rewrite.json`.

### Why the immediate child stack switch matters

An earlier version let libc `fork()` return normally while the modeled parent
stack was a shared physical mapping. Parent and child briefly executed on the
same writable stack and corrupted a stack frame, triggering stack-smashing
detection. The raw syscall trampoline is therefore not merely test machinery:
when the old stack page is deliberately shared, the child must leave it before
normal post-fork execution while the parent may continue.

## Important consequence for RBP

The requested rule excludes RSP, not RBP. Therefore `[rbp+offset]` is
GS-relative. This is useful when RBP retains a pointer into the parent's
pre-fork stack, and the runtime test verifies exactly that case.

It also means ordinary compiler frame-pointer accesses to the *current child
stack* would be translated incorrectly. Code rewritten under this policy
should be compiled without frame pointers, reserve RBP for translated
parent-stack references, or carry metadata that distinguishes current-stack
RBP from inherited-parent-stack RBP. This cannot be inferred reliably from one
instruction in a general binary.

## Remaining limits

This is still slot-based offline rewriting, not arbitrary whole-ELF expansion.
The manifest functions must have symbols and dedicated executable space.
Existing FS/GS accesses, implicit non-RSP memory instructions (including
LEAVE), and multi-memory string operations fail closed. Register-indirect
JMP/CALL targets are not numerically offset because segment prefixes only
affect memory effective addresses; memory-resident target tables are
translated.

The test establishes address-selection correctness and code-growth effects. It
does not yet implement the fork runtime that creates these mappings
automatically, rewrite every function in a production executable, update
unwind/debug metadata, or provide thread-safe GS lifecycle management.
