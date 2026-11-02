# GS-Fork linked ELF rewriter

A working, **fail-closed, restricted linked-ELF rewriter** implementing the
[v2 manifest](gs-fork-elf-rewriter-manifest-v2.md). This is independent of the
older reserved-slot Python prototype and the `../rewriter` ET_REL implementation.
Its inputs are already-linked x86-64 Linux executables, PIEs, and shared objects.
Application source, compiler assembly, reserved slots, and retained static
relocations are not required.

This is not a universal binary translator or a complete GS-Fork runtime.
Acceptance is conditional on the instruction, recovery, metadata, and runtime
contracts below. Unsupported input fails; there is no partial-rewrite mode.

## Install and run

Requirements: Linux x86-64, Python 3.10+, GCC/G++, GNU binutils, and, for runtime
tests, permission to use `arch_prctl`, `memfd_create`, and fixed-address mappings.
No root or Docker is needed. The pinned Ddisasm and printer binaries are supplied
by their Python wheels.

```sh
cd rewriter-v2
make install
make check

# Native disassembly/reassembly control, not GS instrumentation:
.venv/bin/gsfork-elf baseline /path/to/program /path/to/program.baseline

# Dependencies must be explicitly acknowledged as a trusted runtime boundary:
.venv/bin/gsfork-elf rewrite /path/to/program /path/to/program.gs \
    --trust-library libc.so.6
.venv/bin/gsfork-elf validate /path/to/program.gs
```

Repeat `--trust-library` for each `DT_NEEDED` library. C++ programs commonly also
need `--trust-library libstdc++.so.6 --trust-library libgcc_s.so.1`. `-L DIR`
supplies local link-time library search paths. Dynamic symbol versions, version
definitions, SONAME, RPATH/RUNPATH, dependency order, initialization/finalization
targets, and exported function boundaries are checked after linking.

MOVS/STOS instrumentation requires explicit, nonoverlapping, signed-disp32 FS slots:

```sh
.venv/bin/gsfork-elf rewrite library.so library.gs.so \
    --scratch-rax=-16 --sandbox-offset=-8 --trust-library libc.so.6
```

Those offsets are **only an example**: the test executable reserves and verifies
exactly those TLS slots. Do not use them in another program without reserving
appropriate thread-local storage through its runtime. The runtime must initialize
`SANDBOX_OFFSET` to the active GS base before instrumented code executes.
The historical `--scratch-rax` slot holds RAX for MOVS and RDX for STOS.
No offsets are guessed or reserved automatically in an existing process's TLS.

### Deriving the slots from `struct pthread` (no magic numbers)

When the slots are real members of `struct pthread` — as in the custom glibc,
which adds `sandbox_offset` and `sandbox_scratch` to the TCB — name the fields
instead of hand-writing displacements:

```sh
.venv/bin/gsfork-elf rewrite ../../glibc-2.35/build/libc.so.6 libc.gs \
    --scratch-field sandbox_scratch --sandbox-field sandbox_offset \
    --trust-library ld-linux-x86-64.so.2 -L ../../glibc-2.35/build/elf
```

On x86-64 the thread pointer (and therefore the FS base) is the address of the
TCB, which *is* `struct pthread`, so a member's FS displacement equals its struct
offset. The rewriter reads that offset straight from the input's DWARF
(`offsetof(struct pthread, field)`), so the invocation carries no numeric slot at
all. For the supplied build this resolves to `%fs:0x9c0`/`%fs:0x9c8` (2496/2504).

This is the same idea as letting the assembler place the offset: the only place a
struct layout becomes a number is the compiler-generated DWARF (equivalently
glibc's own `gen-as-const`/`tcb-offsets.sym`), and the rewriter consumes that
number by field name rather than repeating it. The emitted wrapper assembly could
in principle reference an absolute `.set` symbol so the final assembler encodes the
displacement, but `gtirb-rewriting` assembles every patch against one shared symbol
table and rejects the repeated definition; deriving the constant once from DWARF
achieves the same "no hand-written offsets" result without that limitation.
`--scratch-field`/`--sandbox-field` and the numeric `--scratch-rax`/
`--sandbox-offset` are mutually exclusive per slot.

**Rewriting programs and other libraries.** The fields are looked up in the
DWARF of the input only by default, which works when rewriting glibc itself. An
ordinary program or third-party library does not contain `struct pthread`, so name
the glibc that owns the TCB layout explicitly:

```sh
.venv/bin/gsfork-elf rewrite program program.gs \
    --scratch-field sandbox_scratch --sandbox-field sandbox_offset \
    --tcb-layout ../../glibc-2.35/build/libc.so --trust-library libc.so.6
```

This is deliberately not inferred from `DT_NEEDED libc.so.6`: the loader chooses
the actual file at run time (`--library-path`, `RUNPATH`, `LD_LIBRARY_PATH`, the
cache), so the rewriter would have to guess and might read the host glibc, whose
`struct pthread` has no sandbox fields. The layout source needs DWARF; either the
unstripped `libc.so`/`ld.so` from the build directory works. The report records
the source path, its SHA-256, and the field names under `runtime_layout`, so a
program can be checked against the glibc it is deployed with. Every artifact in one
process must be rewritten against the same layout; changing `struct pthread`
requires rewriting them all again.

### Parent-stack `leave` mode

For a runtime that keeps a parent-frame RBP but needs to resume on a relocated
stack, enable the dedicated rule with the new `struct pthread` member:

```sh
.venv/bin/gsfork-elf rewrite program program.gs \
    --parent-stack-field parent_stack_offset \
    --scratch-field sandbox_scratch --sandbox-field sandbox_offset \
    --tcb-layout ../../glibc-2.35/build/libc.so \
    --trust-library libc.so.6
```

The expansion requires the existing scratch slot (and its paired sandbox-slot
configuration), shared with MOVS/STOS instrumentation. When rewriting glibc itself,
the layout defaults to the input, as for the other fields. Alternatively,
`--parent-stack-offset NUMBER` specifies the FS displacement numerically; it is
mutually exclusive with `--parent-stack-field`. The slot must be eight bytes,
signed-disp32-addressable, and must not overlap either other configured slot.

With the slot configured, every untrusted ordinary 64-bit `leave` becomes:

```asm
movq %rax, %fs:SCRATCH_RAX_FIELD_OFFSET
movq %fs:PARENT_STACK_FIELD_OFFSET, %rax
leaq (%rbp,%rax), %rsp
movq %fs:SCRATCH_RAX_FIELD_OFFSET, %rax
popq %rbp
```

The runtime must initialize the field in every thread **before any expanded
leave executes**, including early loader code. Its value is the signed byte delta
such that `RBP + parent_stack_offset` addresses the saved frame pointer on the
resumed stack; the return address must follow it. Zero gives native stack results.
This delta is independent of the sandbox/GS delta. The pop remains an implicit
stack access: it receives no GS prefix.

All five instructions preserve flags, and RAX is restored before the pop.
RSP remains on the current stack until LEA switches directly to the parent stack;
it never contains the bare delta.
This is an explicit runtime ABI mode under a parent-stack relocation contract.
Without either parent-stack
option, `leave` stays native; native baselines and trusted sections also remain
unchanged. Prefixed/16-bit leave forms are rejected in parent-stack mode.
The validator checks the exact expansion and FS slot. Existing RBP-based CFI and
the post-pop CFI transition are retained; other CFA forms at an expanded leave
are rejected when unwind rules are present. The runtime remains responsible for
unwinding logical parent frames and preserving the shared scratch slot on signal
entry and across nested instrumentation. The report's `leave_wrappers` lists each
instruction boundary, whether original RAX is in scratch, and whether RSP has
switched to the parent stack. Phase flags describe state before that instruction.
Ordinary CFI alone does not recover the temporary RAX value from scratch.

IFUNC resolvers need no special trust flag: their instructions are rewritten by
the ordinary instruction rules, just like their selected implementations.
`STT_GNU_IFUNC` symbols retain their resolver type; IRELATIVE relocation addends
are symbolic resolver code addresses, not data offsets. Named IFUNC imports,
local IFUNC calls, resolver-valued data pointers, and their generated PLT/GOT
accesses are independently validated. Direct encoded references to the resolver
use an untyped code alias, so reassembly does not accidentally turn a call to the
resolver into an IFUNC call to its selected implementation.

Repeated local names such as `__PRETTY_FUNCTION__.0` are valid ELF. The input
reader retains all their addresses, and a name-only lookup rejects ambiguity
only if a caller actually requests an ambiguous reference. Before reassembly,
local GTIRB symbols receive unique assembler names without changing their symbol
objects, referents, or auxiliary-data identities. The report records these
renames. Nonlocal/exported symbols are not renamed.

`--trust-section NAME` explicitly exempts an entire existing executable section
from instruction rewriting. Its code boundaries and references are still
validated. There are no implicit function-name exemptions; in particular,
`_start`, `register_tm_clones`, and `deregister_tm_clones` are covered.
Use this option only for runtime code implementing a real ABI boundary.

Outputs must not already exist. A successful operation publishes:

* The output ELF, after final validation.
* `OUTPUT.gsfork/report.json`: hashes, trust declarations, every original
  instruction, final locations, symbolic expectations, unwind states, retired
  PLT provenance, generated slots, and REP interruption phases.
* `original.gtirb`, `rewritten.gtirb`, `baseline.S`, `output.S`, tool logs, and a
  native `baseline` executable inside `OUTPUT.gsfork/`.

Intermediate work uses an automatically cleaned temporary directory. Recovery,
assembly, or validation failure does not publish an output ELF or success
directory. Diagnostic logs, assembly, IR, and an explicitly unvalidated report
are retained in a separately named `OUTPUT.failed-*` directory; no executable
is retained there. The manifest attachment is not modified. Output permissions do not
carry setuid/setgid or group/world-write bits from the input.

Keep the report and the output's local provenance symbols together. The standalone
validator requires both, checks instruction semantics and references again, and
checks the artifact hash. Stripping a **rewritten output** is not supported.
Reports are correctness evidence, not cryptographically authenticated certificates.

## Implementation

1. Parse ELF eligibility, dynamic relocations, and available unwind/LSDA data.
2. Run Ddisasm with default CFI recovery and `-j 1`. Reported recovery errors and
   warnings fail except narrowly recognized diagnostics whose corresponding IR
   condition is checked: an absent entry point for an entryless ET_DYN shared
   object; relocation of `__ehdr_start` when it is restored as a linker-defined
   header symbol; and the paired missing-GLOBAL/WEAK diagnostic for a *local*
   IFUNC whose IRELATIVE references are verified against their recovered resolver
   code; and local initial-exec TLS symbols whose TPOFF64 references and offsets
   are verified against PT_TLS. All diagnostics remain in the recovery log.
   Other recovery warnings are not ignored.
3. Produce an unmodified native reassembly control.
4. Classify **every** recovered instruction. Attach block-boundary symbols and
   record original instruction fields, symbolic expressions, and unwind states.
5. Use supported `gtirb-rewriting` passes and `RewritingContext.insert_at` /
   `replace_at`. An ordinary access receives the assembler's `gs` code-prefix
   fragment; the original operand and symbolic expression are not reconstructed.
   MOVS uses the manifest's eleven-instruction FS-scratch sequence with the exact
   original width and repetition form. STOS uses a separate thirteen-instruction
   sequence which preserves the accumulator while saving flags through RDX.
   No detours, spills, or application-stack scratch are introduced.
6. Normalize newly generated, unreferenced framework alignment DataBlocks from
   zero-fill into recorded NOP padding through the mutation API.
   Across both rewrite passes, preserve numeric `SHN_ABS` symbols and numeric
   symbols outside recovered intervals (including discarded glibc link-warning
   sections). Framework layout can place data at synthetic address zero; a
   subsequent pass must not reinterpret constants such as `0` or `0x40` as
   pointers into that data and create overlapping blocks. Their original values
   are restored before printing. If the final synthetic layout still covers one
   of those values, every byte interval is shifted by a 2 MiB multiple so the
   printer emits the symbol as an integral `.set` rather than a label inside
   data. IR addresses are relinked anyway, so the shift only removes ambiguity.
   Overlap diagnostics still fail; they are not suppressed.
7. Print GNU Intel-syntax assembly with `--layout`, `--policy=complete`, `--keep-all-functions`, and
   `--keep-all-array-sections`. The printer's complete policy links with
   `-nostartfiles -nodefaultlibs`: original startup code is retained, not silently
   replaced by new CRT objects. Linker-owned dynamic tables and `_DYNAMIC` are
   explicitly regenerated. References to `_DYNAMIC`, `_GLOBAL_OFFSET_TABLE_`,
   and `__ehdr_start` resolve to the output linker's symbols rather than obsolete
   recovered input blocks. An explicit hidden entry symbol preserves nonzero
   ET_DYN loader entry points. Intel syntax avoids the pinned printer's invalid
   AT&T suffixes on FSGSBASE instructions. The compiler adapter corrects the
   pinned printer's RSTORSSP operand-width and negative XABORT-immediate syntax,
   and ensures init/fini resolve to explicit original-entry aliases rather than
   an arbitrary at-end marker. Final instruction equivalence is checked after
   these corrections. GNU assembly regenerates CFI encodings; the link
   requests `--eh-frame-hdr`, eager binding, and retained local symbols.
8. Apply the bounded PLT strategy below, then validate the actual ELF.

The loader's masked countdown table-walk idiom is recovered with an explicit
bounded rule: the counter, stride, bit filter, and unchanged pointer register
identify accessed addresses within one recovered data block. Its pre-biased
initial address is then expressed relative to that block, rather than incorrectly
relative to regenerated dynamic metadata. Unknown patterns still fail validation.

Initial-exec TLS preserves PT_TLS file size, memory size, alignment, initialized
data, and each recovered TLS symbol's module-relative offset. Already-resolved
absolute FS offsets remain numeric; they are not turned back into local-exec
relocations.

Local-exec TLS (`sym@TPOFF` on a register-based operand, e.g.
`mov %fs:0,%rax; lea sym@tpoff(%rax),%rax`, including linker GD/LD→LE
relaxation output) is accepted **only in executables** (`ET_EXEC`, `DF_1_PIE`,
or `PT_INTERP`), where the main program's TLS block has a static offset. The
reference stays symbolic so the linker recomputes `R_X86_64_TPOFF32`. The
rewriter records the module-wide bias between each encoded thread-pointer offset
and the symbol's module-relative offset; the validator requires every rewritten
reference to reproduce that bias. A local-exec reference in a shared object is
rejected. Relaxation leaves a now-unused `__tls_get_addr` import behind; every
strong (`STB_GLOBAL`) undefined dynamic import is therefore relinked with
`-Wl,--undefined=NAME` so the dynamic symbol table, including its version, is
preserved. Weak imports are not forced because that could change their binding.

Public version aliases at different addresses get private validation
identities without renaming the exported ABI, and reference versions are checked
at their GOT/PLT/data relocation sites.

### Generated code and eager binding

**Why this step exists.** Ddisasm reconstructs the program's own code. The output
linker then generates new PLT stubs after reassembly. As a result, the stubs are
absent from the GTIRB IR and are not covered by the instrumentation passes. Every
live PLT stub performs an explicit memory load:

```asm
jmp  *foo@GOTPCREL(%rip)     # ff 25 <disp32>: reads the GOT entry
```

The rewritten program accesses data through GS, so this load also needs a `gs`
prefix. Otherwise, each call to another library or IFUNC target reads a GOT entry
that is not GS-relative. The final validator rejects any such unprefixed access.
The rewriter therefore patches these linker-generated stubs after linking.

**Why lazy binding cannot be kept.** A classic lazy `.plt` slot uses all 16 of its
bytes:

```text
ff 25 <disp32>     jmp  *GOT[n](%rip)    6 bytes
68 <imm32>         push $n               5 bytes
e9 <rel32>         jmp  PLT0             5 bytes
```

Adding the one-byte GS prefix would make the slot 17 bytes. To make room, the
rewriter would have to move PLT slots. That would break their symbol addresses,
the relocations and GOT entries that refer to them, and their unwind ranges. Before
binding, the lazy path also pushes the relocation index and jumps to PLT0. PLT0
then makes two more GOT accesses, `push *GOT[1]` and `jmp *GOT[2]`, to enter the
dynamic resolver.

With eager binding (`DT_BIND_NOW` / `DF_BIND_NOW`, requested from the output linker
with `-z now`), the loader fills every GOT entry before any code runs. The
`push`/`jmp PLT0` tails and PLT0 become dead code. The rewriter can then replace them
instead of trying to instrument code that does not fit.

**Why eager binding is verified, not assumed.** Before binding, each lazy GOT entry
points to its own slot's `push` tail at `slot+6`. After rewriting, that address is
inside the NOP padding behind the new seven-byte jump. Execution would fall
through into the *next* slot and silently call the wrong function. Validation
therefore rejects any rewritten PLT unless the output ELF carries the eager-binding
flag.

Recognized GNU ld `.plt` slots are 16 bytes and ordinary `.plt.got` slots are 8 bytes.
Each live slot becomes a seven-byte GS-relative RIP-indirect jump followed by
NOPs. Its displacement is recomputed against the unchanged GOT target. Its target
must have a named `GLOB_DAT`/`JUMP_SLOT` relocation or a validated `IRELATIVE`
resolver reference.

Eager binding is required and verified. Lazy entry tails are retired, and PLT0
becomes `ud2` plus NOPs. No slot, section, symbol, or unwind range moves during
this bounded patch. The live jump has the same CFA as the original live jump;
retired resolver/tail states are unreachable. The validator rejects direct
targets into those retired regions and validates the retained CFI boundaries.
It checks every generated slot against this exact contract, not just its hash.

Recognized CET/IBT `.plt.sec` and 16-byte `.plt.got` layouts preserve ENDBR64 and
any BND prefix; the output linker is asked to retain IBT PLT emission. Their
separate lazy slots are retired. A padded jump-only `.iplt` layout is also
recognized, but static startup resolution without eager dynamic binding is not
supported. Unknown layouts still fail. Eager binding alone is **not** treated
as instrumentation. The tests call through the generated GS PLT at nonzero GS
with the original library data/GOT mappings inaccessible.

### Final validation

The validator checks:

* All recovered instructions and all executable-section bytes, including generated
  code and padding. Nonzero executable-segment bytes outside executable sections
  are rejected.
* Required GS prefixes, approved FS operands, native stack rules, exact REP
  sequences, and unchanged non-address operands and branch-control prefixes.
* RIP, direct-branch, PLT, GOT, scalar data-pointer, and symbol-difference/jump-table
  references against final symbols and relocations. Linker transformations that
  change instruction semantics or remove instrumentation fail validation.
* Entry/init/fini targets, declared dynamic dependencies and symbol versions,
  exported function boundaries, and absence of stale debug sections.
* FDE ranges, each decoded CFI row boundary, and preservation of the input unwind
  state at each covered original instruction and generated REP instruction.
* `.eh_frame_hdr` encodings, count, ordering, FDE addresses, and frame pointer.
* LSDA call-site ranges, landing pads, action chains, type references, and their
  association with relocated input code.
* Defined IFUNC symbol and IRELATIVE addend targets against fully covered original
  resolver entry points, including resolver references in ordinary data.
* glibc's conditional LOCK-skipping entries. A bounded post-link prefix
  reordering puts LOCK before GS without changing instruction size or semantics;
  a branch to `instruction + 1` then skips only LOCK, never GS. Other instruction
  interiors are not accepted as direct targets.

An ordinary error identifies the file, section, final address, original address
where applicable, and the violated rule. Unknown bytes do not become trusted
merely because they are in a code section.

## Supported boundary

The exact mnemonic allowlist and form checks are in
[`policy.py`](gsfork_elf/policy.py). Broadly:

| Form | Handling |
|---|---|
| Listed scalar/SSE/AVX/AVX-512/x87/state-save explicit memory, including RSP/RBP and locked RMW | GS prefix |
| RIP-relative loads/stores and memory-indirect CALL/JMP | GS prefix; preserve symbolic target |
| LEA | Logical computation, symbolically relocated |
| Existing FS memory | Preserve the runtime TLS contract |
| Near direct/register-indirect control flow | Preserve; relocate direct references |
| Register-indirect NOTRACK CALL/JMP | Preserve the DS/NOTRACK control prefix |
| Ordinary 64-bit PUSH/POP/CALL/RET, PUSHFQ/POPFQ | Native implicit stack alias |
| 64-bit LEAVE | Native by default; parent-stack mode spills RAX to FS scratch, computes RSP with LEA, restores RAX, then POPs RBP (flags preserved) |
| 64-bit-address MOVS/STOS, byte/word/dword/qword, with or without REP | Dedicated family-specific FS-scratch wrapper |
| Syscall, FS-base, PKRU, and implicit CET shadow-stack controls | Preserve native operation; record runtime-control boundary |
| Alignment NOP / ignored CS-prefixed NOP | Preserve equivalent no-access padding |
| Existing GS, other segment forms, unsupported instruction/implicit access | Reject |

LODS, string CMPS/SCAS, address-size-overridden strings, far transfers, ENTER,
nonstandard stack forms, and instructions absent from the explicit allowlist
remain unsupported. The SIMD CMPSD instruction is distinct from string CMPSD.
Supporting one string family does not permit another.

Recovery requires ordinary sectioned ELF and nonoverlapping, complete recovered
code/data coverage in executable sections. Embedded **non-padding data in an
executable section** is currently rejected; jump tables in ordinary data/rodata
sections are supported. Recovery depends on Ddisasm's code-boundary and
symbolization assumptions. Neither this validator nor successful disassembly
proves that an arbitrary concealed instruction stream was recovered.

Supported dynamic relocation classes are `R_X86_64_64`, `COPY`, `GLOB_DAT`,
`JUMP_SLOT`, `RELATIVE`, `IRELATIVE`, and initial-exec `TPOFF64`. Other dynamic TLS
relocations, text relocations, RELR,
audit dependencies, writable executable segments, and executable stacks are
rejected. Ordinary FS-relative accesses with already-resolved offsets are supported.
Canonical all-zero `R_X86_64_NONE` linker padding entries are accepted as no-ops.

Unwind handling preserves **available input rules**; it does not invent missing
ones. Input without usable `.eh_frame` is rejected. Existing uncovered startup/
leaf regions are explicitly counted as `instructions_without_input_unwind`, and
their instruction records contain `unwind: null`. Such artifacts are not suitable
for a runtime requiring complete asynchronous unwinding at every PC. The initial
LSDA subset is function-relative LPStart, ULEB128 call-site records, nonnegative
action filters, and indirect PC-relative signed-32-bit type entries. Other
encodings fail explicitly. Debug information is removed, not relocated.

## Runtime and interruption contract

The runtime, **not this rewriter**, supplies:

* Per-thread GS management, copied/aliased application data, and actual-address
  transitions for kernel interfaces and trusted libraries.
* Logical RSP and two mappings of the same stack backing at `RSP` and
  `RSP + GS.base`. Explicit stack operands use GS; implicit stack operations use
  the logical mapping.
* Valid, reserved FS scratch, with `SANDBOX_OFFSET == GS.base`.
* Signal/fault handling that interprets interrupted REP phases and preserves
  scratch across nested instrumentation.
* Actual-address marshalling at syscall boundaries. Preserving SYSCALL does not
  make the kernel understand logical pointers.
* Consistent aliases for FS control storage when code obtains FS.base and uses
  an ordinary explicit pointer access, and CET-compatible shadow-stack aliases
  when the application enables shadow stacks. FS-base/PKRU control instructions
  retain their original native effects.

The report's string phases identify instruction boundaries, translated RSI/RDI
states, and whether original RAX (MOVS) or RDX (STOS) is in scratch. The instruction index also
identifies flag-save/restore progress. The addresses are ELF virtual addresses;
add the load bias for PIE/shared objects. Do not blindly restart a wrapper after
partial REP completion or translate its already-translated pointers twice.

`--trust-library` is an explicit boundary, not a pointer-marshalling implementation.
At nonzero GS, arbitrary libc/C++ calls with logical pointers still need runtime
integration. Independently rewritten libraries must be validated separately;
dlopen/JIT/self-modifying code is not automatically covered.

[`runtime.c`](tests/fixtures/runtime.c) and [`invoke.S`](tests/fixtures/invoke.S)
are a test runtime, not a production signal subsystem. They reserve two TLS slots,
copy library data into a shifted mapping, share stack backing through a memfd, and
make the original library data/heap inaccessible. A fault partway through REP
verifies actual RSI/RDI and residual RCX, invokes nested instrumented copies and a
nested signal handler, restores scratch, and resumes the partial operation.

## Validation corpus and performance

`make check` currently runs 26 unittest methods, including:

* Linked C++ ET_EXEC, PIE, and fully stripped PIE without retained static
  relocations; original/native-reassembly/GS=0 execution, constructors/destructors,
  backtraces, exception propagation, cleanup, and landing pads.
* Versioned shared-library loading with `dlvsym`, preserved SONAME, and real
  constructor/destructor execution.
* A compiler-generated symbolic relative jump table.
* Distinct local symbols with identical names from separately linked translation
  units; local/exported/versioned IFUNCs, IRELATIVE function-pointer data, and CET
  PLT preservation, with negative tests for corrupt resolver addends.
* A self-contained ET_DYN loader-entry fixture with ELF-header references and
  FSGSBASE instructions, verifying native reassembly without a CRT. Native
  baseline mode checks instruction equivalence without imposing GS-policy
  eligibility or requiring REP scratch; it is not a GS artifact.
* Heap, RIP, stack alias/LEAVE, indirect call/jump, generated PLT, and existing FS
  accesses at nonzero GS, including IFUNC-selected implementations and direct
  execution of a resolver with original library data inaccessible.
* 384 combinations of arithmetic flags, DF, and zero/one/multiple-element counts
  for each of 16 MOVS/STOS forms (four widths, repeated/plain), across original
  GS=0, native-reassembly GS=0, rewritten GS=0, and rewritten GS=16 MiB:
  24,576 executions. The original uninstrumented shifted control must SIGSEGV.
* Local-exec TLS executables (direct `%fs:` and relaxed `%fs:0` + `sym@tpoff`
  forms) in multiple threads, including a tampered thread-pointer offset.
* Initial-exec TLS in multiple threads, version aliases at distinct addresses,
  pre-biased table walks, and LOCK-skipping branches.
* Partial REP fault/restart and nested scratch use.
* Deliberately uncovered original/PLT/padding accesses, corrupted RIP and LSDA
  references, stale TLS layout and frame index, a GS-bypassing LOCK suffix, and
  a changed immediate next to symbolic memory.

The host's existing stripped `/usr/bin/true` was also recovered, rewritten,
validated, and executed without source: 4,123 recovered non-PLT instructions,
135 retired PLT instructions, 46 generated slots, and 107 FDEs. These counts
describe that tested binary, not every distribution's `true`.

Compare the three controls with paired, rotating-order whole-process timings:

```sh
.venv/bin/gsfork-elf compare /path/to/program \
    /path/to/program.gs.gsfork/baseline /path/to/program.gs --samples 31
```

The command verifies control hashes and output equality, performs three warmups,
and reports median/minimum/p95 wall time, ELF sizes, baseline/original ratio, and
GS/baseline ratio. `--arg VALUE` supplies a program argument. These timings include
process startup and are **not** isolated instruction-overhead measurements.
Use a runtime-integrated workload for nonzero-GS throughput measurements; the
older prototype's performance data is not evidence for this new pipeline.

## glibc 2.35 target status

Both supplied linked inputs, `../../glibc-2.35/build/elf/ld.so` and
`../../glibc-2.35/build/libc.so`, have been rewritten and passed final validation.
No functions or IFUNC implementations were exempted.

| Artifact | Recovered non-PLT instructions | Generated PLT slots | String wrappers | FDEs | Exception call sites |
|---|---:|---:|---:|---:|---:|
| Loader | 37,752 | 9 | 5 | 302 | 0 |
| libc | 372,188 | 103 | 104 | 3,711 | 218 |

All nine combinations of original/native-reassembled/GS-rewritten loader and
original/native-reassembled/GS-rewritten libc passed **both**:

* C: constructors, allocation/free, memcpy/memset IFUNCs, backtraces, pthread
  creation/join, and per-thread TLS.
* C++: backtraces, exception propagation, cleanup/landing pads, and destructors.

The three loaders also produce identical `--help` output after normalizing their
invocation paths, including the recovered hardware-capability table.
These whole-library tests run at GS=0 with explicitly reserved scratch. The
separate nonzero-GS runtime suite tests translation, aliases, TLS, IFUNC resolvers,
all supported string forms, and interrupted/nested scratch use. This is evidence
for the supplied build and corpus, not a universal glibc compatibility claim or
a production implementation of nonzero-GS kernel/library transitions.

From this directory, choose **new output paths** and run:

```sh
mkdir -p build/glibc
.venv/bin/gsfork-elf rewrite \
    ../../glibc-2.35/build/elf/ld-linux-x86-64.so.2 build/glibc/ld.gs \
    --scratch-rax=-16 --sandbox-offset=-8
.venv/bin/gsfork-elf rewrite \
    ../../glibc-2.35/build/libc.so.6 build/glibc/libc.gs \
    --scratch-rax=-16 --sandbox-offset=-8 \
    --trust-library ld-linux-x86-64.so.2 -L ../../glibc-2.35/build/elf
.venv/bin/gsfork-elf validate build/glibc/ld.gs
.venv/bin/gsfork-elf validate build/glibc/libc.gs
```

The offsets above are the **test ABI**, not safe arbitrary defaults for another
program. The acceptance fixtures explicitly reserve and verify the final 16 TLS
bytes. Early loader paths must not reach a scratch-using wrapper before its FS
storage is valid; a production runtime must arrange that prerequisite.

Run the reproducible matrix with:

```sh
.venv/bin/python tests/check_glibc.py \
    --build ../../glibc-2.35/build \
    --loader build/glibc/ld.gs --libc build/glibc/libc.gs \
    --cxx-runtime /path/to/compatible-cxx-runtime
```

The optional C++ runtime directory needs compatible `libstdc++.so`,
`libstdc++.so.6`, `libgcc_s.so`, and `libgcc_s.so.1`; the tested runtime came from
an existing Ubuntu 22.04 image. Newer host C++ libraries can require GLIBC_2.36/
2.38 and cannot be used with glibc 2.35 even before rewriting. Without
`--cxx-runtime`, the script explicitly runs only the nine C combinations.
The script validates both artifacts and their original/native control hashes
before executing any combination, and emits a JSON result.
