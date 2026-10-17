# GS-Fork ELF Rewriter

## Purpose and target

The GS-Fork ELF rewriter transforms standard, already-linked x86-64 Linux ELF executables and shared libraries for execution with GS-based data-address translation. It uses disassembly, symbolic rewriting, and reassembly to emit inline instrumented code.

**Support for linked executables is the architectural requirement and the first integration milestone.** Relocatable object files may be useful fixtures or intermediate outputs, but object rewriting is not the foundation or the acceptance target. The workflow must not require application source code, recompilation, or the original compiler-generated assembly. Stripped binaries and binaries without retained static relocations are target cases; their actual support must be established through validation.

This is a requirements document. Framework capabilities must be demonstrated on the supported input corpus; selecting a framework does not establish correctness or complete coverage for arbitrary binaries.

## Toolchain and architecture

- **Ddisasm:** recover instructions, code/data boundaries, symbolic references, and existing unwind information from linked ELF input.
- **GTIRB:** hold code, data, symbols, symbolic expressions, control flow, and auxiliary metadata, including CFI directives.
- **GS-Fork transformation:** rewrite instruction semantics while maintaining symbolic references and metadata associations.
- **gtirb-rewriting:** preferred mutation layer for implementing transformations and updating affected IR structures.
- **gtirb-pprinter:** emit reassemblable GNU assembly, including symbolic references and `.cfi_*` directives.
- **Assembler and linker:** encode the final instructions, resolve layout-dependent references, regenerate unwind records, and produce the output ELF.
- **Final artifact validator:** check coverage, linker-generated code, references, and required metadata after all transformations.

The integration layer should use the framework's supported APIs; Python is the natural initial implementation language for `gtirb-rewriting`. Rust and `iced-x86` may be retained for instruction analysis or encoding where useful, but are optional components. They must not force us to recreate the framework's ELF layout and metadata machinery.

Instrumentation is emitted inline. Per-memory-access detours or signal-based instruction emulation are not the intended execution model.

## Pipeline

1. Load an already-linked executable or shared object with Ddisasm, retaining normal CFI-directive generation.
2. Establish a no-transformation disassembly/reassembly baseline for the supported input.
3. Classify every recovered instruction and apply the GS-Fork rules in GTIRB.
4. Preserve or update symbolic references, code-boundary metadata, and exception/unwind information through each edit.
5. Emit assembly and assemble/relink it into the output ELF.
6. Instrument or otherwise account for newly generated linker code using an explicit supported strategy.
7. Validate the final artifact and reject any uncovered required access or unsupported construct.

The implementation must retain enough provenance to associate original instructions, generated sequences, and final code locations for diagnostics, coverage accounting, and signal/fault integration.

## Address model

### Data and code

Application data pointers are logical addresses. For an ordinary supported data-memory access, the runtime supplies the translation:

`actual address = logical address + GS.base`

Code addresses do not change across a GS-Fork fork. Offline rewriting and relinking may change addresses relative to the input executable; all affected references must be repaired before execution. Direct and register-indirect branch targets therefore remain code addresses. Memory-indirect branches translate the memory access that loads the target pointer, but do not add the data offset to the loaded code address.

RIP-relative data accesses also require translation: sharing code addresses does not make the referenced data shared. Rewriting must preserve the intended logical target when code layout changes.

### Stack aliases

The runtime provides two mappings of the same stack storage: one at the logical stack address and one at that address plus `GS.base`. Corresponding addresses in both mappings must refer to the same bytes throughout execution.

`%rsp` contains the logical stack address. That address is also directly usable by native stack instructions because the unshifted alias exists. Thus:

- Implicit stack accesses by supported native `push`, `pop`, `call`, and `ret` instructions use the unshifted mapping.
- Explicit stack-memory operands are rewritten to GS-relative accesses and use the shifted mapping.
- Copying `%rsp` into `%rbp` preserves a logical pointer. A subsequent access through `%rbp` is translated like any other explicit data-memory access.

For example:

```asm
movq %rsp, %rbp
movq $1, 8(%rbp)
```

becomes:

```asm
movq %rsp, %rbp
movq $1, %gs:8(%rbp)
```

`leave` must have an explicit handling rule. Its ordinary 64-bit semantics are `movq %rbp, %rsp; popq %rbp`. Under this alias model, both registers remain logical and no unconditional offset addition is required. Any expansion must preserve those semantics and flags. Nonstandard forms require a separate supported rule or rejection.

## Instruction rewrite contract

| Instruction or access | Required handling |
| --- | --- |
| Ordinary explicit load, store, or read-modify-write operand without a segment override | Rewrite to GS-relative access. |
| RIP-relative data-memory operand | Rewrite to GS-relative access and repair its displacement or relocation. |
| Memory-indirect `call` or `jmp` | Translate the target-pointer load; preserve the loaded code address and native stack behavior. |
| Direct or register-indirect branch | Preserve target semantics; repair encoded references when layout changes. |
| `lea` | Preserve logical-address computation; repair layout-dependent displacements or relocations. |
| Existing FS-relative access | Preserve according to the runtime TLS contract. |
| Existing GS-relative access in input code | Reject. |
| Other explicit segment overrides | Require an explicit handling rule; otherwise reject. |
| Supported implicit stack access | Preserve native behavior using the unshifted stack alias. |
| `leave` | Apply the explicit stack rule above. |
| String instruction | Apply a dedicated rule for the exact instruction form. |
| Any other implicit memory access | Reject unless covered by an explicit rewrite or preservation rule. |

GS-relative instructions generated by the rewriter are valid output; the input rejection rule prevents pre-existing GS usage from being mistaken for generated instrumentation. Generated runtime sequences must not be recursively rewritten.

Instruction classification must account for implicit memory operands, segment-override behavior, address size, operand size, flags, and control-flow effects. The presence of a syntactic memory operand alone is insufficient to determine the rewrite.

## String instructions and thread-local scratch

String instructions are treated as a family: `movs`, `stos`, `lods`, `cmps`, and `scas`, including their supported element widths and repetition prefixes. Each exact form must have a dedicated rule or be rejected. Support for `rep movsb` does not imply support for the other forms.

Instrumentation must preserve the instruction's register results, defined flags, direction-flag behavior, repeat termination, and zero-count behavior. Comparison and scan instructions require their own flag-handling rules; the MOVS wrapper below must not be reused unchanged for them.

Thread-local scratch and `SANDBOX_OFFSET` are accessed through FS. `SANDBOX_OFFSET` must equal the active GS base. The runtime must provide valid scratch storage before instrumented code executes and preserve scratch state across nested signal delivery. Signal and fault handling must account for interrupted instrumentation sequences, including temporarily translated register values and partially completed REP operations.

### Reference assembly: REP MOVSB

The previously developed wrapper is included below in GNU assembler AT&T syntax. `SCRATCH_RAX` and `SANDBOX_OFFSET` are fixed offsets in the runtime's FS-relative control region.

```asm
    # Save RAX and the original arithmetic flags before address arithmetic.
    movq %rax, %fs:SCRATCH_RAX
    lahf
    seto %al

    # Convert logical source and destination pointers to actual addresses.
    addq %fs:SANDBOX_OFFSET, %rdi
    addq %fs:SANDBOX_OFFSET, %rsi

    rep movsb

    # Restore logical post-copy pointer values.
    subq %fs:SANDBOX_OFFSET, %rdi
    subq %fs:SANDBOX_OFFSET, %rsi

    # Restore OF from AL, then SF/ZF/AF/PF/CF from AH.
    addb $0x7f, %al
    sahf
    movq %fs:SCRATCH_RAX, %rax
```

This sequence preserves RAX and all six arithmetic flags, leaves DF unchanged, retains native REP execution, and does not write to the application stack or red zone. RCX and the logical RSI/RDI values retain the results of the original instruction. The reference covers the ordinary 64-bit-address-size form; other address sizes need separate rules.

## ELF recovery and symbolic layout

The primary inputs are x86-64 ELF executables (`ET_EXEC` and PIE `ET_DYN`) and shared objects (`ET_DYN`). Input requirements and unsupported features must be explicit and tested.

ELF section and segment information identifies candidate code/data regions. Instruction boundaries, embedded data, and address-bearing values are recovered through Ddisasm's analysis. Section headers alone do not establish instruction-level boundaries. Symbols and retained relocations may improve recovery, but must not become an undocumented requirement for standard executable input.

The rewrite must preserve symbolic relationships for:

- Direct branches, calls, and RIP-relative accesses.
- Code and data pointers, jump tables, and address expressions.
- Dynamic symbols, symbol versions, relocations, GOT references, and library dependencies.
- Entry points, initialization/finalization code, and constructor/destructor arrays.
- Required unwind and exception metadata.

The assembler and linker determine new instruction sizes, displacements, and final addresses from these symbolic relationships. Direct edits to GTIRB bytes must not leave stale symbolic expressions, block offsets, CFI locations, or other auxiliary metadata.

The pipeline must reject reported recovery failures and unsupported constructs. It must not silently skip functions or treat successful disassembly as proof that all executable instructions have been recovered. The supported corpus and analysis assumptions must be documented. Self-modifying and dynamically generated code require a separate runtime strategy and are outside the initial static-rewriting contract.

## Unwind and exception metadata

### Recover rules, regenerate encodings

Existing unwind information must be recovered into CFI directives, kept associated with the correct semantic instruction boundaries through rewriting, and emitted by gtirb-pprinter. The assembler regenerates `.eh_frame` for the new code layout. The final link must generate a consistent `.eh_frame_hdr` when the output uses that index.

Keep Ddisasm's default CFI-directive generation enabled. Do not use `--no-cfi-directives` as the normal pipeline: its alternative raw `.eh_frame` representation is documented as experimental and unreliable.

For an instruction that only gains a GS prefix, the existing stack-recovery rules normally remain valid. Their positions must track the new layout. Reassembly then computes function ranges and instruction distances instead of the GS-Fork pass manually patching `DW_CFA_advance_loc` encodings.

For example:

```asm
.cfi_startproc
    pushq %rbp
.cfi_def_cfa_offset 16
.cfi_offset %rbp, -16
    movq %rsp, %rbp
.cfi_def_cfa_register %rbp

    movq %gs:(%rdi), %rax

    popq %rbp
.cfi_def_cfa %rsp, 8
    ret
.cfi_endproc
```

The directives following the load stay attached to the corresponding code boundaries even when its encoding grows.

### Semantic responsibility

The assembler encodes supplied unwind rules; it does not infer correct rules from arbitrary replacement instructions. A transformation that changes the CFA, saved-register locations, or other required recovery state must supply the appropriate CFI for its intermediate states. Instruction replacement and deletion must preserve directives that describe surrounding code, not inadvertently discard them.

The REP wrapper preserves stack layout, but its temporarily modified registers and FS scratch still require signal/fault handling. CFI regeneration does not replace that runtime contract.

### Exception tables and other metadata

Preserve personality references, LSDA references, exception call-site ranges, and landing-pad targets. `.cfi_personality` and `.cfi_lsda` describe associations; they do not automatically reconstruct `.gcc_except_table` contents. Exception data must retain the symbolic relationships needed for correct reassembly, and the chosen pipeline must demonstrate this on real exception-handling tests.

If required unwind information is absent or unsupported, do not claim reassembly can synthesize it automatically. Record the input limitation and reject cases that cannot satisfy the declared runtime requirements.

Debug information must either be correctly updated or explicitly removed under a documented policy; stale debug addresses must not be presented as valid.

## Startup code, linking, and final executable validation

Startup code already present in the input executable, including `register_tm_clones`, `deregister_tm_clones`, and related initialization/destruction routines, belongs to the rewrite coverage. There must be no silent exclusions based on function names or framework defaults.

Reassembly and relinking may introduce fresh startup objects, PLT entries, thunks, or instruction transformations. The integration must explicitly control startup-code retention versus regeneration to avoid both duplicate initialization and uninstrumented replacements. Do not assume that all code in the output passed through the GS-Fork transformation simply because all recovered input code did.

**Linker-generated code and transformations require validation. This validation is fully in scope and must be implemented.**

The implementation must choose and document a supported strategy for newly generated code, such as GS-aware linker emission or a bounded post-link transformation for recognized layouts. Such a transformation must preserve references and required unwind metadata and be followed by validation. Eager binding may simplify initial PLT handling, but does not remove the requirement to instrument its data accesses. Unsupported generated layouts must fail explicitly.

The validator must:

- Account for every recovered input instruction and every generated code region.
- Recognize intended GS accesses, approved FS accesses, and explicitly allowed implicit stack operations.
- Reject uncovered data-memory accesses and unsupported implicit-memory instructions.
- Validate direct targets and relevant symbolic references against the final layout.
- Check that linker transformations have not removed or invalidated instrumentation.
- Check unwind ranges, CFI boundaries, and exception-table references against final code.
- Reject uninstrumented generated code unless it belongs to an explicitly declared trusted runtime region.
- Report file, section, address, original location where available, and the violated rule.

Framework success, instruction counts, and static validation alone are not a proof of arbitrary-binary compatibility. They must be complemented by behavioral tests and explicit recovery assumptions.

Shared libraries must independently satisfy the instrumentation and validation contract or belong to an explicitly declared trusted runtime boundary. Executable validation does not establish coverage of dynamically loaded dependencies.

## Runtime responsibilities

The runtime supplies GS-base management, consistent stack aliases, FS-relative control storage, and signal/fault integration for instrumentation sequences. It also handles transitions to code or kernel interfaces that require actual addresses.

These runtime properties are prerequisites for correctness. This rewriter and its validator establish instruction coverage for the supported artifact; they do not alone establish the complete MPK isolation policy.

## Failure policy and acceptance criteria

Unsupported instructions, recovery failures, required metadata forms, and linker-generated layouts must fail with actionable diagnostics. Maintain an explicit list of supported instruction forms and handling rules. Partial instrumentation must never be reported as a successful GS-Fork artifact.

Implementation milestones are:

1. **Linked-executable round trip:** disassemble and reassemble representative existing executables and shared libraries without a semantic transformation. Verify execution, initialization/destruction, dynamic linking, stack unwinding, and C++ exception propagation with cleanup execution. Include stripped input and input without retained static relocations in the corpus.
2. **Inline GS transformation:** implement ordinary explicit memory access rules and verify behavior at zero and nonzero GS offsets under the runtime. Confirm pointer/reference repair after instruction expansion.
3. **Dedicated sequences:** implement supported string and implicit-memory rules, including the reference REP wrapper, and verify registers, flags, memory effects, and stack aliases.
4. **Final-link coverage:** implement handling and validation of new PLT/startup/thunk code and linker transformations. Reject deliberately introduced uncovered accesses.
5. **Metadata and interruption checks:** exercise backtraces, exception cleanup/landing pads, and signal delivery at rewritten locations, including nested scratch use and partially completed REP operations.
6. **Performance:** compare original, unmodified reassembly, and GS-rewritten output so that reassembly/layout effects are distinguished from instrumentation costs.

The architecture is accepted only when it demonstrates a viable path for standard linked executables. Passing object-file tests alone is insufficient.

## Framework references

- [Ddisasm command-line options and CFI generation](https://grammatech.github.io/ddisasm/GENERAL/3-Command-line-options.html)
- [GTIRB auxiliary metadata, including cfiDirectives](https://grammatech.github.io/gtirb/md__aux_data.html)
- [gtirb-rewriting](https://github.com/GrammaTech/gtirb-rewriting)
- [gtirb-pprinter](https://github.com/GrammaTech/gtirb-pprinter)
- [GNU assembler CFI directives](https://sourceware.org/binutils/docs/as/CFI-directives.html)
