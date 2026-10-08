# Rewriter test framework

Run the complete rewriter-specific framework with:

```sh
make rewriter-test
```

It has four layers:

1. **Instruction policy matrix** — `tests/rewrite_cases.json` is a
   data-driven set of machine-code inputs, accepted/rejected outcomes, expected
   GS prefixes, code-size changes, and branch targets. The runner is
   `rewrite_test_framework.py`.
2. **Focused Python unit tests** — `tests/test_rewrite.py` covers dynamic cases
   such as branch expansion, and `tests/test_mibench_rewrite.py` covers the
   reviewed MiBench operand selector.
3. **ELF and fault validation** — `validate.py` rewrites linked functions in
   reserved slots, executes all kernel/mapping combinations, and requires
   missing-rewrite controls to SIGSEGV.
4. **Fork topology validation** — `fork_validate.py` performs real forks from
   the modeled parent stack, immediately moves children to reserved child
   stacks, audits decoded operands, validates GS aliases and indirect control
   flow, repeats each mode 16 times, and requires the unrewritten shifted
   control to SIGSEGV.

## Adding an instruction case

Add an object to `tests/rewrite_cases.json`:

```json
{
  "name": "fork-example-load",
  "policy": "fork",
  "hex": "488b07c3",
  "expected": {
    "edits": 1,
    "segments": ["GS", "NONE"],
    "length_delta": 1
  }
}
```

Use `"policy": "restricted"` for the original allowlisted transformer or
`"policy": "fork"` for the broad RIP/RSP-excluding policy. A rejection case
uses an expected error substring:

```json
{
  "name": "fork-reject-string",
  "policy": "fork",
  "hex": "f3a4c3",
  "error": "multiple explicit memory operands"
}
```

Supported assertions are:

- `edits`: number of operands selected by the policy;
- `segments`: explicit segment-prefix sequence after decoding (`GS`, `CS`, or
  `NONE`);
- `length_delta`: output size minus input size;
- `output_hex`: exact encoded bytes;
- `branch_targets`: decoded instruction index to expected target address.

Run only the matrix while developing a new rule:

```sh
python3 rewrite_test_framework.py
```

The runner prints a JSON summary and prefixes failures with the case name.
