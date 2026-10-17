import gtirb
from iced_x86 import Decoder, Mnemonic, OpAccess, OpKind, Register, RegisterExt

from .policy import INFO


def repair_masked_table_bases(module):
    """Recover pre-biased bases of a bounded, bit-filtered countdown table walk."""
    records = []
    for section in module.sections:
        if gtirb.Section.Flag.Executable not in section.flags:
            continue
        instructions = sorted((i for b in section.code_blocks
                               for i in Decoder(64, bytes(b.contents), ip=b.address)), key=lambda i: i.ip)
        blocks = sorted(section.code_blocks, key=lambda b: b.address)
        for index in range(len(instructions) - 7):
            step, decrement, done, one, count, shift, mask, skip = instructions[index:index + 8]
            if any(a.next_ip != b.ip for a, b in zip(instructions[index:index + 7],
                                                    instructions[index + 1:index + 8])):
                continue
            if ([i.mnemonic for i in (step, decrement, done, one, count, shift, mask, skip)]
                    != [Mnemonic.SUB, Mnemonic.SUB, Mnemonic.JB, Mnemonic.MOV, Mnemonic.MOV,
                        Mnemonic.SHL, Mnemonic.TEST, Mnemonic.JE]):
                continue
            if (step.op0_kind != OpKind.REGISTER or step.op0_register not in
                    (Register.RBX, Register.RBP, Register.R12, Register.R13, Register.R14, Register.R15)
                    or step.op1_kind not in (OpKind.IMMEDIATE8TO64, OpKind.IMMEDIATE32TO64)
                    or decrement.op1_kind not in (OpKind.IMMEDIATE8TO32, OpKind.IMMEDIATE32)
                    or decrement.immediate(1) != 1 or one.op0_register != Register.EDX
                    or one.op1_kind != OpKind.IMMEDIATE32 or one.immediate(1) != 1
                    or count.op0_register != Register.ECX or count.op1_register != decrement.op0_register
                    or shift.op0_register != Register.RDX or shift.op1_register != Register.CL
                    or mask.op0_register != Register.DL or mask.op1_kind != OpKind.IMMEDIATE8
                    or skip.near_branch_target != step.ip or done.near_branch_target <= skip.ip):
                continue
            previous = instructions[max(0, index - 32):index]
            if not previous or previous[-1].mnemonic != Mnemonic.JMP or previous[-1].near_branch_target != decrement.ip:
                continue
            loads = [i for i in previous if i.mnemonic == Mnemonic.LEA
                     and i.op0_register == step.op0_register and i.is_ip_rel_memory_operand]
            counts = [i for i in previous if i.mnemonic == Mnemonic.MOV
                      and i.op0_register == decrement.op0_register and i.op1_kind == OpKind.IMMEDIATE32]
            if not loads or not counts:
                continue
            load, initial = loads[-1], counts[-1].immediate(1)
            pointer_writes = [i for i in previous if i.ip > load.ip and any(
                RegisterExt.full_register(r.register) == step.op0_register
                and r.access in (OpAccess.WRITE, OpAccess.COND_WRITE, OpAccess.READ_WRITE, OpAccess.READ_COND_WRITE)
                for r in INFO.info(i).used_registers())]
            if pointer_writes:
                continue
            body = [i for i in instructions[index + 8:] if i.ip < done.near_branch_target]
            if any(RegisterExt.full_register(r.register) == step.op0_register
                   and r.access in (OpAccess.WRITE, OpAccess.COND_WRITE, OpAccess.READ_WRITE, OpAccess.READ_COND_WRITE)
                   for i in body for r in INFO.info(i).used_registers()):
                continue
            stride = step.immediate(1)
            if not 1 <= initial <= 64 or not 1 <= stride <= 256:
                continue
            targets = [load.ip_rel_memory_address - (initial - 1 - bit) * stride
                       for bit in range(min(initial, 8)) if mask.immediate(1) & (1 << bit)]
            if not targets:
                continue
            bases = [b for b in module.data_blocks if b.address is not None
                     and all(b.address <= target < b.address + b.size for target in targets)
                     and b.section.name not in (".dynamic", ".got", ".got.plt")]
            if len(bases) != 1:
                continue
            block = next(b for b in blocks if b.address <= load.ip < b.address + b.size)
            decoder = Decoder(64, bytes(block.contents)[load.ip - block.address:], ip=load.ip)
            instruction = decoder.decode()
            offset = load.ip - block.byte_interval.address + decoder.get_constant_offsets(instruction).displacement_offset
            expr = block.byte_interval.symbolic_expressions.get(offset)
            if (not isinstance(expr, gtirb.SymAddrConst) or expr.symbol.value is None
                    or expr.symbol.value + expr.offset != load.ip_rel_memory_address):
                continue
            base = bases[0]
            alias = gtirb.Symbol(f"__gsfork_table_{load.ip:x}", payload=base, module=module)
            block.byte_interval.symbolic_expressions[offset] = gtirb.SymAddrConst(
                load.ip_rel_memory_address - base.address, alias)
            records.append({"rule": "masked-countdown-table", "instruction": load.ip,
                            "symbol": alias.name, "original_base": base.address,
                            "offset": load.ip_rel_memory_address - base.address,
                            "accessed_targets": targets})
    return records
