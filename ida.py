import idc
import idaapi
import idautils

BADADDR = idaapi.BADADDR

def op_count(ea):
    c = 0
    idaapi.decode_insn(ea)
    for c, v in enumerate(idaapi.cmd.Operands):
        if v.type == idaapi.o_void:
            return c
        continue

    return c