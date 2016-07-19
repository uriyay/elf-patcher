import re
import struct
import tempfile

from Numbers import converter

import arch

class ArchArm32LittleEndian(arch.Arch):
    def __init__(self, is_64_bit=False):
        super(ArchArm32LittleEndian, self).__init__(binutils_prefix='')

    def get_branch(self, source_address, to_address, should_link=False):
        offset24 = converter.to_unsigned((to_address - source_address) >> 1)
        result =  0xea000000 + offset24
        if should_link:
            result |= (1 << 24)
        return result

    def get_registers_dumper(self, registers):
        #not saving the stack
        lines = 'stmfd sp!,{r0-r12,r14-r15}'
        #assemble all of this
        return self.assemble(lines)

    def get_registers_loader(self, registers):
        lines = 'ldmfd sp!,{r0-r12,r14-r15}'
        #assemble all of this
        return self.assemble(lines)

    def get_nop(self):
        #TODO: return a printable nop
        return '\x00\x00\x00\x00'

    def get_call(self, source_address, destination_address):
        return self.get_branch(source_address, destination_address, should_link=True)

    def relocate(self, code, new_address):
        return self._relocate(code, new_address, 'b[a-z][a-z]')
