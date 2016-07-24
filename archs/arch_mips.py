import re
import struct
import tempfile

from Numbers import converter

import arch

class Arch(arch.Arch):
    def __init__(self, binutils_prefix):
        super(Arch, self).__init__(binutils_prefix)
        self.padding_modulu = 8 #for jump and nop
        self.stack_pointer = 'sp'
        self.base_pointer = 'fp'
        self.registers = ['v0', 'v1', 'a0', 'a1', 'a2', 'a3', 't0', 't1', 't2', 't3', 's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 'gp', 'ra']
        self.registers += [self.stack_pointer, self.base_pointer]

    def get_branch(self, source_address, to_address, should_link=False):
        '''
        Returns j/jal
        '''
        offset26 = ((source_address & 0xf0000000) | converter.to_unsigned_int(to_address << 2)) >> 4
        result = 0
        if should_link:
            result = (0b000011 << 26) | offset26
        else:
            result = (0b000010 << 26) | offset26
        #we must add nop after a branch, otherwise the next instruction will be executed too
        return struct.pack('<I', result) + self.get_nop()

    def get_registers_dumper(self, registers):
        lines = 'addi $sp, $sp, -%d\n' % (len(registers) * 4)
        stack_index = len(registers)
        for reg in self.registers:
            lines += 'sw ${}, {}(${})\n'.format(reg, (stack_index * 4), self.stack_pointer)
            stack_index -= 1
        #assemble all of this
        return self.assemble(lines)

    def get_registers_loader(self, registers):
        stack_index = len(registers)
        for reg in self.registers:
            lines += 'lw ${}, {}(${})\n'.format(reg, (stack_index * 4), self.stack_pointer)
            stack_index -= 1
        lines = 'addi $sp, $sp, %d\n' % (len(registers) * 4)
        #assemble all of this
        return self.assemble(lines)

    def get_nop(self):
        #add 0, 0, 0
        return '\x20\x00\x00\x00'

    def get_call(self, source_address, destination_address):
        return self.get_branch(source_address, destination_address, should_link=True)

    def relocate(self, code, new_address):
        return self._relocate(code, new_address, '(b|j)[a-z][a-z]')
