import re
import struct
import tempfile

from Numbers import converter

import arch

class Arch(arch.Arch):
    def __init__(self, is_64_bit=True):
        super(Arch, self).__init__(binutils_prefix='')
        self.is_64_bit = is_64_bit
        self.padding_modulu = 5
        if is_64_bit:
            self.stack_pointer = 'rsp'
            self.base_pointer = 'rbp'
            self.registers = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi']
            #in x86 64 bit you must push/pop 64 bit only
            self.push = 'pushq'
            self.pop = 'popq'
            self.jmp = 'jmpq'
            self.call = 'callq'
        else:
            self.stack_pointer = 'esp'
            self.base_pointer = 'ebp'
            self.registers = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi']
            self.push = 'push'
            self.pop = 'pop'
            self.jmp = 'jmp'
            self.call = 'call'
        self.registers += [self.base_pointer, self.stack_pointer]

    def get_branch(self, source_address, to_address):
        relative_address = to_address - source_address - 5
        return '\xe9' + struct.pack('<I',
                converter.to_unsigned_int(relative_address))

    def get_registers_dumper(self, registers):
        lines = '{0} %{1}\nmov %{2},%{1}\n'.format(self.push,
                                                self.base_pointer,
                                                self.stack_pointer)
        lines += 'pushf\n'
        for reg in registers:
            lines += '{0} %{1}\n'.format(self.push, reg)
        #assemble all of this
        return self.assemble(lines)

    def get_registers_loader(self, registers):
        space = len(registers) * 4
        lines = ''
        #reverse the order of the registers (since its the stack..)
        for reg in registers[::-1]:
            lines += '{0} %{1}\n'.format(self.pop, reg)
        lines += 'popf\n'
        lines += '{0} %{1}'.format(self.pop, self.base_pointer)
        #assemble all of this
        return self.assemble(lines)

    def get_nop(self):
        return '\x90'

    def get_call(self, source_address, destination_address):
        relative_address = destination_address - source_address - 5
        return '\xe8' + struct.pack('<I',
                converter.to_unsigned_int(relative_address))

    def relocate(self, code, new_address):
        return self._relocate(code, new_address, '(j[a-z][a-z])|(j[a-z][a-z]q)|(call)')
