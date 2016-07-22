import os
import re
import subprocess
import tempfile

from Logger import Tracer

import generate_lds

tracer = Tracer.PrintTracer()

class LdsConfig(object):
    symbols = {}
    hook_sections = {}
    memory_layout = []

class Arch(object):
    def __init__(self, binutils_prefix):
        '''
        @param binutils_prefix: like mips-gnu-elf-
        '''
        self.assembler_name = binutils_prefix + 'as'
        self.objcopy_name = binutils_prefix + 'objcopy'
        self.linker_name = binutils_prefix + 'ld'
        self.objdump_name = binutils_prefix + 'objdump'
        self.nm_name = binutils_prefix + 'nm'

    def assemble(self,code, address=None,
            preserve_output=False, lds_config=None):
        if preserve_output:
            tracer_state = tracer.is_trace_on
            tracer.enable()
        tracer.trace('code = %s' % (code))
        object_name = tempfile.mktemp(prefix='obj', suffix='.o')
        elf_name = tempfile.mktemp(prefix='elf', suffix='.out')
        binary_name = tempfile.mktemp(suffix='.bin')
        #compile
        command = '%s -o %s --' % (self.assembler_name, object_name)
        tracer.trace(command)
        compiler = subprocess.Popen(command.split(' '),
                                    stdin=subprocess.PIPE)
        compiler.stdin.write(code)
        compiler.stdin.close()
        compiler.wait()
        #linkage
        if address is None:
            address = 0
        command = '%s -Ttext 0x%x -o %s %s' % (self.linker_name,
                                                 address,
                                                 elf_name,
                                                 object_name)
        if lds_config is not None:
            lds_script = generate_lds.generate_lds(lds_config.symbols,
                    lds_config.hook_sections)
            lds_script_file = tempfile.NamedTemporaryFile()
            lds_script_file.write(lds_script)
            command += ' -T %s' % (lds_script_file.name)
        tracer.trace(command)
        subprocess.call(command.split(' '))
        if lds_config is not None:
            lds_script_file.close()
        #objcopy
        command = '%s -O binary %s %s' % (self.objcopy_name,
                                                elf_name,
                                                binary_name)
        tracer.trace(command)
        subprocess.call(command.split(' '))
        data = open(binary_name, 'rb').read()
        #cleanup
        command = 'rm -f %s %s %s' % (object_name, elf_name, binary_name)
        tracer.trace(command)
        if not preserve_output:
            subprocess.call(command.split(' '))
        else:
            #cancel tracing
            if not tracer_state:
                tracer.disable()

        #return compiled data
        return data

    def disas(self, filename, start_address, end_address):
        '''
        @returns disassembly of range start_address to end_address
        '''
        command = '%s -d %s --start-address=0x%x --stop-address=0x%x --no-show-raw-insn' % (self.objdump_name,
                                           filename,
                                           start_address,
                                           end_address)
        tracer.trace(command)
        disas_cmd = subprocess.Popen(command.split(' '), stdout=subprocess.PIPE)
        disas_output = disas_cmd.stdout.read()
        disas_lines = []
        for line in disas_output.split('\n'):
            if re.search(' *[0-9a-f]+:[\t  ]+.+', line) is not None:
                disas_line = line.partition(':')[-1].split('<')[0]
                disas_lines.append(disas_line)
        return '\n'.join(disas_lines)

    def get_branch(self, source_address, to_address):
        raise NotImplemented()

    def get_registers_dumper(self, registers):
        '''
        @param registers: list of registers names to protect on
        @returns: opcodes for protecting registers
        @desc: you will want to backup your registers before any hook occures, this is how you can do it.
        '''
        raise NotImplemented()

    def get_registers_loader(self, registers):
        '''
        @param registers: list of registers names to protect on
        @returns: opcodes for loading registers
        @desc: see get_registers_protector
        '''
        raise NotImplemented()

    def get_nop(self):
        raise NotImplemented()

    def get_call(self, source_address, destination_address):
        raise NotImplemented()

    def _relocate(self, code, new_address, branch_pattern):
        #get branches and loops
        lds_config = LdsConfig()
        code_lines = code.split('\n')
        symbol_name = '__sym_'
        for line in code_lines:
            if re.search(branch_pattern, line):
                line = line.strip()
                symbol_addr_string = line.split(' ')[-1]
                symbol_name = symbol_name + symbol_addr_string
                symbol_addr = int(symbol_addr_string, 16)
                lds_config.symbols[symbol_name] = symbol_addr

        lds_config.symbols['my_text_address'] = new_address
        #reassemble code to new_address with ld script
        return self.assemble(code, new_address, preserve_output=False, lds_config=lds_config)
