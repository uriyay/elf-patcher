import subprocess
import re

from Logger import Tracer

tracer = Tracer.PrintTracer()

class Section(object):
    def __init__(self, name, virtual_address, size, file_offset, data):
        self.name = name
        self.virtual_address = virtual_address
        self.size = size
        self.file_offset = file_offset
        self.data = data

class Executable(object):
    '''
    Represents an executable file (elf, mostly).
    Its stores sections and make it easy to modify the executable sections data.
    '''
    def __init__(self, filename, arch_obj):
        self.filename = filename
        self.data = open(filename, 'rb').read()
        self.objdump_name = arch_obj.objdump_name
        self.sections = self.get_sections()

    def get_sections(self):
        '''
        Returns: list of Section's
        '''
        command = '%s -h %s' % (self.objdump_name,
                                self.filename)
        objdump_command = subprocess.Popen(command.split(' '),
                                           stdout=subprocess.PIPE)
        objdump_output = objdump_command.stdout.read()
        sections = []
        for line in objdump_output.split('\n'):
            if re.search(' *\d+ +.* [0-9a-f]+ +[0-9a-f]+ +[0-9a-f]+ +[0-9a-f]+ + .*', line):
                parts = re.split(' +', line)
                sect_name = parts[2]
                virtual_address, size, file_offset = (int(x, 16) for x in [parts[4],
                                                                           parts[3],
                                                                           parts[6]])
                data = self.data[file_offset : file_offset + size]
                sections.append(Section(sect_name, virtual_address, size, file_offset, data))
        return sections

    def address_to_offset(self, address):
        for sect in self.sections:
            if address >= sect.virtual_address and address < (sect.virtual_address + sect.size):
                return sect.file_offset + (address - sect.virtual_address)
        return None

    def get_data(self, start_address=None, end_address=None):
        if start_address is None:
            start_address = self.sections[0].virtual_address
        if end_address is None:
            end_address = self.sections[-1].virtual_address

        assert start_address <= end_address

        offset = self.address_to_offset(start_address)
        assert offset is not None
        size = end_address - start_address
        return self.data[offset : offset + size]

    def set_data(self, start_address, data):
        if start_address is None:
            start_address = self.sections[0].virtual_address

        offset = self.address_to_offset(start_address)
        assert offset is not None
        self.data = self.data[:offset] + data + self.data[offset + len(data):]

    def build(self):
        return self.data

class PaddingError(Exception):
    pass

class Patcher(object):
    def __init__(self, binary_filename, arch_obj):
        self.binary = Executable(binary_filename, arch_obj)
        self.arch = arch_obj

    def pad_nops(self, data, padding):
        '''
        param data: the original data to be padded
        param padding: modulu for len(data) to be devide by
        returns: the original data with nops after it,
                 so the bytes count will devide by padding
        notes: currently there is a support in one byte nop only
        '''
        nop = self.arch.get_nop()
        nop_size = len(nop)
        data_size = len(data)
        if padding % nop_size != 0:
            raise PaddingError('padding %d not divides by nop_size (%d)' % (padding, nop_size))
        size_to_pad = padding - (data_size % padding)
        if size_to_pad % nop_size != 0:
            raise PaddingError('cannot pad data_size %d to %d, because size_to_pad = %d and nop_size = %d' % (
                data_size, data_size + size_to_pad, size_to_pad, nop_size))

        if data_size % padding != 0:
            data += nop * (size_to_pad / nop_size)
        #If I somehow got mistake here -
        if len(data) % padding:
            raise PaddingError('I padded it but it still not padded.. a programmer error..')
        tracer.trace('length of new data after padding is %d, new_data = %s' % (len(data), data.encode('hex')))
        return data

    def hook(self,
             #hook
             hook_address,
             padding_modulu,
             #hook glue
             hook_glue_address,
             hook_data_address,
             #hook data
             hook_filename,
             hook_sections_names,
             #output
             output_filepath):
        '''
        This function will patch self.binary, it will generate a branch to a hook glue:
        a place where registers backup, jump to your hook code, load registers load, hook-overriden code and jump back after hook.
        param hook_address: the branch address in the target executable to jump from
        param padding_modulu: see pad_nops(), sometimes you must put nops after branch (like in MIPS)
        param hook_glue_address: where the hook glue will be
        param hook_data_address: where your hook code will seat
        param hook_filename: your hook code file name
        hook_sections_names: which sections from your hook code elf will be injected
        output_filepath: where the patched target will be stored
        '''

        #get branch to hook_glue
        tracer.trace('Hooking at 0x%x (padding_modulu = %d), hook_glue at 0x%x, hook_data at 0x%x' % (
            hook_address, padding_modulu, hook_glue_address, hook_data_address))
        branch = self.arch.get_branch(hook_address, hook_glue_address)
        branch = self.pad_nops(branch, padding_modulu)
        tracer.trace('branch = %s, len = %d' % (branch.encode('hex'), len(branch)))
        #get overriden data
        overriden_data_size = len(branch)
        overriden_data = self.binary.get_data(hook_address,
                            hook_address + overriden_data_size)
        overriden_data_disas = self.arch.disas(self.binary.filename,
                hook_address, hook_address + overriden_data_size)
        tracer.trace('overriden_data = %s, length = %d\n%s\n' % (overriden_data.encode('hex'),
                len(overriden_data), overriden_data_disas))
        
        #get hook_glue
        registers = self.arch.registers
        #dump registers
        hook_glue = self.arch.get_registers_dumper(registers)
        #nop padding
        hook_glue = self.pad_nops(hook_glue, padding_modulu)
        #call hook_data
        hook_glue += self.arch.get_call(hook_glue_address + len(hook_glue),
                                        hook_data_address)
        #load back registers
        hook_glue += self.arch.get_registers_loader(registers)
        #do original code
        relocated_overriden_data = self.arch.relocate(overriden_data_disas,
                    hook_glue_address + len(hook_glue))
        tracer.trace('relocated_overriden_data - %s, len - %d, address - 0x%x' % (relocated_overriden_data.encode('hex'),
                len(relocated_overriden_data), hook_glue_address + len(hook_glue)))
        hook_glue += relocated_overriden_data
        #jump back after hook
        hook_glue += self.arch.get_branch(hook_glue_address + len(hook_glue),
                hook_address + overriden_data_size)
        tracer.trace('hook_glue: %s, len - %d, at address - 0x%x, ends at - 0x%x' % (hook_glue.encode('hex'),
                len(hook_glue), hook_glue_address, hook_glue_address + len(hook_glue)))

        #put hook data
        hook_exe = Executable(hook_filename, self.arch)
        for sect in hook_exe.sections:
            self.binary.set_data(sect.virtual_address, sect.data)

        #put hook_glue
        self.binary.set_data(hook_glue_address, hook_glue)

        #put hook
        self.binary.set_data(hook_address, branch)

        file(output_filepath, 'wb').write(self.binary.build())
