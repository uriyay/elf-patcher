import subprocess
import re
import copy

from Logger import Tracer
from executable import Section, Executable

tracer = Tracer.PrintTracer()

#Exceptions
class PaddingError(Exception):
    pass

class FailedToGetDisasMatch(Exception):
    pass

###
#Constants
PADDING_MULTIPLE = 20

###

class PatchEntry(object):
    def __init__(self, virtual_address, data, patch_name, original_data=None, description=None):
        self.virtual_address = virtual_address
        self.data = data
        self.size = len(data)
        self.patch_name = patch_name
        if original_data is not None:
            assert self.size == len(original_data), '%d != %d' % (self.size, len(original_data))
        self.original_data = original_data
        self.description = description

    def __str__(self):
        return 'PatchEntry %s - %s (start = 0x%x, size = 0x%x)' % (
                self.patch_name, self.description,
                self.virtual_address, self.size)

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

    def get_branch_data(self, source_address, dest_address):
        '''
        Returns: (branch_data, overriden_dat, overriden_data_disas)
        '''
        #get branch to hook_glue
        branch = self.arch.get_branch(source_address, dest_address)

        #get overriden data
        branch_size = len(branch)
        overriden_data_disas_to_compare = self.arch.disas(self.binary.filename,
                source_address, source_address + branch_size + self.arch.padding_modulu * PADDING_MULTIPLE)
        got_disas_match = False
        for i in xrange(PADDING_MULTIPLE):
            overriden_data_disas = self.arch.disas(self.binary.filename,
                    source_address, source_address + branch_size + self.arch.padding_modulu * i)
            if overriden_data_disas in overriden_data_disas_to_compare:
                got_disas_match = True
                break
        if not got_disas_match:
            raise FailedToGetDisasMatch('Failed to got disas match of overriden_data_disas in overriden_data_disas_to_compare')
        branch = branch + self.arch.get_nop() * (self.arch.padding_modulu * i)
        overriden_data = self.binary.get_data(source_address, len(branch))

        tracer.trace('branch = %s, len = %d' % (branch.encode('hex'), len(branch)))
        tracer.trace('overriden_data = %s, length = %d\n%s\n' % (overriden_data.encode('hex'),
                len(overriden_data), overriden_data_disas))

        return branch, overriden_data, overriden_data_disas
    
    def get_hook_glue_data(self, hook_exe, hook_symbol_to_jump_to, overriden_data_disas, hook_glue_address, return_address):
        '''
        Returns hook_glue
        '''
        #get hook_glue
        registers = self.arch.registers
        #dump registers
        hook_glue = self.arch.get_registers_dumper(registers)
        #nop padding
        hook_glue = self.pad_nops(hook_glue, self.arch.padding_modulu)
        #call hook_data
        hook_glue += self.arch.get_call(hook_glue_address + len(hook_glue),
                                        hook_exe.get_symbol_by_name(hook_symbol_to_jump_to).virtual_address)
        #load back registers
        hook_glue += self.arch.get_registers_loader(registers)
        #do original code
        relocated_overriden_data = self.arch.relocate(overriden_data_disas,
                    hook_glue_address + len(hook_glue))
        tracer.trace('relocated_overriden_data - %s, len - %d, address - 0x%x' % (relocated_overriden_data.encode('hex'),
                len(relocated_overriden_data), hook_glue_address + len(hook_glue)))
        hook_glue += relocated_overriden_data
        #jump back after hook
        hook_glue += self.arch.get_branch(hook_glue_address + len(hook_glue), return_address)
        tracer.trace('hook_glue: %s, len - %d, at address - 0x%x, ends at - 0x%x' % (hook_glue.encode('hex'),
                len(hook_glue), hook_glue_address, hook_glue_address + len(hook_glue)))

        return hook_glue

    def get_patch(self,
             #hook
             hook_address,
             #hook glue
             hook_glue_address,
             #hook data
             hook_filename,
             hook_symbols_to_paste,
             hook_symbol_to_jump_to=None):
        '''
        This function will patch self.binary, it will generate a branch to a hook glue:
        a place where registers backup, jump to your hook code, load registers load, hook-overriden code and jump back after hook.
        param hook_address: the branch address in the target executable to jump from
        param hook_glue_address: where the hook glue will be
        param hook_symbol_to_jump_to: the name of symbol in hook_filename to jump to
        param hook_filename: your hook code file name
        param hook_symbols_to_paste: which symbols from your hook code elf will be injected
        return value: patch_table - a list of PatchEntry's
        '''

        #preparations
        if hook_symbol_to_jump_to is None:
            hook_symbol_to_jump_to = 'main'
        tracer.trace('Hooking %s at 0x%x with %s, hook_glue at 0x%x, hook_symbol_to_jump_to is %s' % (
            self.binary.filename, hook_address, hook_filename, hook_glue_address, hook_symbol_to_jump_to))
        hook_exe = Executable(hook_filename, self.arch)

        branch, overriden_data, overriden_data_disas = self.get_branch_data(hook_address, hook_glue_address)
        hook_glue = self.get_hook_glue_data(hook_exe,
                                            hook_symbol_to_jump_to,
                                            overriden_data_disas,
                                            hook_glue_address,
                                            hook_address + len(branch))

        #prepare patch table
        patch_table = []

        for sym in hook_exe.symbols:
            if sym.name in hook_symbols_to_paste:
                patch_table.append(PatchEntry(sym.virtual_address, sym.data, 'hook_symbol_%s' % (sym.name),
                                              self.binary.get_data(sym.virtual_address, len(sym.data)), 'hook symbol'))

        patch_table.append(PatchEntry(hook_glue_address, hook_glue, 'hook_glue', self.binary.get_data(hook_glue_address, len(hook_glue)),
                                      'hook glue'))

        patch_table.append(PatchEntry(hook_address, branch, 'branch', overriden_data, 'branch to hook_glue'))

        return patch_table

    def write_binary_to_file(self, output_filepath):
        with file(output_filepath, 'wb') as f:
            f.write(self.binary.build())

    def patch_binary(self, patch_table, output_filepath):
        '''
        This function will apply patch table on self.binary and will save it to output_filepath
        Note that this function will change self.binary
        if you want to undo the operation of this function - call undo_patch_binary()
        param patch_table: a list of PatchEntry's
        param output_filepath: a filepath to write the patched binary to
        '''
        for patch_entry in patch_table:
            tracer.trace('pasting patch %s' % (str(patch_entry)))
            self.binary.set_data(patch_entry.virtual_address, patch_entry.data)

        self.write_binary_to_file(output_filepath)

    def create_undo_table(self, patch_table):
        '''
        patch_entry.original_data will be patch data,
        and patch_entry.data will be original_data
        '''
        undo_table = copy.deepcopy(patch_table)
        for undo_entry in undo_table:
            undo_entry.original_data, undo_entry.data = undo_entry.data, undo_entry.original_data
        return undo_table

    def undo_patch_binary(self, patch_table):
        '''
        See doc of patch_binary
        '''
        for undo_entry in self.create_undo_table(patch_table):
            tracer.trace('binary undo %s' % (str(undo_entry)))
            self.binary.set_data(undo_entry.virtual_address, undo_entry.data)

    def hot_patch(self, patch_table, hot_patcher, should_read_original_data=True):
        '''
        This function will apply patch table by hot patching with a hot_patcher object.
        Note that this function will change a running thing (can be a process or what-ever you need it to be),
        if you want to undo the operation of this function - call undo_hot_patch()
        Note2: if you want to hot patch slowly then pass a partial patch_table (the same for undo_hot_patch)
        param patch_table: a list of PatchEntry's
        param hot_patcher: an object of a class that inherits HotPatcher (which is abstract class)
        param should_read_original_data: if you pass True - the original data will be read before patching
        '''
        for patch_entry in patch_table:
            tracer.trace('hot patch %s' % (str(patch_entry)))
            if verify_original_data:
                tracer.trace('reading original data')
                patch_entry.original_data = hot_patcher.read(patch_entry.virtual_address, patch_entry.size)
            hot_patcher.write(patch_entry.virtual_address, patch_entry.data)

    def undo_hot_patch(self, patch_table, hot_patcher):
        for undo_entry in self.create_undo_table(patch_table):
            tracer.trace('hot undo %s' % (str(undo_entry)))
            hot_patcher.write(undo_entry.virtual_address, undo_entry.data)

