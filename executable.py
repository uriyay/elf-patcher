import re
import struct
import subprocess

from StringIO import StringIO
from elftools.elf.elffile import ELFFile

from Numbers import converter

class FindSymbolError(Exception):
    pass

class FindSymbolTooManyMatches(Exception):
    pass

class FindSectionError(Exception):
    pass

class FindSectionTooManyMatches(Exception):
    pass

class Symbol(object):
    def __init__(self, name, virtual_address, size, file_offset, data):
        '''
        param name: section name
        param virtual_address: virtual address of section at runtime
        param size: section size
        param file_offest: offset to section in the executable file
        param data: section data
        '''
        self.name = name
        self.virtual_address = virtual_address
        self.size = size
        self.file_offset = file_offset
        self.data = data

    def __str__(self):
        return '%s: virtual_address=0x%x, file_offset=0x%x, size=0x%x' % (self.name, self.virtual_address, self.file_offset, self.size)

class Section(Symbol):
    pass

class Executable(object):
    '''
    Represents an executable file (elf, mostly).
    Its stores sections and make it easy to modify the executable sections data.
    '''
    def __init__(self, filename, arch_obj):
        '''
        param filename: executable filename
        param arch_obj: one of arch class in arch_*.py
        '''
        self.filename = filename
        self.data = open(filename, 'rb').read()
        self._elffile = ELFFile(StringIO(self.data))
        self.arch = arch_obj
        self.sections = self.get_sections()
        self.symbols = self.get_symbols()

    def get_sections(self):
        '''
        Returns: list of Section's
        '''
        sections = []
        for sect in self._elffile.iter_sections():
            sect_name = sect.name
            virtual_address = sect.header.sh_addr
            size = sect.header.sh_size
            file_offset = sect.header.sh_offset
            data = self.data[file_offset : file_offset + size]
            sections.append(Section(sect_name, virtual_address, size, file_offset, data))
        return sections

    def get_symbols(self):
        '''
        This function will return the symbols that appears in the elf
        '''
        symbols = []
        symtab = self._elffile.get_section_by_name('.symtab')
        dynsym = self._elffile.get_section_by_name('.dynsym')
        rela_plt = self._elffile.get_section_by_name('.rela.plt')
        if symtab is not None:
            for sym in symtab.iter_symbols():
                sym_name = sym.name
                if sym_name == '':
                    continue
                virtual_address = sym.entry.st_value
                size = sym.entry.st_size
                file_offset = self.address_to_offset(virtual_address)
                if file_offset is not None:
                    data = self.data[file_offset : file_offset + size]
                else: data = ''
                symbols.append(Symbol(sym_name, virtual_address, size, file_offset, data))
        if dynsym is not None:
            for sym in dynsym.iter_symbols():
                sym_name = sym.name
                if sym_name == '':
                    continue
                virtual_address = 0
                for reloc in rela_plt.iter_relocations():
                    if dynsym.get_symbol(reloc['r_info_sym']).name == sym_name:
                        function_plt_pointer = self.address_to_offset(reloc['r_offset'])
                        is_little_endian = self._elffile.little_endian
                        is_64_bit = self.arch.__dict__.get('is_64_bit', False)
                        address_data = self.data[function_plt_pointer:function_plt_pointer + 8]
                        virtual_address = converter.parse_address(address_data, is_64_bit, is_little_endian) - 6
                #get the real virtual address
                size = sym.entry.st_size
                file_offset = self.address_to_offset(virtual_address)
                if file_offset is not None:
                    data = self.data[file_offset : file_offset + size]
                else:
                    data = ''
                symbols.append(Symbol(sym_name, virtual_address, size, file_offset, data))
        return symbols

    def get_symbol_by_name(self, name):
        matches = [x for x in self.symbols if x.name == name]
        matches_count = len(matches)
        if matches_count < 1:
            raise FindSymbolError('Cannot find symbol %s' % (name))
        elif matches_count > 1:
            raise FindSymbolTooManyMatches('There is more than one match to %s symbol' % (name))
        return matches[0]

    def get_section_by_name(self, name):
        matches = [x for x in self.sections if x.name == name]
        matches_count = len(matches)
        if matches_count < 1:
            raise FindSectionError('Cannot find section %s' % (name))
        elif matches_count > 1:
            raise FindSectionTooManyMatches('There is more than one match to %s section' % (name))
        return matches[0]

    def address_to_offset(self, address):
        for sect in self.sections:
            if address >= sect.virtual_address and address < (sect.virtual_address + sect.size):
                return sect.file_offset + (address - sect.virtual_address)
        return None

    def get_data(self, start_address, size):
        offset = self.address_to_offset(start_address)
        assert offset is not None
        return self.data[offset : offset + size]

    def set_data(self, start_address, data):
        if start_address is None:
            start_address = self.sections[0].virtual_address

        offset = self.address_to_offset(start_address)
        assert offset is not None
        self.data = self.data[:offset] + data + self.data[offset + len(data):]

    def build(self):
        return self.data
