import re
import subprocess

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
        self.objdump_name = arch_obj.objdump_name
        self.nm_name = arch_obj.nm_name
        self.sections = self.get_sections()
        self.symbols = self.get_symbols()

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

    def get_symbols(self):
        '''
        This function will return the symbols that appears in the elf
        '''
        command = '%s -S %s' % (self.nm_name,
                                self.filename)
        nm_command = subprocess.Popen(command.split(' '),
                                           stdout=subprocess.PIPE)
        nm_output = nm_command.stdout.read()
        symbols = []
        for line in nm_output.split('\n'):
            if re.search('[0-9a-f]+ [0-9a-f]+ [a-zA-Z] [a-zA-Z]+', line):
                parts = re.split(' +', line)
                sym_name = parts[3]
                virtual_address, size = (int(x, 16) for x in [parts[0], parts[1]])
                file_offset = self.address_to_offset(virtual_address)
                data = self.data[file_offset : file_offset + size]
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
