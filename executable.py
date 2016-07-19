class Section(object):
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
