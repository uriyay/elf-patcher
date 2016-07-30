import sys
import imp
import os
import pickle

my_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(my_dir, '..'))

from executable import Executable

def translate_address(entry_name, address, target_binary=None):
    if type(address) not in (int, long):
        if target_binary is None:
            raise Exception('error: got symbol "%s", but cannot resolve it because target_binary is None' % (str(address)))
        if type(address) is tuple:
            symbol, offset = address
            address = target_binary.get_symbol_by_name(symbol)
            if address is None:
                raise Exception('cannot resolve symbol "%s" in target %s' % (symbol, target_binary.filename))
            address = address.virtual_address + offset
        elif type(address) is str:
            symbol = address
            address = target_binary.get_symbol_by_name(symbol)
            if address is None:
                raise Exception('cannot resolve symbol "%s" in target %s' % (symbol, target_binary.filename))
            address = address.virtual_address

    return entry_name, address

def process_symbols(symbols, target_binary=None):
    for key, value in symbols.iteritems():
        yield translate_address(key, value, target_binary)

def main(config_file_name, binutils_prefix=None, arch_pickle_filename=None, target_filename=None):
    config = imp.load_source(os.path.basename(config_file_name).split('.py')[0],
                             config_file_name)

    hook_sections = config.hook_sections
    symbols = config.symbols
    if binutils_prefix is None:
        binutils_prefix = ''
    target_binary = None
    if target_filename is not None:
        if arch_pickle_filename is None:
            raise Exception('expected arch_pickle_filename in order to resolve symbols, got None')
        arch = pickle.load(file(arch_pickle_filename, 'rb'))
        target_binary = Executable(target_filename, arch)

    #process addresses: it can be address, symbol name or tuple of (symbol_name, offset)
    hook_sections = process_symbols(hook_sections, target_binary)
    symbols = process_symbols(symbols, target_binary)

    sections_params = ' '.join('-Xlinker --section-start=%s=0x%x' % (name, addr) for name, addr in hook_sections)
    symbols_params = ' '.join('-Xlinker --defsym=%s=0x%x' % (name, addr) for name, addr in symbols)
    gcc_cmd = '{}gcc {} {}'.format(binutils_prefix, sections_params, symbols_params)
    print gcc_cmd

if __name__ == '__main__':
    main(*sys.argv[1:])
