import sys
import imp
import os

def main(config_file_name, binutils_prefix=None):
    config = imp.load_source(os.path.basename(config_file_name).split('.py')[0],
                             config_file_name)
    if binutils_prefix is None:
        binutils_prefix = ''
    sections_params = ' '.join('-Xlinker --section-start=%s=0x%x' % (name, addr) for name, addr in config.hook_sections.iteritems())
    symbols_params = ' '.join('-Xlinker --defsym=%s=0x%x' % (name, addr) for name, addr in config.symbols.iteritems())
    gcc_cmd = '{}gcc {} {}'.format(binutils_prefix, sections_params, symbols_params)
    print gcc_cmd

if __name__ == '__main__':
    main(*sys.argv[1:])
