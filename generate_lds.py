import sys
import imp
import os


MEMORY_LAYPUT = '''
MEMORY
{
    ram : ORIGIN = 0x%x, LENGTH = 0x%x
}

'''

LDS_FORMAT1 = '''
SECTIONS
{
    . = 0x%(text_addr)x;
    .text : { *(.text) }
    .data : { *(.data) }

    %(other_sections)s
}
'''

LDS_FORMAT2 = '''
SECTIONS
{
    .text : { *(.text) } > ram
    .data : { *(.data) } > ram

    %(other_sections)s
}
'''

HOOK_SECTION_FORMAT = '''
    . = 0x%(hook_addr)x;
    .%(hook_section_name)s = .;
'''

def generate_lds(symbols, hook_sections, memory_layout=None):
    '''
    param symbols: a dict of {symbol : address}
    param hook_sections: a dict of {hook_addr : hook_section_name}
    param (optional) memory_layout: a tuple of (orig, length)
    returns: ld script
    '''
    other_sections = '\n\n'.join(HOOK_SECTION_FORMAT % {'hook_addr' : hook_addr,
                                                        'hook_section_name' : hook_section_name} \
                                 for hook_section_name, hook_addr in hook_sections.iteritems())
    if memory_layout is None:
        lds = LDS_FORMAT1 % {'text_addr' : symbols['my_text_address'], 
                            'other_sections' : other_sections}
    else:
        lds = MEMORY_LAYPUT % memory_layout
        lds += LDS_FORMAT2  % {'other_sections' : other_sections}
    symbols_text = '\n'.join('%s = 0x%x;' % (sym_name, sym_addr) for sym_name, sym_addr in symbols.iteritems())
    lds = symbols_text + lds
    return lds

def main(config_file_name, output_lds_file_name):
    '''
    param config_file_name: a python file with globals of symbols
    param output_lds_file_name: where to save the ld script
    '''
    config = imp.load_source(os.path.basename(config_file_name).split('.py')[0],
                             config_file_name)
    lds = generate_lds(config.symbols, config.hook_sections)
    with open(output_lds_file_name, 'wb') as lds_file:
        lds_file.write(lds)

if __name__ == '__main__':
    main(*sys.argv[1:])
