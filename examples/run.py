#I want that this script will compile and run for every arch I have and for every patch I have

import os
import sys
import imp
import glob
import argparse
import platform
import subprocess

my_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(my_dir, '..'))

import patcher
from archs import arch_x86, arch_arm

ARCHS = {
            'x86' : arch_x86.Arch(is_64_bit=False),
            'x86_64' : arch_x86.Arch(is_64_bit=True),
            'arm' : arch_arm.Arch(binutils_prefix='arm-none-linux-gnueabi-'),
        }

PATCHES = {
            'printf': {'filename' : os.path.join(my_dir, 'patches/printf/printf'),
                        'hook_symbols_to_paste' : ['main', 'my_str'],
                      },
            'run_sh' : {'filename' : os.path.join(my_dir, 'patches/run_sh/run_sh'),
                        'hook_symbols_to_paste' : ['main', 'execve_wrap', 'sh'],
                       },
          }

TARGETS = {
            'printf' : {'filename' : os.path.join(my_dir, 'targets/printf/main'),
                        'hook_address' : 0x4006c9,
                        'hook_data_addr' : 'nothing',
                       },
            #/bin/ls ?
            'ls' : {'filename' : '/bin/ls',
                    'hook_address' : 0x4082c1, #at print_current_files
                    'hook_data_addr' : 0,
                    },
          }

def get_config_from_cli():
    parser = argparse.ArgumentParser()
    parser.add_argument('--simple', help='test simple case - x86_64 taregt printf with patch of run_sh',
                        action="store_true", default=False)
    parser.add_argument('arch', help='which arch you want to use')
    parser.add_argument('target', help='which target to use')
    parser.add_argument('patch', help='which patch to use')
    parser.add_argument('output_filename', help='where to write the result', default=None)
    args = parser.parse_args()

    if args.simple:
        print 'here!!'
        if '64' in platform.architecture()[0]:
            arch = ARCHS['x86_64']
        else:
            arch = ARCHS['x86']
        target = TARGETS['printf']
        patch = PATCHES['run_sh']
        return arch, target, patch, None #None for output_filename

    assert args.arch in ARCHS, 'arch %s not in possible archs = %s' % (args.arch, ARCHS.keys())
    assert args.target in TARGETS, 'target %s not in possible targets = %s' % (args.target, TARGETS.keys())
    assert args.patch in PATCHES, 'patch  %s not in possibles patches = %s' % (args.patch, PATCHES.keys())

    return ARCHS[args.arch], TARGETS[args.target], PATCHES[args.patch], args.output_filename

def main():
    arch, target, patch, output_filename = get_config_from_cli()

    #enable tracer
    patcher.tracer.enable()
    target_filename = target['filename']
    p = patcher.Patcher(target_filename, arch)
    patch_filename =  patch['filename']

    hook_data_addr = target['hook_data_addr']
    if type(hook_data_addr) is str:
        sym_name = hook_data_addr
        hook_data_addr = p.binary.get_symbol_by_name(hook_data_addr).virtual_address
        if hook_data_addr is None:
            raise Exception('Cannot get address from symbol %s', sym_name)

    hook_glue_address = hook_data_addr + 0x100

    #the address to jump from in the original binary
    hook_addr = target['hook_address']
    padding_modulu = arch.padding_modulu
    where_to_jump = patch.get('hook_symbol_to_jump_to', None)
    patch_table = p.get_patch(hook_addr,
                              padding_modulu,
                              hook_glue_address,
                              patch_filename,
                              patch['hook_symbols_to_paste'],
                              where_to_jump)
    if output_filename is None:
        output_filename = 'output'
    p.patch_binary(patch_table, output_filename)

if __name__ == '__main__':
    main()
