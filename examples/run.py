#I want that this script will compile and run for every arch I have and for every patch I have

import os
import sys
import imp
import glob
import pickle
import argparse
import tempfile
import platform
import subprocess

my_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(my_dir, '..'))

import patcher
from archs import arch_x86, arch_arm, arch_mips

ARCHS = {
            'x86' : {
                    'arch_object' : arch_x86.Arch(is_64_bit=False),
                    'compiler_args' : '-m32',
                    },
            'x86_64' : {
                        'arch_object' : arch_x86.Arch(is_64_bit=True),
                        'compiler_args' : '',
                       },
            'arm' : {
                    'arch_object': arch_arm.Arch(binutils_prefix='arm-none-linux-gnueabi-'),
                    'compiler_args' : 'CROSS_COMPILER=arm-none-linux-gnueabi-'
                    },
            'mips32el' : {
                         'arch_object' : arch_mips.Arch(binutils_prefix='mips-sde-elf-'),
                         'compiler_args' : 'CROSS_COMPILER=mips-sde-elf-',
                         },
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
                        'hook_address' : 'func',
                        'hook_data_addr' : 'nothing',
                       },
            #/bin/ls ?
            'ls' : {'filename' : '/bin/ls',
                    'hook_address' : 'print_current_files', #at print_current_files
                    'hook_data_addr' : 0,
                    },
          }

def get_config_from_cli():
    parser = argparse.ArgumentParser()
    parser.add_argument('--simple', help='test simple case - x86_64 taregt printf with patch of run_sh',
                        action="store_true", default=False)
    parser.add_argument('-a', '--arch', help='which arch you want to use %s' % (str(ARCHS.keys())))
    parser.add_argument('-t', '--target', help='which target to use %s' % (str(TARGETS.keys())))
    parser.add_argument('-p', '--patch', help='which patch to use %s' % (str(PATCHES.keys())))
    parser.add_argument('-o', '--output', help='where to write the result')
    args = parser.parse_args()

    if args.simple:
        if '64' in platform.architecture()[0]:
            arch = ARCHS['x86_64']
        else:
            arch = ARCHS['x86']
        target = TARGETS['printf']
        patch = PATCHES['run_sh']
        return arch, target, patch, None #None for output

    assert args.arch in ARCHS, 'arch %s not in possible archs = %s' % (args.arch, ARCHS.keys())
    assert args.target in TARGETS, 'target %s not in possible targets = %s' % (args.target, TARGETS.keys())
    assert args.patch in PATCHES, 'patch  %s not in possibles patches = %s' % (args.patch, PATCHES.keys())

    return ARCHS[args.arch], TARGETS[args.target], PATCHES[args.patch], args.output

def compile(dir_path, makefile_args):
    command = 'make -C %s %s rebuild' % (dir_path, makefile_args)
    result = os.system(command)
    if result != 0:
        raise Exception("Failed to compile, command = %s, result = %d" % (command, result))


def main():
    arch, target, patch, output_filename = get_config_from_cli()

    #enable tracer
    patcher.tracer.enable()
    target_filename = target['filename']
    p = patcher.Patcher(target_filename, arch['arch_object'])
    patch_filename =  patch['filename']

    #compile target
    compile(os.path.dirname(target_filename), arch['compiler_args'])
    #compile patch
    arch_pickle_file = tempfile.NamedTemporaryFile(prefix='arch_pickle_', delete=False)
    pickle.dump(p.arch, arch_pickle_file)
    arch_pickle_file.close()
    compile(os.path.dirname(patch_filename), ' '.join([arch['compiler_args'],
                                                      'ARCH_PICKLE_FILENAME=%s' % (arch_pickle_file.name),
                                                      'TARGET_TO_PATCH_FILENAME=%s' % (target_filename),
                                                      ]))
    os.unlink(arch_pickle_file.name)

    hook_data_addr = target['hook_data_addr']
    if type(hook_data_addr) is str:
        sym_name = hook_data_addr
        hook_data_addr = p.binary.get_symbol_by_name(hook_data_addr).virtual_address
        if hook_data_addr is None:
            raise Exception('Cannot get address from symbol %s' % (sym_name))

    hook_glue_address = hook_data_addr + 0x100

    #the address to jump from in the original binary
    hook_addr = target['hook_address']
    if type(hook_addr) is str:
        sym_name = hook_addr
        hook_addr = p.binary.get_symbol_by_name(sym_name).virtual_address
        if hook_addr is None:
            raise Exception('Cannot get address from symbol %s' % (sym_name))

    where_to_jump = patch.get('hook_symbol_to_jump_to', None)
    patch_table = p.get_patch(hook_addr,
                              hook_glue_address,
                              patch_filename,
                              patch['hook_symbols_to_paste'],
                              where_to_jump)
    if output_filename is None:
        output_filename = 'output'
    p.patch_binary(patch_table, output_filename)

if __name__ == '__main__':
    main()
