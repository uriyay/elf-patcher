import os
import sys
import subprocess

my_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(my_dir + '/..')

import patcher
import arch_x86

PRINTF_PATCH = patch_filename =  my_dir + '/patches/printf/printf'
RUN_SH_PATCH = patch_filename = my_dir + '/patches/run_sh/run_sh'

PATCH_PATH = PRINTF_PATCH

HOOK_DATA_ADDR = 0x4005a4

def get_address_from_symbol(path, symbol):
    proc = subprocess.Popen(['nm', path], stdout=subprocess.PIPE)
    proc.wait()
    nm_output = proc.stdout.read().split('\n')
    for line in nm_output:
        parts = line.split(' ')
        if len(parts) >= 3 and parts[2] == symbol:
            return int(parts[0], 16)
    return None

def main():
    arch = arch_x86.ArchX86(is_64_bit=True)
    #enable tracer
    patcher.tracer.enable()
    target_filename = my_dir + '/targets/printf/main'
    p = patcher.Patcher(target_filename, arch)
    patch_filename =  PATCH_PATH
    hook_data_addr = get_address_from_symbol(patch_filename, 'main')
    if hook_data_addr is None:
        raise Exception('Cannot get address from symbol %s', 'main')

    #the address to jump from in the original binary
    hook_addr = 0x4006c4
    padding_modulu = 5
    patch_table = p.get_patch(hook_addr,
                              padding_modulu,
                              hook_data_addr + 0x100,
                              hook_data_addr,
                              patch_filename,
                              ['.text', '.rodata'])
    p.patch_binary(patch_table, 'output')

if __name__ == '__main__':
    main()
