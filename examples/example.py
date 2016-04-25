import os
import sys

my_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(my_dir + '/..')

import patcher
import arch_x86

def main():
    arch = arch_x86.ArchX86(is_64_bit=True)
    #enable tracer
    patcher.tracer.enable()
    p = patcher.Patcher(my_dir + '/targets/printf/main', arch)
    patch_filename =  my_dir + '/patches/printf/printf'
    hook_data_addr = 0x400540

    hook_addr = 0x40063c
    padding_modulu = 5
    p.hook(hook_addr,
           padding_modulu,
           hook_data_addr + 0x50,
           hook_data_addr,
           patch_filename,
           ['.text'],
           'output')

if __name__ == '__main__':
    main()
