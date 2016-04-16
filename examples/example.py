import os
import patcher
import arch_x86

def main():
    arch = arch_x86.ArchX86(is_64_bit=True)
    #enable tracer
    patcher.tracer.enable()
    my_dir = os.path.dirname(__file__)
    p = patcher.Patcher(my_dir + '/targets/printf/main', arch)
    patch_filename =  my_dir + '/patches/printf/printf'
    hook_addr = 0x400540

    leech_addr = 0x40063c
    padding_modulu = 5
    p.hook(leech_addr,
           padding_modulu,
           hook_addr + 0x50,
           hook_addr,
           patch_filename,
           ['.text'],
           'output')

if __name__ == '__main__':
    main()
