import patcher
import arch_x86

def main():
    arch = arch_x86.ArchX86(is_64_bit=True)
    #enable tracer
    patcher.tracer.enable()
    p = patcher.Patcher('./targets/printf/main', arch)
    patch_filename =  './patches/printf/printf'
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
