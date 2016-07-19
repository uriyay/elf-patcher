INCLUDE default.lds
my_text_address = 0x400000;
puts = 0x400410;
SECTIONS
{
    . = 0x400000;
    .text : { *(.text) }
    .data : { *(.data) }

    
    . = 0x400540;
    .hook_run_sh = .;



    . = 0x400580;
    .rodata = .;

}
