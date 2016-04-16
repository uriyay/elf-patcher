a = 0xdadababa;
my_text_address = 0x400540;
puts = 0x400410;
SECTIONS
{
    . = 0x400540;

    .text : { *(.text) }
    .data : { *(.data) }

    
    . = 0x400540;
    .hook_run_sh = .;

}
