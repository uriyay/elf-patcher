symbols = {'puts' : 'puts',}

hook_sections = {'.text' : 0x200000,
                 'hook_printf' : 'nothing',
                 '.data' : ('nothing', 0xc0),}
