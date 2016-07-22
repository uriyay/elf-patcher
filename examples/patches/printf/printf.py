symbols = {'puts' : 0x400410,
           'my_text_address' : 0x400540}

hook_sections = {'.text' : 0x200000,
                 'hook_printf' : 0x400540,
                 '.data' : 0x400600,}
