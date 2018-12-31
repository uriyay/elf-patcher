import struct

def to_unsigned(signed, bits_number):
    temp = signed + 2**bits_number
    return temp & (2**bits_number - 1)

def to_signed(unsigned, bits_number):
    if unsigned & (1 << (bits_number - 1)):
        #its negative number
        return unsigned - (2**bits_number)
    return unsigned

def to_unsigned_int(signed_int):
    return to_unsigned(signed_int, 32)

def to_unsigned_short(signed_short):
    return to_unsigned(signed_short, 16)

def to_unsigned_byte(signed_byte):
    return to_unsigned(signed_byte, 8)

def to_signed_int(unsigned_int):
    return to_signed(unsigned_int, 32)

def to_signed_short(unsigned_short):
    return to_signed(unsigned_short, 16)

def to_signed_byte(unsigned_byte):
    return to_signed(unsigned_byte, 8)

def parse_address(data, is_64_bit=False, is_little_endian=True):
    format_str = '%s%s' % ('<' if is_little_endian else '>',
                           'Q' if is_64_bit else 'I')
    return struct.unpack(format_str, data)[0]
