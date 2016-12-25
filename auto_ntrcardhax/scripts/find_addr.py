import sys
import struct

def search(binary, pattern, skip=0, masks=None):
    pattern_len = len(pattern)
    for idx in xrange(len(binary) - pattern_len):
        b = binary[idx : idx + pattern_len]
        if masks:
            for offset, maskbit in masks:
                target_uint = struct.unpack('I', (b[offset:offset + 4]))[0]
                b = b[:offset] + struct.pack('I', target_uint & maskbit) + b[offset + 4:]
        if b != pattern:
            continue
        return struct.unpack('I', (binary[idx + skip: idx + skip + 4]))[0]

def find_ntrcard_header_address(arm9bin):
    # 7C B5               PUSH    {R2-R6,LR}
    # 2C 4C               LDR     R4, =card_struct
    # 05 00               MOVS    R5, R0
    # 2A 48               LDR     R0, =ntrcard_header
    # 26 00               MOVS    R6, R4
    type0 = search(arm9bin, '\x7c\xb5\x2c\x4c\x05\x00\x2a\x48\x26\x00', 0xb0)
    type1 = search(arm9bin, '\x7c\xb5\x2d\x4c\x05\x00\x2b\x48\x26\x00', 0xb4)
    return type0 or type1

def find_rtfs_cfg_address(arm9bin):
    # 10 B5               PUSH    {R4,LR}
    # 0D 48               LDR     R0, =rtfs_cfg; dest
    # 0D 4C               LDR     R4, =ERTFS_prtfs_cfg
    # FF 22 6D 32         MOVS    R2, #0x16C; len
    # 00 21               MOVS    R1, #0; val
    # 20 60               STR     R0, [R4]
    return search(arm9bin,
                  '\x10\xb5\x0d\x48\x0d\x4c\xff\x22\x6d\x32\x00\x21\x20\x60',
                  0x38)

def find_rtfs_handle_address(arm9bin):
    # 70 B5               PUSH    {R4-R6,LR}
    # 0B 23               MOVS    R3, #0xB
    # 0B 4A               LDR     R2, =rtfs_handle
    # 00 21               MOVS    R1, #0
    # 9B 01               LSLS    R3, R3, #6
    # C4 18               ADDS    R4, R0, R3
    addr = search(arm9bin,
                  '\x70\xb5\x0b\x23\x0b\x4a\x00\x21\x9b\x01\xc4\x18',
                  0x34)
    if addr:
        return addr + 0x10

def exist_map_memory_adr(arm9bin):
    # F0 40 2D E9         STMFD   SP!, {R4-R7,LR}
    # 14 D0 4D E2         SUB     SP, SP, #0x14
    # 03 40 A0 E1         MOV     R4, R3
    # 7C C0 9F E5         LDR     R12, =0x1F600000 ; mask ~0xFFF
    # 28 50 9D E5         LDR     R5, [SP,#0x28]
    type0 = search(arm9bin,
                   '\xf0\x40\x2d\xe9\x14\xd0\x4d\xe2\x03\x40\xa0\xe1\x00\xc0\x9f\xe5'
                   '\x28\x50\x9d\xe5',
                   masks=[(0x0C, ~0xFFF)])
    # FF 5F 2D E9         STMFD   SP!, {R0-R12,LR}
    # 1F 04 51 E3         CMP     R1, #0x1F000000
    # 01 40 A0 E1         MOV     R4, R1
    # 02 50 A0 E1         MOV     R5, R2
    # 00 80 A0 E1         MOV     R8, R0
    # 05 26 81 E0         ADD     R2, R1, R5,LSL#12
    type1 = search(arm9bin,
                   '\xff\x5f\x2d\xe9\x1f\x04\x51\xe3\x01\x40\xa0\xe1\x02\x50\xa0\xe1'
                   '\x00\x80\xa0\xe1\x05\x26\x81\xe0')

    # 7F 40 2D E9         STMFD   SP!, {R0-R6,LR}
    # 03 C0 A0 E1         MOV     R12, R3
    # 7A 05 51 E3         CMP     R1, #0x1E800000
    # 02 36 81 E0         ADD     R3, R1, R2, LSL#12
    # 20 E0 9D E5         LDR     LR, [SP, #0x20]
    type2 = search(arm9bin,
                   '\x7f\x40\x2d\xe9\x03\xc0\xa0\xe1\x7a\x05\x51\xe3\x02\x36\x81\xe0'
                   '\x20\xe0\x9d\xe5')
    if type0 or type1 or type2:
        return 'true'
    return 'false'

def hex_or_dead(addr):
    return hex(addr or 0xdeadbabe)

if len(sys.argv) < 2:
    print '%s <native_nand_arm9.bin>' % sys.argv[0]
    raise SystemExit(1)

with open(sys.argv[1], 'rb') as r:
    arm9bin = r.read()
    ntrcard_header_addr = find_ntrcard_header_address(arm9bin)
    rtfs_cfg_addr = find_rtfs_cfg_address(arm9bin)
    rtfs_handle_addr = find_rtfs_handle_address(arm9bin)
    print '#define NTRCARD_HEADER_ADDR %s' % hex_or_dead(ntrcard_header_addr)
    print '#define RTFS_CFG_ADDR       %s' % hex_or_dead(rtfs_cfg_addr)
    print '#define RTFS_HANDLE_ADDR    %s' % hex_or_dead(rtfs_handle_addr)
    print '#define EXIST_MAP_MEMORY_ADDR %s' % exist_map_memory_adr(arm9bin)
