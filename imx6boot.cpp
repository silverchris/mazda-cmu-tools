// SPDX-License-Identifier: GPL-2.0+
/*
 * (C) Copyright 2022
 * Chris Schimp <silverchris@gmail.com
 *
 * (C) Copyright 2009
 * Stefano Babic, DENX Software Engineering, sbabic@denx.de.
 *
 * (C) Copyright 2008
 * Marvell Semiconductor <www.marvell.com>
 * Written-by: Prafulla Wadaskar <prafulla@marvell.com>
 */

/* Adapted from uboot with some modifications */


#include <cstdint>
#include "imximage.h"
#include <cstdlib>
#include <cstdio>
#include <cstring>

#include <endian.h>

typedef uint32_t __u32;
typedef unsigned int uint;
typedef unsigned long ulong;

/* Define these on the host so we can build some target code */
typedef __u32 u32;

#define uswap_16(x) \
	((((x) & 0xff00) >> 8) | \
	 (((x) & 0x00ff) << 8))
#define uswap_32(x) \
	((((x) & 0xff000000) >> 24) | \
	 (((x) & 0x00ff0000) >>  8) | \
	 (((x) & 0x0000ff00) <<  8) | \
	 (((x) & 0x000000ff) << 24))
#define _uswap_64(x, sfx) \
	((((x) & 0xff00000000000000##sfx) >> 56) | \
	 (((x) & 0x00ff000000000000##sfx) >> 40) | \
	 (((x) & 0x0000ff0000000000##sfx) >> 24) | \
	 (((x) & 0x000000ff00000000##sfx) >>  8) | \
	 (((x) & 0x00000000ff000000##sfx) <<  8) | \
	 (((x) & 0x0000000000ff0000##sfx) << 24) | \
	 (((x) & 0x000000000000ff00##sfx) << 40) | \
	 (((x) & 0x00000000000000ff##sfx) << 56))
#if defined(__GNUC__)
# define uswap_64(x) _uswap_64(x, ull)
#else
# define uswap_64(x) _uswap_64(x, )
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
# define cpu_to_le16(x)		(x)
# define cpu_to_le32(x)		(x)
# define cpu_to_le64(x)		(x)
# define le16_to_cpu(x)		(x)
# define le32_to_cpu(x)		(x)
# define le64_to_cpu(x)		(x)
# define cpu_to_be16(x)		uswap_16(x)
# define cpu_to_be32(x)		uswap_32(x)
# define cpu_to_be64(x)		uswap_64(x)
# define be16_to_cpu(x)		uswap_16(x)
# define be32_to_cpu(x)		uswap_32(x)
# define be64_to_cpu(x)		uswap_64(x)
#else
# define cpu_to_le16(x)		uswap_16(x)
# define cpu_to_le32(x)		uswap_32(x)
# define cpu_to_le64(x)		uswap_64(x)
# define le16_to_cpu(x)		uswap_16(x)
# define le32_to_cpu(x)		uswap_32(x)
# define le64_to_cpu(x)		uswap_64(x)
# define cpu_to_be16(x)		(x)
# define cpu_to_be32(x)		(x)
# define cpu_to_be64(x)		(x)
# define be16_to_cpu(x)		(x)
# define be32_to_cpu(x)		(x)
# define be64_to_cpu(x)		(x)
#endif

#if !defined(CONFIG_IMX_DCD_ADDR)
#define CONFIG_IMX_DCD_ADDR 0x00910000
#endif


void genimg_print_size(uint32_t size)
{
    printf("%d Bytes = %.2f KiB = %.2f MiB\n", size, (double)size / 1.024e3,
           (double)size / 1.048576e6);
}


/**
 * manual_reloc() - Manually relocate a pointer if needed
 *
 * This is a nop in almost all cases, except for the systems with a broken gcc
 * which need to manually relocate some things.
 *
 * @ptr: Pointer to relocate
 * Return: new pointer value
 */
static inline void *manual_reloc(void *ptr)
{
    return ptr;
}

const table_entry_t *get_table_entry(const table_entry_t *table, int id)
{
    for (; table->id >= 0; ++table) {
        if (table->id == id)
            return table;
    }
    return NULL;
}

/**
 * get_table_entry_name - translate entry id to long name
 * @table: pointer to a translation table for entries of a specific type
 * @msg: message to be returned when translation fails
 * @id: entry id to be translated
 *
 * get_table_entry_name() will go over translation table trying to find
 * entry that matches given id. If matching entry is found, its long
 * name is returned to the caller.
 *
 * returns:
 *     long entry name if translation succeeds
 *     msg otherwise
 */
char *get_table_entry_name(const table_entry_t *table, char *msg, int id)
{
    table = get_table_entry(table, id);
    if (!table)
        return msg;
    return static_cast<char *>(manual_reloc(table->lname));
}

static table_entry_t imximage_versions[] = {
        {IMXIMAGE_V1,	"",	" (i.MX25/35/51 compatible)", },
        {IMXIMAGE_V2,	"",	" (i.MX53/6/7 compatible)",   },
        {-1,            "",     " (Invalid)",                 },
};

static uint32_t imximage_plugin_size;

static uint32_t detect_imximage_version(struct imx_header *imx_hdr)
{
    imx_header_v1_t *hdr_v1 = &imx_hdr->header.hdr_v1;
    imx_header_v2_t *hdr_v2 = &imx_hdr->header.hdr_v2;
    flash_header_v1_t *fhdr_v1 = &hdr_v1->fhdr;
    flash_header_v2_t *fhdr_v2 = &hdr_v2->fhdr;

    /* Try to detect V1 */
    if ((fhdr_v1->app_code_barker == APP_CODE_BARKER) &&
        (hdr_v1->dcd_table.preamble.barker == DCD_BARKER))
        return IMXIMAGE_V1;

    /* Try to detect V2 */
    if ((fhdr_v2->header.tag == IVT_HEADER_TAG) &&
        (hdr_v2->data.dcd_table.header.tag == DCD_HEADER_TAG))
        return IMXIMAGE_V2;

    if ((fhdr_v2->header.tag == IVT_HEADER_TAG) &&
        hdr_v2->boot_data.plugin)
        return IMXIMAGE_V2;

    return IMXIMAGE_VER_INVALID;
}

static void err_imximage_version(int version)
{
    fprintf(stderr,
            "Error: Unsupported imximage version:%d\n", version);

    exit(EXIT_FAILURE);
}

static void set_dcd_val_v1(struct imx_header *imxhdr, char *name, int lineno,
                           int fld, uint32_t value, uint32_t off)
{
    dcd_v1_t *dcd_v1 = &imxhdr->header.hdr_v1.dcd_table;

    switch (fld) {
        case CFG_REG_SIZE:
            /* Byte, halfword, word */
            if ((value != 1) && (value != 2) && (value != 4)) {
                fprintf(stderr, "Error: %s[%d] - "
                                "Invalid register size " "(%d)\n",
                        name, lineno, value);
                exit(EXIT_FAILURE);
            }
            dcd_v1->addr_data[off].type = value;
            break;
        case CFG_REG_ADDRESS:
            dcd_v1->addr_data[off].addr = value;
            break;
        case CFG_REG_VALUE:
            dcd_v1->addr_data[off].value = value;
            break;
        default:
            break;

    }
}

static void print_hdr_v1(struct imx_header *imx_hdr)
{
    imx_header_v1_t *hdr_v1 = &imx_hdr->header.hdr_v1;
    flash_header_v1_t *fhdr_v1 = &hdr_v1->fhdr;
    dcd_v1_t *dcd_v1 = &hdr_v1->dcd_table;
    uint32_t size, length, ver;

    size = dcd_v1->preamble.length;
    if (size > (MAX_HW_CFG_SIZE_V1 * sizeof(dcd_type_addr_data_t))) {
        fprintf(stderr,
                "Error: Image corrupt DCD size %d exceed maximum %d\n",
                (uint32_t)(size / sizeof(dcd_type_addr_data_t)),
                MAX_HW_CFG_SIZE_V1);
        exit(EXIT_FAILURE);
    }

    length = dcd_v1->preamble.length / sizeof(dcd_type_addr_data_t);
    ver = detect_imximage_version(imx_hdr);

    printf("Image Type:   Freescale IMX Boot Image\n");
    printf("Image Ver:    %x", ver);
    printf("%s\n", get_table_entry_name(imximage_versions, NULL, ver));
    printf("Data Size:    ");
    genimg_print_size(dcd_v1->addr_data[length].type);
    printf("Load Address: %08x\n", (uint32_t)fhdr_v1->app_dest_ptr);
    printf("Entry Point:  %08x\n", (uint32_t)fhdr_v1->app_code_jump_vector);
}

static void print_hdr_v2(struct imx_header *imx_hdr)
{
    imx_header_v2_t *hdr_v2 = &imx_hdr->header.hdr_v2;
    flash_header_v2_t *fhdr_v2 = &hdr_v2->fhdr;
    dcd_v2_t *dcd_v2 = &hdr_v2->data.dcd_table;
    uint32_t size, version, plugin;

    plugin = hdr_v2->boot_data.plugin;
    if (!plugin) {
        size = be16_to_cpu(dcd_v2->header.length);
        if (size > (MAX_HW_CFG_SIZE_V2 * sizeof(dcd_addr_data_t))) {
            fprintf(stderr,
                    "Error: Image corrupt DCD size %d exceed maximum %d\n",
                    (uint32_t)(size / sizeof(dcd_addr_data_t)),
                    MAX_HW_CFG_SIZE_V2);
            exit(EXIT_FAILURE);
        }
    }

    version = detect_imximage_version(imx_hdr);

    printf("Image Type:   Freescale IMX Boot Image\n");
    printf("Image Ver:    %x", version);
    printf("%s\n", get_table_entry_name(imximage_versions, NULL, version));
    printf("Mode:         %s\n", plugin ? "PLUGIN" : "DCD");
    if (!plugin) {
        printf("Data Size:    ");
        genimg_print_size(hdr_v2->boot_data.size);
        printf("Load Address: %08x\n", (uint32_t)fhdr_v2->boot_data_ptr);
        printf("Entry Point:  %08x\n", (uint32_t)fhdr_v2->entry);
        if (fhdr_v2->csf) {
            uint16_t dcdlen;
            int offs;

            dcdlen = hdr_v2->data.dcd_table.header.length;
            offs = (char *)&hdr_v2->data.dcd_table
                   - (char *)hdr_v2;

            /*
             * The HAB block is the first part of the image, from
             * start of IVT header (fhdr_v2->self) to the start of
             * the CSF block (fhdr_v2->csf). So HAB size is
             * calculated as:
             * HAB_size = fhdr_v2->csf - fhdr_v2->self
             */
            printf("HAB Blocks:   0x%08x 0x%08x 0x%08x\n",
                   (uint32_t)fhdr_v2->self, 0,
                   (uint32_t)(fhdr_v2->csf - fhdr_v2->self));
            printf("DCD Blocks:   0x%08x 0x%08x 0x%08x\n",
                   CONFIG_IMX_DCD_ADDR, offs, be16_to_cpu(dcdlen));
        }
    } else {
        imx_header_v2_t *next_hdr_v2;
        flash_header_v2_t *next_fhdr_v2;

        /*First Header*/
        printf("Plugin Data Size:     ");
        genimg_print_size(hdr_v2->boot_data.size);
        printf("Plugin Code Size:     ");
        genimg_print_size(imximage_plugin_size);
        printf("Plugin Load Address:  %08x\n", hdr_v2->boot_data.start);
        printf("Plugin Entry Point:   %08x\n", (uint32_t)fhdr_v2->entry);

        /*Second Header*/
        next_hdr_v2 = (imx_header_v2_t *)((char *)hdr_v2 +
                                          imximage_plugin_size);
        next_fhdr_v2 = &next_hdr_v2->fhdr;
        printf("U-Boot Data Size:     ");
        genimg_print_size(next_hdr_v2->boot_data.size);
        printf("U-Boot Load Address:  %08x\n",
               next_hdr_v2->boot_data.start);
        printf("U-Boot Entry Point:   %08x\n",
               (uint32_t)next_fhdr_v2->entry);
    }
}


static void imximage_print_header(const void *ptr)
{
    struct imx_header *imx_hdr = (struct imx_header *) ptr;
    uint32_t version = detect_imximage_version(imx_hdr);

    switch (version) {
        case IMXIMAGE_V1:
            print_hdr_v1(imx_hdr);
            break;
        case IMXIMAGE_V2:
            print_hdr_v2(imx_hdr);
            break;
        default:
            err_imximage_version(version);
            break;
    }
}

int main(int argv, char *argc[]){
    if(argv == 2){
        FILE * img_file = fopen(argc[1], "rb");

        void * buffer;
        buffer = malloc(1048576);
        fread(buffer, 1, 1048576, img_file );
        imximage_print_header(buffer);

    }
    return 0;
}


