
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <malloc.h>
#include <nds.h>
#include <fat.h>
#include "../mbedtls/aes.h"
#include "../term256/term256ext.h"
#include "utils.h"
#include "crypto.h"
#include "sector0.h"
#include "nandio.h"
#include "imgio.h"

extern const char nand_vol_name[];
extern swiSHA1context_t sha1ctx;

const char nand_img_name[] = "nand.bin";

static u32 sector_buf32[SECTOR_SIZE/sizeof(u32)];
static u8 *sector_buf = (u8*)sector_buf32;

static u32 sector_buf_a32[SECTOR_SIZE/sizeof(u32)];
static u8 *sector_buf_a = (u8*)sector_buf_a32;

static ssize_t nand_size;

static u32 emmc_cid32[4];
static u8 *emmc_cid = (u8*)emmc_cid32;
static u32 console_id32[2];
static u8 *console_id = (u8*)console_id32;

// BEWARE, this is not zero terminated
static const char nocash_footer_id[16] = {
	'D', 'S', 'i', ' ',
	'e', 'M', 'M', 'C',
	' ', 'C', 'I', 'D',
	'/', 'C', 'P', 'U'
};

typedef struct {
	char footer_id[16];
	u8 emmc_cid[16];
	u8 console_id[8];
	u8 reserved[24];
} nocash_footer_t;

static_assert(sizeof(nocash_footer_t) == 0x40, "no$gba footer should be 40h bytes");

// BEWARE, this doesn't work in place
void reverse8(u8 *o, const u8 *i) {
	o[0] = i[7];
	o[1] = i[6];
	o[2] = i[5];
	o[3] = i[4];
	o[4] = i[3];
	o[5] = i[2];
	o[6] = i[1];
	o[7] = i[0];
}

static void generate_footer() {
	nocash_footer_t *f = (nocash_footer_t*)sector_buf;
	memcpy(f->footer_id, nocash_footer_id, sizeof(nocash_footer_id));
	memcpy(f->emmc_cid, emmc_cid, sizeof(f->emmc_cid));
	// no$gba uses a different order for Console ID in the footer
	reverse8(f->console_id, console_id);
	memset(f->reserved, 0, sizeof(f->reserved));
}

int get_ids() {
	if (!isDSiMode()) {
		prt("not running in DSi mode\n");
		return -2;
	}
	nand_size = nand_GetSize();
	if (nand_size == 0) {
		prt("can't access eMMC\n");
		return -3;
	}
	iprtf("eMMC: %u sectors, %s MB\n", nand_size, to_mebi(nand_size * SECTOR_SIZE));

	fifoSendValue32(FIFO_USER_01, 4);
	while (fifoCheckDatamsgLength(FIFO_USER_01) < 16) swiIntrWait(1, IRQ_FIFO_NOT_EMPTY);
	fifoGetDatamsg(FIFO_USER_01, 16, (u8*)emmc_cid);
	prt("eMMC CID: ");
	print_bytes(emmc_cid, 16);
	prt("\n");

	char *p_console_id_file = 0;
	size_t console_id_file_size;
	int console_id_from_file = 0;
	if (load_file((void**)&p_console_id_file, &console_id_file_size, "console_id.txt", 0, 0) == 0) {
		if (console_id_file_size >= 16 && hex2bytes(console_id, 8, p_console_id_file) == 0) {
			console_id_from_file = 1;
		}
		free(p_console_id_file);
	}
	if (!console_id_from_file) {
		fifoSendValue32(FIFO_USER_01, 5);
		while (fifoCheckDatamsgLength(FIFO_USER_01) < 8) swiIntrWait(1, IRQ_FIFO_NOT_EMPTY);
		fifoGetDatamsg(FIFO_USER_01, 8, console_id);
	}
	iprtf("Console ID (from %s): ", console_id_from_file ? "file" : "RAM");
	print_bytes(console_id, 8);
	prt("\n");
	return 0;
}

int test_sector0(int *p_is3DS) {
	int is3DS = parse_ncsd(sector_buf, 0) == 0;
	// iprintf("sector 0 is %s\n", is3DS ? "3DS" : "DSi");
	dsi_crypt_init(console_id, emmc_cid, is3DS);
	dsi_nand_crypt(sector_buf, sector_buf, 0, SECTOR_SIZE / AES_BLOCK_SIZE);
	if (p_is3DS) {
		*p_is3DS = is3DS;
	}
	return parse_mbr(sector_buf, is3DS, 0);
}

int test_ids_against_nand(int *p_is3DS) {
	nand_ReadSectors(0, 1, sector_buf);
	return test_sector0(p_is3DS);
}

int test_image_against_nand() {
	FILE *f = fopen(nand_img_name, "r");
	if (f == 0) {
		iprtf("can't open %s\n", nand_img_name);
		return -1;
	}
	// test sector 0 against NAND
	nand_ReadSectors(0, 1, sector_buf);
	size_t read = fread(sector_buf_a, 1, SECTOR_SIZE, f);
	if (read != SECTOR_SIZE) {
		iprtf("fread() returned %u, expecting %u\n", read, SECTOR_SIZE);
		fclose(f);
		return -1;
	}
	if (memcmp(sector_buf, sector_buf_a, SECTOR_SIZE) != 0) {
		iprtf("sector 0 doesn't match, foreign NAND image?\n");
		fclose(f);
		return -2;
	}
	// test size against NAND
	fseek(f, 0, SEEK_END);
	unsigned img_size = ftell(f);
	if (img_size != nand_size * SECTOR_SIZE + sizeof(nocash_footer_t)) {
		iprtf("image size: %u, expecting %u\n", img_size,
			(nand_size * SECTOR_SIZE + sizeof(nocash_footer_t)));
		fclose(f);
		return -3;
	}
	// test footer
	generate_footer();
	fseek(f, nand_size * SECTOR_SIZE, SEEK_SET);
	read = fread(sector_buf_a, 1, sizeof(nocash_footer_t), f);
	if (read != sizeof(nocash_footer_t)) {
		iprtf("fread() returned %u, expecting %u\n", read, sizeof(nocash_footer_t));
		fclose(f);
		return -1;
	}
	if (memcmp(sector_buf, sector_buf_a, sizeof(nocash_footer_t)) != 0) {
		prt("invalid footer\n");
		fclose(f);
		// save_file("footer_expected.bin", sector_buf, sizeof(nocash_footer_t), 0);
		// save_file("footer_img.bin", sector_buf_a, sizeof(nocash_footer_t), 0);
		return -4;
	}
	fclose(f);
	return 0;
}

// this is only used in img test mode
int test_image_against_footer() {
	FILE *f = fopen(nand_img_name, "r");
	if (f == 0) {
		iprtf("can't open %s\n", nand_img_name);
		return -1;
	}
	// read and validate footer
	fseek(f, 0, SEEK_END);
	unsigned size = ftell(f) - sizeof(nocash_footer_t);
	iprtf("image size sans footer: %s MB\n", to_mebi(size));
	fseek(f, size, SEEK_SET);
	size_t read = fread(sector_buf, 1, sizeof(nocash_footer_t), f);
	if (read != sizeof(nocash_footer_t)) {
		iprtf("fread() returned %u, expecting %u\n", read, sizeof(nocash_footer_t));
		fclose(f);
		return -1;
	}
	nocash_footer_t *footer = (nocash_footer_t*)sector_buf;
	if (memcmp(footer->footer_id, nocash_footer_id, sizeof(nocash_footer_id)) != 0) {
		iprtf("invalid footer\n");
		fclose(f);
		return -2;
	}
	// extract IDs
	memcpy(emmc_cid, footer->emmc_cid, sizeof(footer->emmc_cid));
	reverse8(console_id, footer->console_id);
	// read sector 0
	fseek(f, 0, SEEK_SET);
	read = fread(sector_buf, 1, SECTOR_SIZE, f);
	if (read != SECTOR_SIZE) {
		iprtf("fread() returned %u, expecting %u\n", read, SECTOR_SIZE);
		fclose(f);
		return -1;
	}
	fclose(f);
	// test IDs against sector 0
	return test_sector0(0);
}

int mount(int direct) {
	if (direct) {
		nand_ReadSectors(0, 1, sector_buf);
	} else {
		FILE *f = fopen(nand_img_name, "r");
		if (f == 0) {
			iprtf("can't open %s\n", nand_img_name);
			return -1;
		}
		// test sector 0 against nand
		size_t read = fread(sector_buf, 1, SECTOR_SIZE, f);
		fclose(f);
		if (read != SECTOR_SIZE) {
			iprtf("fread() returned %u, expecting %u\n", read, SECTOR_SIZE);
			return -1;
		}
	}
	int is3DS;
	test_sector0(&is3DS);
	mbr_t *mbr = (mbr_t*)sector_buf;
	int mnt_ret;
	if (direct) {
		nandio_set_fat_sig_fix(is3DS ? 0 : mbr->partitions[0].offset);
		mnt_ret = fatMount(nand_vol_name, &io_dsi_nand, mbr->partitions[0].offset, 4, 64);
	} else {
		imgio_set_fat_sig_fix(is3DS ? 0 : mbr->partitions[0].offset);
		mnt_ret = fatMount(nand_vol_name, &io_nand_img, mbr->partitions[0].offset, 4, 64);
	}
	if (mnt_ret == 0) {
		iprtf("failed to mount %s\n", direct ? nand_vol_name : nand_img_name);
		return -2;
	} else {
		iprtf("%s mounted\n", direct ? nand_vol_name : nand_img_name);
	}
	///* // the volume label is all white space?
	char vol_label[32];
	fatGetVolumeLabel(nand_vol_name, vol_label);
	iprtf("label: \"%s\"\n", vol_label);
	//*/
	return 0;
}

// to prevent possible alloc failure for critical restore
#define SECTORS_PER_LOOP 128
#define DUMP_BUF_SIZE (SECTOR_SIZE * SECTORS_PER_LOOP)
u32 dump_buf[DUMP_BUF_SIZE / sizeof(u32)];

int backup() {
	if ((nand_size * SECTOR_SIZE) % DUMP_BUF_SIZE != 0) {
		prt("weird NAND size not supported\n");
		return -2;
	}
	if (df(".", 0) < (nand_size * SECTOR_SIZE) + DUMP_BUF_SIZE) {
		prt("insufficient space\n");
		return -1;
	}
	FILE *f = fopen(nand_img_name, "w");
	if (f == 0) {
		iprtf("failed to open %s for writing\n", nand_img_name);
		return -1;
	}
	sha1ctx.sha_block = 0;
	swiSHA1Init(&sha1ctx);
	int ret = 0;
	size_t written;
	const unsigned loops = nand_size / SECTORS_PER_LOOP;
	// iprintf("%u %u %u\n", SECTOR_SIZE, SECTORS_PER_LOOP, loops);
	// return -1;
	for (unsigned i = 0; i < loops; ++i) {
		if (nand_ReadSectors(SECTORS_PER_LOOP * i, SECTORS_PER_LOOP, dump_buf) == 0) {
			prt("error reading NAND\n");
			ret = -1;
			break;
		}
		swiSHA1Update(&sha1ctx, dump_buf, DUMP_BUF_SIZE);
		written = fwrite(dump_buf, 1, DUMP_BUF_SIZE, f);
		if (written != DUMP_BUF_SIZE) {
			iprtf("error writing to %s\n", nand_img_name);
			ret = -1;
			break;
		}
		iprtf("%u/%u\r", i + 1, loops);
	}
	generate_footer();
	swiSHA1Update(&sha1ctx, sector_buf, sizeof(nocash_footer_t));
	written = fwrite(sector_buf, 1, sizeof(nocash_footer_t), f);
	if (written != sizeof(nocash_footer_t)) {
		iprtf("error writing to %s\n", nand_img_name);
		ret = -1;
	}
	fclose(f);
	if (ret == 0) {
		save_sha1_file(nand_img_name);
	}
	return ret;
}

int restore() {
	iprtf("%s: not implemented\n", __FUNCTION__);
	return -1;
}

void aes_test(int loops, const char * s_console_id, const char * s_emmc_cid) {
	hex2bytes(console_id, 8, s_console_id);
	hex2bytes(emmc_cid, 16, s_emmc_cid);
	dsi_crypt_init(console_id, emmc_cid, 0);

	cpuStartTiming(0);
	for (int i = 0; i < loops; ++i) {
		dsi_nand_crypt((u8*)dump_buf, (u8*)dump_buf,
			i * (DUMP_BUF_SIZE / AES_BLOCK_SIZE), DUMP_BUF_SIZE / AES_BLOCK_SIZE);
	}
	u32 td = timerTicks2usec(cpuEndTiming());

	prtf("%" PRIu32 " us %u KB\n%.2f KB/s\n", td, (DUMP_BUF_SIZE * loops) >> 10,
		1000.0f * DUMP_BUF_SIZE * loops / td);
}

