#include <nds.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fat.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/statvfs.h>
#include <dirent.h>
#include "aes.h"
#include "utils.h"
#include "crypto.h"
#include "sector0.h"
#include "nandio.h"
#include "imgio.h"
#include "walk.h"
#include "scripting.h"

#define NAND_IMG_MODE 1

#define SHA1_LEN 20

#define NAND_RESERVE (5 * 1024 * 1024)

PrintConsole topScreen;
PrintConsole bottomScreen;

u8 nandcid[16];
u8 consoleid[8];

const char nand_img_name[] = "nand.bin";

const char nand_vol_name[] = "NAND";
const char nand_root[] = "NAND:/";

#define CONSOLE_WIDTH	32
#define CONSOLE_HEIGHT	23

#define Cls "\x1b[2J"
#define Rst "\x1b[0m"
// unfortunately background colors are not working
#define Blk "\x1b[40m"
#define Red "\x1b[41m"
#define Grn "\x1b[42m"
#define Ylw "\x1b[43m"
#define Blu "\x1b[44m"
#define Mag "\x1b[45m"
#define Cyn "\x1b[46m"
#define Wht "\x1b[47m"

typedef struct {
	const char *name;
	size_t size;
}file_list_item_t;

#define FILE_LIST_MAX 0x100

const char pwd[] = ".";
const char footer[] = "(A)select (B)quit";
file_list_item_t file_list[FILE_LIST_MAX];
unsigned file_list_len;
unsigned view_pos;
unsigned cur_pos;

#define VIEW_HEIGHT (CONSOLE_HEIGHT - 2)

void file_list_add(const char *name, size_t size, void *_) {
	if (size == INVALID_SIZE) {
		// filter out directory
		return;
	}
	unsigned len_name = strlen(name);
	if (len_name < 5) {
		// shortest valid name would be like "1.nfs"
		return;
	}
	// abbreviation for NAND File Script
	if (strcmp(".nfs", name + len_name - 4)){
		return;
	}
	char *name_copy = malloc(len_name + 1);
	strcpy(name_copy, name);
	file_list[file_list_len].name = name_copy;
	file_list[file_list_len].size = size;
	++file_list_len;
}

void draw_file_list() {
	// TODO: right align position
	iprintf(Cls Red "%s %u/%u\n", pwd, view_pos + cur_pos + 1, file_list_len);
	for (unsigned i = 0; i < VIEW_HEIGHT; ++i) {
		if (view_pos + i < file_list_len) {
			iprintf(i == cur_pos ? Grn : Wht);
			file_list_item_t *item = &file_list[view_pos + i];
			// TODO: right align size
			iprintf("%s %u\n", item->name, item->size);
		} else {
			iprintf("\n");
		}
	}
	iprintf(Red "%s\n" Rst, footer);
}

void menu_move(int move) {
	unsigned last_pos = file_list_len < VIEW_HEIGHT ? file_list_len - 1 : VIEW_HEIGHT - 1;
	switch (move) {
	case -1:
		if (cur_pos > 0) {
			--cur_pos;
		} else {
			// TODO: move window
		}
		break;
	case 1:
		if (cur_pos < last_pos) {
			++cur_pos;
		} else {
		}
		break;
	case -2:
		if (cur_pos > 0) {
			cur_pos = 0;
		} else {
		}
		break;
	case 2:
		if (cur_pos < last_pos) {
			cur_pos = last_pos;
		} else {
		}
	}
}

void exit_with_prompt(int exit_code) {
	iprintf("press A to exit...");
	while (1) {
		swiWaitForVBlank();
		scanKeys();
		if (keysDown() & KEY_A) break;
	}
	exit(exit_code);
}

unsigned wait_keys(unsigned keys) {
	while (1) {
		swiWaitForVBlank();
		scanKeys();
		unsigned kd = keysDown();
		if (kd & keys) {
			return kd;
		}
	}
}

size_t df(int verbose) {
	// it's amazing libfat even got this to work
	struct statvfs s;
	statvfs(nand_root, &s);
	size_t free = s.f_bsize * s.f_bfree;
	if (verbose) {
		iprintf("%s", to_mebi(free));
		iprintf("/%s MB (free/total)\n", to_mebi(s.f_bsize * s.f_blocks));
	}
	return free;
}

void walk_cb_lst(const char *name, void *p_param) {
	iprintf("%s\n", name);
	fiprintf((FILE*)p_param, "%s\n", name);
}

void walk_cb_sha1(const char *name, void *p_param) {
	iprintf("%s", name);
	unsigned char digest[SHA1_LEN];
	int sha1_ret = sha1_file(digest, name);
	iprintf(" %d\n", sha1_ret);
	if (sha1_ret < 0) {
		return;
	}
	for (unsigned i = 0; i < SHA1_LEN; ++i) {
		fiprintf((FILE*)p_param, "%02X", digest[i]);
	}
	fiprintf((FILE*)p_param, " *%s\n", name);
}

void walk_cb_dump(const char *name, void *_) {
}

void menu_action(const char *name) {
	iprintf("scripting: %s\n", name);
	int ret = scripting(name, 1);
	iprintf("dry run returned %d\n", ret);
}

// uint32 prev_keys = 0;

void menu() {
	// list
	file_list_len = 0;
	listdir(pwd, 0, file_list_add, 0);
	// init menu
	consoleSelect(&topScreen);
	view_pos = 0;
	cur_pos = 0;
	draw_file_list();
	int needs_redraw = 0;
	while (1) {
		swiWaitForVBlank();
		scanKeys();
		uint32 keys = keysDownRepeat();
		/*
		if (keys != prev_keys) {
			consoleSelect(&bottomScreen);
			iprintf("%08lx\n", keys);
			consoleSelect(&topScreen);
			prev_keys = keys;
		}
		*/
		consoleSelect(&bottomScreen);
		if (keys & KEY_B) {
			break;
		}else if(keys & (KEY_UP|KEY_DOWN|KEY_LEFT|KEY_RIGHT)){
			if (keys & KEY_UP) {
				menu_move(-1);
			} else if (keys & KEY_DOWN) {
				menu_move(1);
			} else if (keys & KEY_LEFT) {
				menu_move(-2);
			} else if (keys & KEY_RIGHT) {
				menu_move(2);
			}
			needs_redraw = 1;
		} else if (keys & KEY_A) {
			menu_action(file_list[view_pos + cur_pos].name);
		} else if ((keys & KEY_START) && (keys & KEY_L)) {
			FILE * f = fopen("nand_files.lst", "w");
			iprintf("walk returned %d\n", walk(nand_root, walk_cb_lst, f));
			fclose(f);
		} else if ((keys & KEY_START) && (keys & KEY_R)) {
			FILE * f = fopen("nand_files.sha1", "w");
			iprintf("walk returned %d\n", walk(nand_root, walk_cb_sha1, f));
			fclose(f);
		}
		if (needs_redraw) {
			consoleSelect(&topScreen);
			draw_file_list();
		}
	}
}

int main() {
	defaultExceptionHandler();

	videoSetMode(MODE_0_2D);
	videoSetModeSub(MODE_0_2D);

	vramSetBankA(VRAM_A_MAIN_BG);
	vramSetBankC(VRAM_C_SUB_BG);

	consoleInit(&topScreen, 3, BgType_Text4bpp, BgSize_T_256x256, 31, 0, true, true);
	consoleInit(&bottomScreen, 3, BgType_Text4bpp, BgSize_T_256x256, 31, 0, false, true);

	consoleSelect(&bottomScreen);

	iprintf("FAT init...");

	if (!fatInitDefault()) {
		iprintf("\rFAT init failed!\n");
		exit_with_prompt(-1);
	} else {
		iprintf("\rFAT init succeed\n");
	}

	u8 *sector_buf = (u8*)memalign(32, SECTOR_SIZE);

#if !NAND_IMG_MODE
	if (!isDSiMode()) {
		iprintf("not running in DSi mode\n");
		exit_with_prompt(-2);
	}

	ssize_t nandSize = nand_GetSize();
	if (nandSize == 0) {
		iprintf("can't access NAND\n");
		exit_with_prompt(-3);
	}

	iprintf("NAND: %d sectors, %s MB\n", nandSize, to_mebi(nandSize * 512));
#endif

	iprintf("NAND CID:\n");
#if NAND_IMG_MODE
	char *pCIDFile = 0;
	size_t CIDFileSize;
	bool CIDFromFile = false;
	if (load_file((void**)&pCIDFile, &CIDFileSize, "cid.txt", false, 0) == 0) {
		if (CIDFileSize >= 32 && hex2bytes(nandcid, 16, pCIDFile) == 0) {
			CIDFromFile = true;
		}
		free(pCIDFile);
	}
	if (!CIDFromFile) {
		iprintf("cid.txt missing/invalid\n");
		exit_with_prompt(0);
	}
#else
	fifoSendValue32(FIFO_USER_01, 4);
	while (fifoCheckDatamsgLength(FIFO_USER_01) < 16) swiIntrWait(1, IRQ_FIFO_NOT_EMPTY);
	fifoGetDatamsg(FIFO_USER_01, 16, (u8*)nandcid);
#endif
	print_bytes(nandcid, 16);

	char *pConsoleIDFile = 0;
	size_t ConsoleIDFileSize;
	bool consoleIDFromFile = false;
	if (load_file((void**)&pConsoleIDFile, &ConsoleIDFileSize, "console_id.txt", false, 0) == 0) {
		if (ConsoleIDFileSize >= 16 && hex2bytes(consoleid, 8, pConsoleIDFile) == 0) {
			consoleIDFromFile = true;
		}
		free(pConsoleIDFile);
	}
	if (!consoleIDFromFile) {
#if NAND_IMG_MODE
		iprintf("console_id.txt missing/invalid\n");
		exit_with_prompt(0);
#else
		fifoSendValue32(FIFO_USER_01, 5);
		while (fifoCheckDatamsgLength(FIFO_USER_01) < 8) swiIntrWait(1, IRQ_FIFO_NOT_EMPTY);
		fifoGetDatamsg(FIFO_USER_01, 8, consoleid);
#endif
	}
	iprintf("Console ID (from %s):\n", consoleIDFromFile ? "file" : "RAM");
	print_bytes(consoleid, 8);
	iprintf("\n");

	// check NCSD header
#if NAND_IMG_MODE
	FILE *f = fopen(nand_img_name, "r");
	if (f == 0) {
		iprintf("can't open %s\n", nand_img_name);
		exit_with_prompt(0);
	}
	size_t read = fread(sector_buf, 1, SECTOR_SIZE, f);
	if (read != SECTOR_SIZE) {
		iprintf("read = %u, expecting %u\n", (unsigned)read, SECTOR_SIZE);
		exit_with_prompt(0);
	}
	fclose(f);
#else
	nand_ReadSectors(0, 1, sector_buf);
#endif
	int is3DS = parse_ncsd(sector_buf, 0);
	iprintf("%s mode\n", is3DS ? "3DS" : "DSi");

	dsi_nand_crypt_init(consoleid, nandcid, is3DS);

	// check MBR
	dsi_nand_crypt(sector_buf, sector_buf, 0, SECTOR_SIZE / AES_BLOCK_SIZE);
	int mbr_ok = parse_mbr(sector_buf, is3DS, 0);
	if (mbr_ok != 1) {
		iprintf("most likely Console ID is wrong\n");
		exit_with_prompt(-4);
	} else {
		iprintf("MBR OK\n");
	}

	mbr_t *mbr = (mbr_t*)sector_buf;
	// finally mount NAND
#if NAND_IMG_MODE
	imgio_set_fat_sig_fix(is3DS ? 0 : mbr->partitions[0].offset);
	if (!fatMount(nand_vol_name, &io_nand_img, mbr->partitions[0].offset, 4, 64)) {
#else
	nandio_set_fat_sig_fix(is3DS ? 0 : mbr->partitions[0].offset);
	if (!fatMount(nand_vol_name, &io_dsi_nand, mbr->partitions[0].offset, 4, 64)) {
#endif
		iprintf("failed to mount NAND\n");
		exit_with_prompt(-5);
	} else {
		iprintf("NAND mounted\n");
	}

	///* // the volume label is all white space?
	char vol_label[32];
	fatGetVolumeLabel(nand_vol_name, vol_label);
	iprintf("label: \"%s\"\n", vol_label);
	//*/
	df(1);

	if (scripting_init() != 0) {
		exit_with_prompt(-1);
	}

	menu();

	fatUnmount(nand_vol_name);
}
