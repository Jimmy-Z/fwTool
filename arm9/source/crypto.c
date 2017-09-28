
#include <nds.h>
// #include <stdio.h>
#include "../mbedtls/aes.h"
#include "crypto.h"
#include "utils.h"

// more info:
//		https://github.com/Jimmy-Z/TWLbf/blob/master/dsi.c
//		https://github.com/Jimmy-Z/bfCL/blob/master/dsi.h
// ported back to 32 bit for ARM9

static const u32 DSi_NAND_KEY_Y[4] =
	{0x0ab9dc76u, 0xbd4dc4d3u, 0x202ddd1du, 0xe1a00005u};

static const u32 DSi_KEY_MAGIC[4] =
	{0x1a4f3e79u, 0x2a680f5fu, 0x29590258u, 0xfffefb4eu};

static inline void xor_128(u32 *x, const u32 *a, const u32 *b){
	x[0] = a[0] ^ b[0];
	x[1] = a[1] ^ b[1];
	x[2] = a[2] ^ b[2];
	x[3] = a[3] ^ b[3];
}

static inline void add_128(u32 *a, const u32 *b){
	unsigned c1, c2, c3; // carry
	// round 1
	a[3] += b[3];
	a[2] += b[2];
	a[1] += b[1];
	a[0] += b[0];
	// carry
	c3 = a[2] < b[2];
	c2 = a[1] < b[1];
	c1 = a[0] < b[0];
	// round 2
	a[3] += c3;
	a[2] += c2;
	a[1] += c1;
	// carry
	c3 = a[2] < c2;
	c2 = a[1] < c1;
	// round 3
	a[3] += c3;
	a[2] += c2;
	// carry
	c3 = a[2] < c2;
	// round 4
	a[3] += c3;
}

static inline void add_128_32(u32 *a, u32 b){
	a[0] += b;
	if(a[0] < b){
		a[1] += 1;
		if (a[1] == 0) {
			a[2] += 1;
			if (a[2] == 0) {
				a[3] += 1;
			}
		}
	}
}

// Answer to life, universe and everything.
static inline void rol42_128(u32 *a){
	u32 t3 = a[3], t2 = a[2];
	a[3] = (a[2] << 10) | (a[1] >> 22);
	a[2] = (a[1] << 10) | (a[0] >> 22);
	a[1] = (a[0] << 10) | (t3 >> 22);
	a[0] = (t3 << 10) | (t2 >> 22);
}

static void make_nand_key_x_dsi(u32 *key, const u32* console_id) {
	key[0] = console_id[0];
	key[1] = console_id[0] ^ 0x24ee6906;
	key[2] = console_id[1] ^ 0xe65b601d;
	key[3] = console_id[1];
}

static void make_nand_key_x_3ds(u32 *key, const u32* console_id) {
	key[0] = (console_id[0] ^ 0xb358a6af) | 0x80000000;
	key[1] = 0x544e494e;
	key[2] = 0x4f444e45;
	key[3] = console_id[1] ^ 0x08c267b7;
}

// xor_128 can work in place, so this can also work if key = key_x
static void make_normal_key(u32 *key, const u32 *key_x, const u32 *key_y) {
	// Key = ((Key_X XOR Key_Y) + FFFEFB4E295902582A680F5F1A4F3E79h) ROL 42
	// equivalent to F_XY in twltool/f_xy.c
	xor_128(key, key_x, key_y);
	// iprintf("AES KEY: XOR KEY_Y:\n");
	// print_bytes(key, 16);
	add_128(key, DSi_KEY_MAGIC);
	// iprintf("AES KEY: + MAGIC:\n");
	// print_bytes(key, 16);
	rol42_128(key);
	// iprintf("AES KEY: ROL 42:\n");
	// print_bytes(key, 16);
}

#ifdef _MSC_VER
#define DTCM_BSS
#endif

DTCM_BSS static u32 nand_ctr_rk[RK_LEN];
static u32 nand_ctr_iv[4];

static int tables_generated = 0;

void dsi_nand_crypt_init(const u8 *console_id_be, const u8 *emmc_cid, int is3DS) {
	if (tables_generated == 0) {
		aes_gen_tables();
		tables_generated = 1;
	}

	u32 key[4], console_id[2];
	// console_id from hex string usually comes in big endian
	GET_UINT32_BE(console_id[0], console_id_be, 4);
	GET_UINT32_BE(console_id[1], console_id_be, 0);
	if (is3DS) {
		make_nand_key_x_3ds(key, console_id);
	} else {
		make_nand_key_x_dsi(key, console_id);
	}
	make_normal_key(key, key, DSi_NAND_KEY_Y);

	aes_set_key_enc_128_be(nand_ctr_rk, (u8*)key);

	u32 digest[5];
	swiSHA1context_t ctx;
	ctx.sha_block = 0;
	swiSHA1Init(&ctx);
	swiSHA1Update(&ctx, emmc_cid, 16);
	swiSHA1Final(digest, &ctx);
	nand_ctr_iv[0] = digest[0];
	nand_ctr_iv[1] = digest[1];
	nand_ctr_iv[2] = digest[2];
	nand_ctr_iv[3] = digest[3];
}

// crypt one AES block, in/out must be aligned to 32 bit
// offset as block offset
void dsi_nand_crypt_1(u8* out, const u8* in, u32 offset) {
	u32 buf[4] = { nand_ctr_iv[0], nand_ctr_iv[1], nand_ctr_iv[2], nand_ctr_iv[3] };
	add_128_32(buf, offset);
	// iprintf("AES CTR:\n");
	// print_bytes(buf, 16);
	aes_encrypt_128_be(nand_ctr_rk, (u8*)buf, (u8*)buf);
	xor_128((u32*)out, (u32*)in, buf);
}

void dsi_nand_crypt(u8* out, const u8* in, u32 offset, unsigned count) {
	u32 ctr[4] = { nand_ctr_iv[0], nand_ctr_iv[1], nand_ctr_iv[2], nand_ctr_iv[3] };
	u32 xor[4];
	add_128_32(ctr, offset);
	for (unsigned i = 0; i < count; ++i) {
		aes_encrypt_128_be(nand_ctr_rk, (u8*)ctr, (u8*)xor);
		xor_128((u32*)out, (u32*)in, xor);
		out += AES_BLOCK_SIZE;
		in += AES_BLOCK_SIZE;
		add_128_32(ctr, 1);
	}
}

// http://problemkaputt.de/gbatek.htm#dsiesblockencryption
