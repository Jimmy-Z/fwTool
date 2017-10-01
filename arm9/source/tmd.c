#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <sys/stat.h>
#include "../term256/term256ext.h"
#include "../mbedtls/rsa.h"
#include "../mbedtls/aes.h"
#include "heap.h"
#include "utils.h"
#include "walk.h"
#include "ticket0.h"
#include "crypto.h"
#include "scripting.h"

extern const char nand_root[];

const char cert_sys_path[] = "sys/cert.sys";

const char cert_cp07_name[] = "CP00000007";

const uint32_t dsiware_title_id_h = 0x00030004;

const char hwinfo_s_path[] = "sys/HWINFO_S.dat";

// used while looking for a ticket template
const char ticket_dir_fmt[] = "%sticket/%08lx/";
// used while reading app aside tmd on SD
const char app_src_fmt[] = "%s%08lx.app";
// dst full path generation
const char ticket_dst_fmt[] = "%sticket/%08lx/%08lx.tik";
const char tmd_dst_fmt[] = "%stitle/%08lx/%08lx/content/title.tmd";
const char app_dst_fmt[] = "%stitle/%08lx/%08lx/content/%08lx.app";
// need to create these directories
const char dir0_fmt[] = "%stitle/%08lx/%08lx";
const char dir1_fmt[] = "%stitle/%08lx/%08lx/content";
const char dir2_fmt[] = "%stitle/%08lx/%08lx/data";

rsa_context_t rsa_cp07;

uint8_t * ticket_template;

uint8_t region;

int setup_cp07_pubkey() {
	cert_t *cert = malloc(sizeof(cert_t));
	if (cert == 0){
		prt("failed to alloc memory\n");
		return -1;
	}
	int ret;
	char *cert_sys_full_path = alloc_buf();
	strcpy(cert_sys_full_path, nand_root);
	strcat(cert_sys_full_path, cert_sys_path);
	if (load_block_from_file(cert, cert_sys_full_path, 0x700, sizeof(cert_t)) != 0) {
		iprtf("failed to load cert from %s\n", cert_sys_full_path);
		ret = -1;
	} else {
		if (strncmp(cert->key_name, cert_cp07_name, sizeof(cert_cp07_name)) != 0) {
			iprtf("unexpected key name %s, should be %s\n", cert->key_name, cert_cp07_name);
			ret = -2;
		} else {
			rsa_init(&rsa_cp07);
			if (rsa_set_pubkey(&rsa_cp07,
				cert->rsa_key, sizeof(cert->rsa_key),
				cert->rsa_exp, sizeof(cert->rsa_exp)) != 0) {
				prt("failed to setup RSA key\n");
				ret = -1;
			} else {
				ret = 0;
			}
		}
	}
	free(cert);
	free_buf(cert_sys_full_path);
	return ret;
}

// returns 0 on success, and write SHA1 to out
int decrypt_cp07_signature(uint8_t *out, const uint8_t *in) {
	static_assert(RSA_2048_LEN <= BUF_SIZE, "BUF_SIZE shouldn't < RSA_2048_LEN");
	uint8_t *sig = (uint8_t*)alloc_buf();
	int ret;
	if (sig == 0) {
		prt("failed to alloc memory\n");
		ret = -1;
	} else if (rsa_public(&rsa_cp07, in, sig) != 0){
		prt("failed to decrypt signature\n");
		ret = -2;
	} else if (sig[0] != 0 || sig[1] != 1 || sig[2] != 0xff
		|| sig[RSA_2048_LEN - SHA1_LEN - 1] != SHA1_LEN) {
		prt("invalid signature, first 16 bytes:\n\t");
		print_bytes(sig, 16);
		prt("\nlast 32 bytes:\n\t");
		print_bytes(sig + RSA_2048_LEN - 32, 16);
		prt("\n\t");
		print_bytes(sig + RSA_2048_LEN - 16, 16);
		prt("\n");
		ret = -3;
	} else {
		memcpy(out, sig + RSA_2048_LEN - SHA1_LEN, SHA1_LEN);
		ret = 0;
	}
	free_buf(sig);
	return ret;
}

#define TICKET_SIZE (sizeof(ticket_v0_t) + sizeof(es_block_footer_t))
#define TICKET_ALIGN 4
static_assert(TICKET_SIZE % TICKET_ALIGN == 0, "invalid TICKET_ALIGN");

unsigned wait_keys(unsigned);

static int find_ticket_cb(const char* full_path, const char* name, size_t size, void *cb_param) {
	if (size == INVALID_SIZE || size < TICKET_SIZE) {
		return 0;
	}
	if (load_block_from_file(ticket_template, full_path, 0, TICKET_SIZE) != 0) {
		iprtf("failed to load ticket: %s\n", name);
		// return 0 to let list_dir continue
		return 0;
	}
// #define ES_ENCRYPT_TEST
#ifdef ES_ENCRYPT_TEST
	uint8_t *ticket_original = memalign(TICKET_ALIGN, TICKET_SIZE);
	assert(ticket_original != 0);
	memcpy(ticket_original, ticket_template, TICKET_SIZE);
#endif
	if (dsi_es_block_crypt(ticket_template, TICKET_SIZE, DECRYPT) != 0) {
		iprtf("failed to decrypt ticket: %s\n", name);
		return 0;
	}
#ifdef ES_ENCRYPT_TEST
	uint8_t *ticket_enc = memalign(TICKET_ALIGN, TICKET_SIZE);
	assert(ticket_enc != 0);
	memcpy(ticket_enc, ticket_template, TICKET_SIZE);
	assert(dsi_es_block_crypt(ticket_enc, TICKET_SIZE, ENCRYPT) == 0);
	if (memcmp(ticket_original, ticket_enc, TICKET_SIZE) == 0) {
		prtf("ES encryption test OK\n");
	} else {
		prtf("ES encryption test failed\n");
	}
	free(ticket_original);
	free(ticket_enc);
#endif
	ticket_v0_t *ticket = (ticket_v0_t*)ticket_template;
	// maybe we should reject XS00000006 tickets, only allow XS00000003?
	// iprtf("ticket signature issuer: %s\n", ticket->issuer);
	// TODO: maybe also validate ticket signature
	uint32_t title_id[2];
	GET_UINT32_BE(title_id[0], ticket->title_id, 4);
	GET_UINT32_BE(title_id[1], ticket->title_id, 0);
	if (title_id[1] != dsiware_title_id_h) {
		iprtf("weird, got a %08lx ticket\n", title_id[1]);
		return 0;
	}
	*(int*)cb_param = 1;
	return 1;
}

int setup_ticket_template() {
	// we'll do AES-CCM on that, so must be aligned at least 32 bit
	ticket_template = memalign(TICKET_ALIGN, TICKET_SIZE);
	if (ticket_template == 0) {
		prt("failed to alloc memory\n");
		return -1;
	}
	// iprtf("ticket_template addr: %08x\n", (unsigned)ticket_template);
	char * ticket_dir = alloc_buf();
	sprintf(ticket_dir, ticket_dir_fmt, nand_root, dsiware_title_id_h);
	int found = 0;
	list_dir(ticket_dir, find_ticket_cb, &found);
	free_buf(ticket_dir);
	if (found) {
		return 0;
	} else {
		free(ticket_template);
		ticket_template = 0;
		return 1;
	}
}

int load_region() {
	// 1 byte region, 12 byte serial, 1 more for \0
	int ret;
	char *hwinfo_s_full_path = alloc_buf();
	strcpy(hwinfo_s_full_path, nand_root);
	strcat(hwinfo_s_full_path, hwinfo_s_path);
	char region_and_serial[14];
	if (load_block_from_file(region_and_serial, hwinfo_s_full_path, 0x90, 13) != 0) {
		iprtf("failed to load region from %s\n", hwinfo_s_full_path);
		ret = -1;
	} else {
		region = (uint8_t)region_and_serial[0];
		prt("region: ");
		switch (region) {
			case 0: prt("J(0)\n"); break;
			case 1: prt("U(1)\n"); break;
			case 2: prt("E(2)\n"); break;
			case 3: prt("A(3)\n"); break;
			case 4: prt("C(4)\n"); break;
			case 5: prt("K(5)\n"); break;
			default: iprtf("unknown(%02x)\n", region); break;
		}
		region_and_serial[13] = 0;
		iprtf("serial: %s\n", region_and_serial + 1);
		ret = 0;
	}
	return ret;
}

/* cartridge header/title, also used in app
http://problemkaputt.de/gbatek.htm#dscartridgeheader
http://problemkaputt.de/gbatek.htm#dsicartridgeheader
http://problemkaputt.de/gbatek.htm#dscartridgeicontitle
*/
static_assert(BUF_SIZE >= 0x100, "BUF_SIZE too small");
int get_app_region(const char* name, uint32_t *p_region) {
	// they use little endian now, what a surprise
	if (load_block_from_file(p_region, name, 0x1b0, 4) != 0) {
		prt("failed to read region flags from app\n");
		return -1;
	}
	uint32_t icon_offset;
	if (load_block_from_file(&icon_offset, name, 0x68, 4) != 0){
		prt("failed to read icon offset from app\n");
		return -1;
	}
	// read the English title
	uint8_t *buf = (uint8_t*)alloc_buf();
	if (load_block_from_file(buf, name, icon_offset + 0x340, 0x100) != 0) {
		prt("failed to read title from app\n");
		free_buf(buf);
		return -1;
	}
	// this thing requirs is uint16_t aligned, luckily heap.c does that
	utf16_to_ascii(buf, (uint16_t*)buf, 0x80);
	// just to be sure
	buf[0x80] = 0;
	prt((char*)buf);
	prt("\n");
	free_buf(buf);
	return 0;
}

#define TMD_SIZE (sizeof(tmd_header_v0_t) + sizeof(tmd_content_v0_t))

int tmd_verify(const uint8_t *tmd_buf, const char *tmd_dir,
	uint32_t *title_id, uint32_t *content_id,
	char *app_src, uint8_t *app_sha1, int *psize, uint8_t *ticket_buf)
{
	tmd_header_v0_t *header = (tmd_header_v0_t*)tmd_buf;
	GET_UINT32_BE(title_id[0], header->title_id, 4);
	GET_UINT32_BE(title_id[1], header->title_id, 0);
	if (title_id[1] != dsiware_title_id_h) {
		iprtf("not a DSiWare title(%08lx)\n", title_id[1]);
		return -1;
	}
	iprtf("Title ID: %08lx/%c%c%c%c\n", title_id[1],
		header->title_id[4], header->title_id[5], header->title_id[6], header->title_id[7]);
	if (header->num_content[0] != 0 || header->num_content[1] != 1) {
		iprtf("num_content should be 1(%02x%02x)\n",
			header->num_content[0], header->num_content[1]);
		return -1;
	}
	// I'm ashamed to used app_sha1 for a different thing 
	if (decrypt_cp07_signature(app_sha1, header->sig) != 0) {
		return -1;
	}
#define SIG_OFFSET (sizeof(header->sig_type) + sizeof(header->sig) + sizeof(header->padding0))
#define SIG_LEN (TMD_SIZE - SIG_OFFSET)
	if (dsi_sha1_verify(app_sha1, tmd_buf + SIG_OFFSET, SIG_LEN) != 0) {
#undef SIG_OFFSET
#undef SIG_LEN
		prt("TMD signature verification failed\n");
		return -1;
	} else {
		prt("TMD signature verified\n");
	}
	// verify app region
	tmd_content_v0_t *content = (tmd_content_v0_t*)(tmd_buf + sizeof(tmd_header_v0_t));
	GET_UINT32_BE(*content_id, content->content_id, 0);
	sprintf(app_src, app_src_fmt, tmd_dir, *content_id);
	uint32_t region_flags;
	if (get_app_region(app_src, &region_flags) != 0) {
		prt("failed to get region\n");
		return -1;
	}
	iprtf("region flags: %08lx\n", region_flags);
	if (!((1 << region) & region_flags)) {
		prt("incompatible region\n");
		return -1;
	}
	// verify app sha1
	// TODO: verify app signature and title id, allow TMD<->app sha1 mismatch
	prt(app_src);
	if ((*psize = sha1_file(app_sha1, app_src)) == -1) {
		prt(" <- couldn't open\n");
		return -1;
	}
	if (memcmp(content->sha1, app_sha1, SHA1_LEN) != 0) {
		prt(" SHA1 doesn't match\n");
		return -1;
	} else {
		prt(" SHA1 verified\n");
	}
	// TODO: verify data/*.sav size, I suppose this is not critical
	// forge ticket
	memcpy(ticket_buf, ticket_template, TICKET_SIZE);
	PUT_UINT32_BE(title_id[0], ((ticket_v0_t*)ticket_buf)->title_id, 4);
	if (dsi_es_block_crypt(ticket_buf, TICKET_SIZE, ENCRYPT) != 0) {
		prt("weird, failed to forge ticket\n");
		return -1;
	}
	return 0;
}

int wait_yes_no(const char *);

void verify(const char *name, const uint8_t *digest_verify) {
	uint8_t digest[SHA1_LEN];
	int ret = sha1_file(digest, name);
	if (ret == -1) {
		prt(" but failed to read for verification\n");
	} else if (memcmp(digest, digest_verify, SHA1_LEN)) {
		prt(" but verification failed\n");
	} else {
		prt(" and verified\n");
	}
}

void save_and_verify(const char *name, uint8_t *buf, size_t len) {
	int ret = save_file(name, buf, len, 0);
	if (ret == 0) {
		uint8_t digest[SHA1_LEN];
		swiSHA1Calc(digest, buf, len);
		verify(name, digest);
	}
}

int data_cp(const char *full_path, const char *name, size_t size, void *cb_param) {
	char *dst = alloc_buf();
	sprintf(dst, "%s/%s", (char*)cb_param, name);
	prt(dst);
	if (cp(full_path, dst) != 0) {
		prt(" failed to copy\n");
	} else {
		prt(" copied to NAND");
		uint8_t digest[SHA1_LEN];
		sha1_file(digest, full_path);
		verify(dst, digest);
	}
	free_buf(dst);
	return 0;
}

void install_tmd(const char *tmd_fullname, const char *tmd_dir, int max_size) {
	// TMD file
	uint8_t *tmd_buf = malloc(TMD_SIZE);
	if (tmd_buf == 0) {
		prt("failed to alloc memory for TMD\n");
		return;
	}
	uint8_t *ticket_buf = memalign(TICKET_ALIGN, TICKET_SIZE);
	if (ticket_buf == 0) {
		prt("failed to alloc memory for ticket\n");
		free(tmd_buf);
		return;
	}
	if (load_block_from_file(tmd_buf, tmd_fullname, 0,
		sizeof(tmd_header_v0_t) + sizeof(tmd_content_v0_t)) != 0) {
		prt("failed to load TMD\n");
		free(tmd_buf);
		free(ticket_buf);
		return;
	}
	uint32_t title_id[2];
	uint32_t content_id;
	char *tmd_dst = alloc_buf();
	char *app_src = alloc_buf();
	uint8_t app_sha1[SHA1_LEN];
	int size;
	char *app_dst = alloc_buf();
	char *ticket_dst = alloc_buf();
	char * dir = alloc_buf();
	char * dir_data = alloc_buf();
	if (tmd_verify(tmd_buf, tmd_dir, title_id, &content_id,
		app_src, app_sha1, &size, ticket_buf) == 0) {
		if (size > max_size) {
			prt("insufficient NAND space\n");
		} else if(wait_yes_no("install to NAND?")){
			// generate paths
			sprintf(ticket_dst, ticket_dst_fmt, nand_root, title_id[1], title_id[0]);
			sprintf(tmd_dst, tmd_dst_fmt, nand_root, title_id[1], title_id[0]);
			sprintf(app_dst, app_dst_fmt, nand_root, title_id[1], title_id[0], content_id);
			// write ticket
			FILE *f = fopen(ticket_dst, "r");
			if (f != 0) {
				fclose(f);
				prt("ticket already exist, won't overwrite\n");
			} else {
				save_and_verify(ticket_dst, ticket_buf, TICKET_SIZE);
			}
			// create directories
			sprintf(dir, dir0_fmt, nand_root, title_id[1], title_id[0]);
			mkdir(dir, S_IRWXU | S_IRWXG | S_IRWXO);
			sprintf(dir, dir1_fmt, nand_root, title_id[1], title_id[0]);
			mkdir(dir, S_IRWXU | S_IRWXG | S_IRWXO);
			sprintf(dir, dir2_fmt, nand_root, title_id[1], title_id[0]);
			mkdir(dir, S_IRWXU | S_IRWXG | S_IRWXO);
			// write TMD
			save_and_verify(tmd_dst, tmd_buf, TMD_SIZE);
			// copy app
			prt(app_dst);
			if (cp(app_src, app_dst) != 0) {
				prt(" failed to copy\n");
			} else {
				prt(" copied to NAND");
				verify(app_dst, app_sha1);
			}
			// copy data
			// TODO: only copy .sav files indicated by tmd/app header
			sprintf(dir_data, "%s../data", tmd_dir);
			list_dir(dir_data, data_cp, dir);
			prt("all done\n");
		}
	}
	free(tmd_buf);
	free(ticket_buf);
	free_buf(tmd_dst);
	free_buf(app_src);
	free_buf(app_dst);
	free_buf(ticket_dst);
	free_buf(dir);
	free_buf(dir_data);
}
