#pragma once

#define SHA1_LEN 20

int sha1_file(void *digest, const char *name);

int cp(const char *from, const char *to);

int scripting_init();

int scripting(const char *filename, int dry_run, unsigned *p_size);
