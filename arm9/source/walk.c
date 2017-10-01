
// a POSIX directory tree walk
// walk down subdirectories and calls callback on regular files/directories, skip all others

#include <stdio.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include "../term256/term256ext.h"
#include "heap.h"
#include "walk.h"

#define STACK_DEPTH 0x400

static void **base;
static unsigned head;

static unsigned stack_usage;
static unsigned stack_max_depth;
static unsigned longest_path;

// I suppose no need for a linked stack
static int s_alloc() {
	base = memalign(sizeof(void*), sizeof(void*) * STACK_DEPTH);
	if (base == 0) {
		return -1;
	}
	head = 0;
	return 0;
}

static void s_free() {
	free(base);
}

static int s_push(void *p) {
	++stack_usage;
	if (head < STACK_DEPTH) {
		base[head++] = p;
		if (head > stack_max_depth) {
			stack_max_depth = head;
		}
		return 0;
	} else {
		prt("stack limit exceed\n");
		return -1;
	}
}

static void* s_pop() {
	if (head > 0) {
		return base[--head];
	} else {
		return 0;
	}
}

static void s_deep_free() {
	void *p;
	while ((p = s_pop()) != 0) {
		free(p);
	}
	free(base);
}

// walk doesn't use heap.c, since the stack could be dramatically deeper
// and it doesn't do critical jobs so failure(induced by malloc failure) is fine
int walk(const char *dir, void (*callback)(const char*, size_t, void*), void *p_cb_param) {
	// init the stack
	stack_max_depth = 0;
	stack_usage = 0;
	longest_path = 0;
	if (s_alloc() != 0) {
		return -1;
	}
	char *p = (char*)malloc(strlen(dir) + 1);
	if (p == 0) {
		return -1;
	}
	strcpy(p, dir);
	s_push(p);
	// walk the stack
	while ((p = (char*)s_pop()) != 0) {
		unsigned len_parent = strlen(p);
		DIR * d = opendir(p);
		if (d == 0) {
			free(p);
			continue;
		}
		struct dirent * de;
		while ((de = readdir(d)) != 0) {
			if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) {
				continue;
			}
			unsigned full_len = len_parent + 1 + strlen(de->d_name);
			if (full_len > longest_path) {
				longest_path = full_len;
			}
			char *fullname = (char*)malloc(full_len + 1);
			if (fullname == 0) {
				prt("failed to alloc memory\n");
				closedir(d);
				free(p);
				s_deep_free();
				return -1;
			}
			strcpy(fullname, p);
			if (p[len_parent - 1] == '/') {
				strcpy(fullname + len_parent, de->d_name);
			} else {
				fullname[len_parent] = '/';
				strcpy(fullname + len_parent + 1, de->d_name);
			}
			struct stat s;
			if (stat(fullname, &s) != 0) {
				iprtf("weird stat failure, errno: %d\n", errno);
				free(fullname);
				continue;
			}
			if ((s.st_mode & S_IFMT) == S_IFREG) {
				if (callback != 0) {
					callback(fullname, s.st_size, p_cb_param);
				}
				free(fullname);
			} else if ((s.st_mode & S_IFMT) == S_IFDIR) {
				if (callback != 0) {
					callback(fullname, INVALID_SIZE, p_cb_param);
				}
				if (s_push(fullname) != 0) {
					free(fullname);
					closedir(d);
					free(p);
					s_deep_free();
					return -2;
				}
			} else {
				iprtf("weird type 0x%08lx: %s\n", s.st_mode & S_IFMT, fullname);
				free(fullname);
			}
		}
		closedir(d);
		free(p);
	}
	s_free();
	iprtf("walk stats: %u, %u, %u\n", stack_max_depth, stack_usage, longest_path);
	return 0;
}

// this is much simpler, the callback can break the loop by returning non-zero values
void list_dir(const char *dir, int(*callback)(const char*, const char*, size_t, void*), void *p_cb_param) {
	DIR * d = opendir(dir);
	if (d == 0) {
		return;
	}
	char *full_path = alloc_buf();
	int len_path = strlen(dir);
	strcpy(full_path, dir);
	if (full_path[len_path - 1] != '/') {
		full_path[len_path] = '/';
		len_path += 1;
		// beware the string might not be zero terminated now
	}
	struct dirent * de;
	while ((de = readdir(d)) != 0) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) {
			continue;
		}
		int len_name = strlen(de->d_name);
		if (len_path + len_name + 1 > BUF_SIZE) {
			// consider current usage cases, missing a file for long path is no big deal
			iprtf("name too long: %s\n", de->d_name);
			continue;
		}
		strcpy(full_path + len_path, de->d_name);
		struct stat s;
		if (stat(full_path, &s) != 0) {
			iprtf("weird stat failure, errno: %d\n", errno);
			continue;
		}
		if ((s.st_mode & S_IFMT) == S_IFREG) {
			if (callback(full_path, de->d_name, s.st_size, p_cb_param) != 0) {
				break;
			}
		} else if ((s.st_mode & S_IFMT) == S_IFDIR) {
			// use INVALID_SIZE as is_dir
			if (callback(full_path, de->d_name, INVALID_SIZE, p_cb_param) != 0) {
				break;
			}
		}
	}
	closedir(d);
	free_buf(full_path);
}
