#include <malloc.h>
#include <term256ext.h>
#include "heap.h"

#define HEAP_LEN 0x20
#define WARN 0x10

static char *heap;
static char *alloc_map;
static int alloced;
static int next;

int heap_init() {
	heap = memalign(4, BUF_SIZE * HEAP_LEN);
	alloc_map = malloc(HEAP_LEN);
	if (heap == 0 || alloc_map == 0) {
		prt("failed to init heap\n");
		return -1;
	}
	memset(alloc_map, 0, HEAP_LEN);
	alloced = 0;
	next = 0;
	return 0;
}

char *alloc_buf() {
	if (alloced >= WARN) {
		prt("HEAP WARNING: YOU SHOULD CONSIDER INCREASING HEAP_LEN\n");
	}
	if (alloced < HEAP_LEN) {
		for (int i = 0; i < HEAP_LEN; ++i) {
			int j = (next + i) % HEAP_LEN;
			if (alloc_map[j] == 0) {
				alloc_map[j] = 1;
				++alloced;
				next = (j + 1) % HEAP_LEN;
				return heap + BUF_SIZE * j;
			}
		}
		prt("HEAP ERROR: invalid heap alloc map\n");
		alloced = HEAP_LEN;
	}
	// fallback to malloc
	prt("HEAP_WARNING: heap depleted, using malloc as fallback\n");
	// WARNING: we don't handle malloc failure here
	return malloc(BUF_SIZE);
}

void free_buf(void *p) {
	if ((char*)p >= heap && (char*)p < heap + BUF_SIZE * HEAP_LEN) {
		unsigned offset = (unsigned)p - (unsigned)heap;
		if (offset % BUF_SIZE == 0) {
			unsigned j = offset / BUF_SIZE;
			if (alloc_map[j] == 1) {
				alloc_map[j] = 0;
				--alloced;
				next = j;
			} else {
				prt("HEAP ERROR: freeing unalloced pointer\n");
			}
		} else {
			prt("HEAP ERROR: freeing wild pointer\n");
		}
	} else {
		// it's a fallback
		free(p);
	}
}
