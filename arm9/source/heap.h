/*
	mainly used for file names and paths
	since call stack is so fucking tight
		buffers in call stack makes me nervous
		using malloc everywhere needs checks everywhere
		using globals everywhere is stupid
	principle:
		don't use recursive
		tests should not hit warning
*/

#define BUF_SIZE 0x100

int heap_init();

char *alloc_buf();

void free_buf(void *p);
