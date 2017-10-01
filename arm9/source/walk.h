#pragma once

#include <assert.h>

#define INVALID_SIZE ((size_t)-1)

int walk(const char *dir, void(*callback)(const char*, size_t, void*), void *p_cb_param);

void list_dir(const char *dir, int(*callback)(const char*, const char*, size_t, void*), void *p_cb_param);
