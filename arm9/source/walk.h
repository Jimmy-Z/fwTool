#pragma once

#include <assert.h>

#define INVALID_SIZE ((size_t)-1)

int walk(const char *dir, void(*callback)(const char*, int, void*), void *p_cb_param);

void listdir(const char *dir, int want_full, void(*callback)(const char*, size_t, void*), void *p_cb_param);
